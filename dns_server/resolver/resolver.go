package resolver

import (
	"bytes"
	pb "dns_server/packet_builder"
	rr "dns_server/resource_records"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	maxNSjumps = 10
	maxCNAMEs  = 5
)

type Resolver struct {
}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) Resolve(req pb.DNSPacket) pb.DNSPacket {
	if len(req.Questions) == 0 {
		return buildErrorResponse(req, pb.FormatErr)
	}
	question := req.Questions[0]

	if records, handled := r.handleMultiplyFeature(question.Name, question.Type); handled {
		log.Printf("[Multiply] Handled special query for %s", string(question.Name))
		return buildSuccessResponse(req, records)
	}

	records, err := r.resolveInternal(question.Name, question.Type, 0)

	if err != nil {
		if err, ok := err.(RCodeError); ok {
			resp := buildErrorResponse(req, err.RCode)
			if err.SOA != nil {
				resp.Authorities = append(resp.Authorities, *err.SOA)
				resp.Header.NSCount = 1
			}
			return resp
		}
		return buildErrorResponse(req, pb.NameServerErr)
	}

	return buildSuccessResponse(req, records)
}

func (r *Resolver) handleMultiplyFeature(name []byte, qtype rr.RecordType) ([]rr.ResourceRecord, bool) {
	if qtype != rr.TypeA {
		return nil, false
	}

	sName := string(name)
	if !strings.Contains(sName, ".multiply.") {
		return nil, false
	}

	parts := strings.Split(sName, ".")
	multiplyIndex := -1
	for i, part := range parts {
		if part == "multiply" {
			multiplyIndex = i
			break
		}
	}

	if multiplyIndex <= 0 {
		return nil, false
	}

	product := 1
	for i := 0; i < multiplyIndex; i++ {
		num, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil, false
		}
		product *= num
	}

	x := byte(product % 256)

	ip := net.IP{127, 0, 0, x}
	aRecord := rr.ARecord{Address: ip}

	resourceRecord := rr.ResourceRecord{
		Name:   name,
		Type:   rr.TypeA,
		Class:  1,
		TTL:    60,
		Record: aRecord,
	}

	log.Printf("[Multiply] Calculated 127.0.0.%d for %s", x, sName)
	return []rr.ResourceRecord{resourceRecord}, true
}

func (r *Resolver) resolveInternal(
	name []byte,
	qtype rr.RecordType,
	depth int) ([]rr.ResourceRecord, error) {
	if depth > maxCNAMEs {
		return nil, fmt.Errorf("max CNAME depth exceeded")
	}

	answers, err := r.iterate(name, qtype)
	if err != nil {
		return nil, err
	}

	var finalAnswers []rr.ResourceRecord
	for _, record := range answers {
		if record.Type == rr.TypeCName && bytes.Equal(record.Name, name) {
			cname := record.Record.(rr.CNameRecord).CanonicalName
			log.Printf("Found CNAME: %s -> %s", name, cname)
			cnameAnswers, err := r.resolveInternal(cname, qtype, depth+1)
			if err != nil {
				return nil, err
			}
			return append([]rr.ResourceRecord{record}, cnameAnswers...), nil
		}
		finalAnswers = append(finalAnswers, record)
	}

	return finalAnswers, nil
}

func (r *Resolver) iterate(name []byte, qtype rr.RecordType) ([]rr.ResourceRecord, error) {
	currentNameServers := GetRootServers()

	for range maxNSjumps {
		serverToQuery := currentNameServers[0]
		query := buildQuery(name, qtype)
		log.Printf("Iterate: querying %s for %s (%s)", serverToQuery, name, qtype)

		response, err := sendQuery(serverToQuery, query)
		if err != nil {
			log.Printf("Error querying %s: %v", serverToQuery, err)
			currentNameServers = currentNameServers[1:]
			if len(currentNameServers) == 0 {
				return nil, fmt.Errorf("all nameservers failed")
			}
			continue
		}

		if response.Header.ResponseCode() != pb.OK {
			log.Printf("Got RCode: %v", response.Header.ResponseCode())
			var soa *rr.ResourceRecord
			if response.Header.NSCount > 0 {
				for _, auth := range response.Authorities {
					if auth.Type == 6 {
						soa = &auth
						break
					}
				}
			}
			return nil, RCodeError{
				RCode: response.Header.ResponseCode(),
				SOA:   soa,
			}
		}

		if response.Header.ANCount > 0 {
			var answers []rr.ResourceRecord
			for _, ans := range response.Answers {
				if (ans.Type == qtype || ans.Type == rr.TypeCName) && bytes.Equal(ans.Name, name) {
					answers = append(answers, ans)
				}
			}

			if len(answers) > 0 {
				log.Printf("Found Answer for %s", name)
				return answers, nil
			}
		}

		if response.Header.NSCount > 0 {
			nsNames, glueIPs := r.processReferral(response)

			if len(glueIPs) > 0 {
				log.Printf("Got referral for %s", name)
				currentNameServers = glueIPs
				continue
			}

			if len(nsNames) > 0 {
				log.Printf("Got referral for %s. Resolving NS: %s", name, nsNames[0])
				nsIPs, err := r.resolveInternal(nsNames[0], rr.TypeA, 0)
				if err != nil || len(nsIPs) == 0 {
					return nil, fmt.Errorf("failed to resolve NS: %s", nsNames[0])
				}

				var nsAddrs []string
				for _, ipRec := range nsIPs {
					if ipRec.Type == rr.TypeA {
						nsAddrs = append(nsAddrs, ipRec.Record.(rr.ARecord).Address.String()+":53")
					}
				}

				if len(nsAddrs) == 0 {
					return nil, fmt.Errorf("no A records found for NS: %s", nsNames[0])
				}

				currentNameServers = nsAddrs
				continue
			}
		}

		if response.Header.ANCount == 0 && response.Header.ResponseCode() == pb.OK {
			log.Printf("Got NoData response (RCode=0, AN=0) for %s", name)
			return []rr.ResourceRecord{}, nil
		}

		return nil, fmt.Errorf("server failure: unexpected response from %s", serverToQuery)
	}

	return nil, fmt.Errorf("resolution depth exceeded")
}

func (r *Resolver) processReferral(resp pb.DNSPacket) (nsNames [][]byte, glueIPs []string) {
	for _, auth := range resp.Authorities {
		if auth.Type == rr.TypeNS {
			nsName := auth.Record.(rr.NSRecord).NameServer
			nsNames = append(nsNames, nsName)
			for _, add := range resp.Additional {
				if add.Type == rr.TypeA && bytes.Equal(add.Name, nsName) {
					ip := add.Record.(rr.ARecord).Address.String()
					glueIPs = append(glueIPs, ip+":53")
				}
			}
		}
	}
	return
}

type RCodeError struct {
	RCode pb.RCode
	SOA   *rr.ResourceRecord
}

func (e RCodeError) Error() string {
	return fmt.Sprintf("DNS RCode Error: %v", e.RCode)
}

func buildErrorResponse(req pb.DNSPacket, rcode pb.RCode) pb.DNSPacket {
	hdr := pb.DNSHeader{
		ID:   req.Header.ID,
		Bits: req.Header.Bits,
	}

	hdr.SetIsResponse(true)
	hdr.SetResponseCode(rcode)
	hdr.SetRecursionAvailable(false)
	hdr.ANCount = 0
	hdr.NSCount = 0
	hdr.ARCount = 0

	return pb.DNSPacket{
		Header:    hdr,
		Questions: req.Questions,
	}
}

func buildSuccessResponse(req pb.DNSPacket, answers []rr.ResourceRecord) pb.DNSPacket {
	hdr := pb.DNSHeader{
		ID:   req.Header.ID,
		Bits: req.Header.Bits,
	}
	hdr.SetIsResponse(true)
	hdr.SetResponseCode(pb.OK)
	hdr.SetRecursionAvailable(false)

	return pb.DNSPacket{
		Header:    hdr,
		Questions: req.Questions,
		Answers:   answers,
	}
}
