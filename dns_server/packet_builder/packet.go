package packet_builder

import (
	"bytes"
	rr "dns_server/resource_records"
	"fmt"
	"io"
)

type DNSPacket struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []rr.ResourceRecord
	Authorities []rr.ResourceRecord
	Additional  []rr.ResourceRecord
}

func ParsePacket(bb []byte) (DNSPacket, error) {
	var rs io.ReadSeeker = bytes.NewReader(bb)

	hdr, err := ParseHeader(rs)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("failed to parse header: %w", err)
	}

	questions, err := ParseQuestions(hdr.QDCount, rs)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("failed to parse question section: %w", err)
	}

	answers, err := rr.ParseResourceRecords(hdr.ANCount, rs)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("failed to parse answer section: %w", err)
	}

	authorities, err := rr.ParseResourceRecords(hdr.NSCount, rs)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("failed to parse authority section: %w", err)
	}

	additional, err := rr.ParseResourceRecords(hdr.ARCount, rs)
	if err != nil {
		return DNSPacket{}, fmt.Errorf("failed to parse additional section: %w", err)
	}

	return DNSPacket{
		Header:      hdr,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additional:  additional,
	}, nil
}

func (packet DNSPacket) SerializeDNS() ([]byte, error) {
	buf := new(bytes.Buffer)

	packet.Header.QDCount = uint16(len(packet.Questions))
	packet.Header.ANCount = uint16(len(packet.Answers))
	packet.Header.NSCount = uint16(len(packet.Authorities))
	packet.Header.ARCount = uint16(len(packet.Additional))

	hdrBytes, err := packet.Header.SerializeDNS()
	if err != nil {
		return nil, err
	}
	buf.Write(hdrBytes)

	if err := serializeSection(buf, packet.Questions); err != nil {
		return nil, fmt.Errorf("failed to serialize questions: %w", err)
	}

	if err := serializeSection(buf, packet.Answers); err != nil {
		return nil, fmt.Errorf("failed to serialize answers: %w", err)
	}

	if err := serializeSection(buf, packet.Authorities); err != nil {
		return nil, fmt.Errorf("failed to serialize authorities: %w", err)
	}

	if err := serializeSection(buf, packet.Additional); err != nil {
		return nil, fmt.Errorf("failed to serialize additional: %w", err)
	}

	return buf.Bytes(), nil
}

func serializeSection[T interface{ SerializeDNS() ([]byte, error) }](
	buf *bytes.Buffer, records []T) error {
	for _, r := range records {
		rBytes, err := r.SerializeDNS()
		if err != nil {
			return err
		}
		buf.Write(rBytes)
	}
	return nil
}

func (packet DNSPacket) String() string {
	return fmt.Sprintf(
		"Header: %s\n Questions: %v\n Answers: %v\n Authorities: %v\n Additional: %v",
		packet.Header,
		packet.Questions,
		packet.Answers,
		packet.Authorities,
		packet.Additional,
	)
}
