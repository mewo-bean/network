package resource_records

import (
	"dns_server/utils"
	"io"
)

type NSRecord struct {
	NameServer []byte
}

func (ns NSRecord) SerializeDNS() ([]byte, error) {
	return utils.WriteDomainName(ns.NameServer), nil
}
func (ns NSRecord) String() string {
	return string(ns.NameServer)
}

func parseNSRecord(r io.ReadSeeker) (Record, error) {
	dn, err := utils.ReadDomainName(r)
	if err != nil {
		return nil, err
	}
	return NSRecord{NameServer: dn}, nil
}
