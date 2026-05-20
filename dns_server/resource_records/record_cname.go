package resource_records

import (
	"dns_server/utils"
	"io"
)

type CNameRecord struct {
	CanonicalName []byte
}

func (c CNameRecord) SerializeDNS() ([]byte, error) {
	return utils.WriteDomainName(c.CanonicalName), nil
}
func (c CNameRecord) String() string {
	return string(c.CanonicalName)
}

func parseCNameRecord(r io.ReadSeeker) (Record, error) {
	dn, err := utils.ReadDomainName(r)
	if err != nil {
		return nil, err
	}
	return CNameRecord{CanonicalName: dn}, nil
}
