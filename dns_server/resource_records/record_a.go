package resource_records

import (
	"fmt"
	"io"
	"net"
)

type ARecord struct {
	Address net.IP
}

func (a ARecord) SerializeDNS() ([]byte, error) {
	return a.Address.To4(), nil
}
func (a ARecord) String() string {
	return a.Address.String()
}

func parseARecord(rdlength uint16, r io.ReadSeeker) (Record, error) {
	if rdlength != 4 {
		return nil, fmt.Errorf("invalid rdlength for A record: %d", rdlength)
	}
	buf := make([]byte, 4)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	return ARecord{Address: net.IP(buf)}, nil
}
