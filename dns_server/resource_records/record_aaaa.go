package resource_records

import (
	"fmt"
	"io"
	"net"
)

type AAAARecord struct {
	Address net.IP
}

func (a AAAARecord) SerializeDNS() ([]byte, error) {
	return a.Address.To16(), nil
}
func (a AAAARecord) String() string {
	return a.Address.String()
}

func parseAAAARecord(rdlength uint16, r io.ReadSeeker) (Record, error) {
	if rdlength != 16 {
		return nil, fmt.Errorf("invalid rdlength for AAAA record: %d", rdlength)
	}
	buf := make([]byte, 16)
	if _, err := r.Read(buf); err != nil {
		return nil, err
	}
	return AAAARecord{Address: net.IP(buf)}, nil
}
