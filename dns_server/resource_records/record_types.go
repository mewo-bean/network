package resource_records

import (
	"fmt"
)

type RecordType uint16

const (
	TypeA     RecordType = 1
	TypeNS    RecordType = 2
	TypeCName RecordType = 5
	TypeMX    RecordType = 15
	TypeAAAA  RecordType = 28
)

func (recType RecordType) String() string {
	switch recType {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCName:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("Type%d", recType)
	}
}

type Record interface {
	SerializeDNS() ([]byte, error)
	String() string
}

type UnknownRecord struct {
	Data []byte
}

func (u UnknownRecord) SerializeDNS() ([]byte, error) {
	return u.Data, nil
}
func (u UnknownRecord) String() string {
	return fmt.Sprintf("[Unknown Record: %d bytes]", len(u.Data))
}
