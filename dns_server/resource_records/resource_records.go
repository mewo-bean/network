package resource_records

import (
	"bytes"
	"dns_server/utils"
	"encoding/binary"
	"fmt"
	"io"
)

type ResourceRecord struct {
	Name   []byte
	Type   RecordType
	Class  uint16
	TTL    uint32
	Record Record
}

func (rr ResourceRecord) SerializeDNS() ([]byte, error) {
	buf := new(bytes.Buffer)

	buf.Write(utils.WriteDomainName(rr.Name))

	binary.Write(buf, binary.BigEndian, rr.Type)
	binary.Write(buf, binary.BigEndian, rr.Class)
	binary.Write(buf, binary.BigEndian, rr.TTL)

	recordBytes, err := rr.Record.SerializeDNS()
	if err != nil {
		return nil, err
	}

	binary.Write(buf, binary.BigEndian, uint16(len(recordBytes)))
	buf.Write(recordBytes)

	return buf.Bytes(), nil
}

func (rr ResourceRecord) String() string {
	return fmt.Sprintf("%s %d %s %s", string(rr.Name), rr.TTL, rr.Type, rr.Record)
}

func ParseResourceRecords(count uint16, r io.ReadSeeker) ([]ResourceRecord, error) {
	result := make([]ResourceRecord, 0, count)
	for i := range count {
		var rr ResourceRecord
		dn, err := utils.ReadDomainName(r)
		if err != nil {
			return nil, fmt.Errorf("record %d: failed to read domain name: %w", i, err)
		}
		rr.Name = dn

		if err := binary.Read(r, binary.BigEndian, &rr.Type); err != nil {
			return nil, fmt.Errorf("record %d: failed to read type: %w", i, err)
		}
		if err := binary.Read(r, binary.BigEndian, &rr.Class); err != nil {
			return nil, fmt.Errorf("record %d: failed to read class: %w", i, err)
		}
		if err := binary.Read(r, binary.BigEndian, &rr.TTL); err != nil {
			return nil, fmt.Errorf("record %d: failed to read TTL: %w", i, err)
		}

		var rdlength uint16
		if err := binary.Read(r, binary.BigEndian, &rdlength); err != nil {
			return nil, fmt.Errorf("record %d: failed to read rdlength: %w", i, err)
		}

		switch rr.Type {
		case TypeA:
			rr.Record, err = parseARecord(rdlength, r)
		case TypeAAAA:
			rr.Record, err = parseAAAARecord(rdlength, r)
		case TypeNS:
			rr.Record, err = parseNSRecord(r)
		case TypeCName:
			rr.Record, err = parseCNameRecord(r)
		case TypeMX:
			rr.Record, err = parseMXRecord(r)
		default:

			buf := make([]byte, rdlength)
			if rdlength > 0 {
				n, errRead := r.Read(buf)
				if errRead != nil {
					return nil, fmt.Errorf("record %d: failed to read unknown record data: %w", i, errRead)
				}
				buf = buf[:n]
			}
			rr.Record = UnknownRecord{Data: buf}
			err = nil
		}

		if err != nil {
			return nil, fmt.Errorf("record %d: failed to parse record type %v: %w", i, rr.Type, err)
		}
		result = append(result, rr)
	}

	return result, nil
}
