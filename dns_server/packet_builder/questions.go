package packet_builder

import (
	"bytes"
	"dns_server/resource_records"
	"dns_server/utils"
	"encoding/binary"
	"fmt"
	"io"
)

type DNSQuestion struct {
	Name  []byte
	Type  resource_records.RecordType
	Class uint16
}

func (q DNSQuestion) SerializeDNS() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(utils.WriteDomainName(q.Name))
	binary.Write(buf, binary.BigEndian, q.Type)
	binary.Write(buf, binary.BigEndian, q.Class)
	return buf.Bytes(), nil
}

func (q DNSQuestion) String() string {
	return fmt.Sprintf("%s %s", string(q.Name), q.Type)
}

func ParseQuestions(count uint16, r io.ReadSeeker) ([]DNSQuestion, error) {
	questions := make([]DNSQuestion, 0, count)
	for range count {
		var q DNSQuestion
		dn, err := utils.ReadDomainName(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain name: %w", err)
		}
		q.Name = dn
		if err := binary.Read(r, binary.BigEndian, &q.Type); err != nil {
			return nil, fmt.Errorf("failed to read query type: %w", err)
		}
		if err := binary.Read(r, binary.BigEndian, &q.Class); err != nil {
			return nil, fmt.Errorf("failed to read query class: %w", err)
		}

		questions = append(questions, q)
	}
	return questions, nil
}
