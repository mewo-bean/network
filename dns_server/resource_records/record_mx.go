package resource_records

import (
	"bytes"
	"dns_server/utils"
	"encoding/binary"
	"fmt"
	"io"
)

type MXRecord struct {
	Preference uint16
	Exchange   []byte
}

func (mx MXRecord) SerializeDNS() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, mx.Preference)
	buf.Write(utils.WriteDomainName(mx.Exchange))

	return buf.Bytes(), nil
}
func (mx MXRecord) String() string {
	return fmt.Sprintf("%d %s", mx.Preference, string(mx.Exchange))
}

func parseMXRecord(r io.ReadSeeker) (Record, error) {
	var pref uint16
	if err := binary.Read(r, binary.BigEndian, &pref); err != nil {
		return nil, fmt.Errorf("failed to read MX preference: %w", err)
	}

	dn, err := utils.ReadDomainName(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read MX exchange: %w", err)
	}
	return MXRecord{Preference: pref, Exchange: dn}, nil
}
