package packet_builder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type DNSHeader struct {
	ID      uint16
	Bits    uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type OpCode int
type RCode int

const (
	OpCodeQuery OpCode = 0
)

const (
	OK RCode = iota
	FormatErr
	NameServerErr
	ExistanceErr
	TypeErr
	SecurityErr
)

func (h DNSHeader) SerializeDNS() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, h); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ParseHeader(r io.Reader) (DNSHeader, error) {
	var h DNSHeader
	if err := binary.Read(r, binary.BigEndian, &h); err != nil {
		return h, fmt.Errorf("failed to read Header: %w", err)
	}
	return h, nil
}

func (h DNSHeader) IsResponse() bool {
	return ((h.Bits >> 15) & 1) > 0
}

func (h *DNSHeader) SetIsResponse(v bool) {
	if v {
		h.Bits |= (1 << 15)
	} else {
		h.Bits &^= (1 << 15)
	}
}

func (h DNSHeader) OpCode() OpCode {
	return OpCode((h.Bits >> 11) & 0b1111)
}

func (h *DNSHeader) SetOpCode(op OpCode) {
	h.Bits = (h.Bits & 0b1000011111111111) | (uint16(op) << 11)
}

func (h DNSHeader) IsAuthotityAnswer() bool {
	return ((h.Bits >> 10) & 1) > 0
}

func (h DNSHeader) IsTruncated() bool {
	return ((h.Bits >> 9) & 1) > 0
}

func (h DNSHeader) IsRecursionDesired() bool {
	return ((h.Bits >> 8) & 1) > 0
}

func (h *DNSHeader) SetRecursionDesired(v bool) {
	if v {
		h.Bits |= (1 << 8)
	} else {
		h.Bits &^= (1 << 8)
	}
}

func (h DNSHeader) IsRecursionAvailable() bool {
	return ((h.Bits >> 7) & 1) > 0
}

func (h *DNSHeader) SetRecursionAvailable(v bool) {
	if v {
		h.Bits |= (1 << 7)
	} else {
		h.Bits &^= (1 << 7)
	}
}

func (h DNSHeader) Z() uint16 {
	return 0
}

func (h DNSHeader) ResponseCode() RCode {
	return RCode(h.Bits & 0b1111)
}

func (h *DNSHeader) SetResponseCode(rc RCode) {
	h.Bits = (h.Bits & 0b1111111111110000) | uint16(rc)
}

func (h DNSHeader) String() string {
	return fmt.Sprintf(
		"ID %d | IsResponse: %t | OpCode: %v | AA: %t | TC: %t | "+
			"RD: %t | RA: %t | RCode: %v | QD: %d | AN: %d | NS: %d | AR: %d",
		h.ID,
		h.IsResponse(),
		h.OpCode(),
		h.IsAuthotityAnswer(),
		h.IsTruncated(),
		h.IsRecursionDesired(),
		h.IsRecursionAvailable(),
		h.ResponseCode(),
		h.QDCount,
		h.ANCount,
		h.NSCount,
		h.ARCount,
	)
}
