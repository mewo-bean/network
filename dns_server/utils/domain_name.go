package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func ReadDomainName(r io.ReadSeeker) ([]byte, error) {
	var parts [][]byte
	var jumps int
	const maxJumps = 5
	posToRestore := int64(-1)

	for {
		if jumps > maxJumps {
			return nil, fmt.Errorf("tried to make more than %d jumps", maxJumps)
		}

		var length byte
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to read label length: %w", err)
		}

		if length == 0 {
			break
		}

		if (length & 0b11000000) == 0b11000000 {
			var b2 byte
			if err := binary.Read(r, binary.BigEndian, &b2); err != nil {
				return nil, fmt.Errorf("failed to read pointer byte 2: %w", err)
			}
			offset := int64(((uint16(length) & 0x3F) << 8) | uint16(b2))

			if posToRestore == -1 {
				curPos, err := r.Seek(0, io.SeekCurrent)
				if err != nil {
					return nil, fmt.Errorf("failed to get current position: %w", err)
				}
				posToRestore = curPos
			}

			if _, err := r.Seek(offset, io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to follow a label pointer: %w", err)
			}
			jumps++
			continue
		}

		if (length & 0b11000000) != 0b00000000 {
			return nil, fmt.Errorf("invalid label type: %b", length)
		}

		label, err := ReadLabel(length, r)
		if err != nil {
			return nil, err
		}
		parts = append(parts, label)
	}

	if posToRestore != -1 {
		if _, err := r.Seek(posToRestore, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to return to original position: %w", err)
		}
	}

	return bytes.Join(parts, []byte(".")), nil
}

func ReadLabel(length byte, r io.Reader) ([]byte, error) {
	label := make([]byte, length)
	if _, err := r.Read(label); err != nil {
		return nil, fmt.Errorf("failed to read bytes: %w", err)
	}
	return label, nil
}

func WriteDomainName(name []byte) []byte {
	buf := new(bytes.Buffer)
	parts := bytes.SplitSeq(name, []byte("."))
	for part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.Write(part)
	}
	buf.WriteByte(0x00)
	return buf.Bytes()
}
