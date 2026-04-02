package masque

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	TypeDatagram = 0x00
)

type Capsule struct {
	Type  uint64
	Value []byte
}

func ReadVarInt(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	b[0] = b[0] & 0x3f
	
	if length > 1 {
		if _, err := io.ReadFull(r, b[1:length]); err != nil {
			return 0, err
		}
	}
	
	var val uint64
	for i := 0; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, nil
}

func WriteVarInt(w io.Writer, val uint64) error {
	var b []byte
	if val <= 0x3f {
		b = []byte{byte(val)}
	} else if val <= 0x3fff {
		b = []byte{byte(val>>8) | 0x40, byte(val)}
	} else if val <= 0x3fffffff {
		b = make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(val))
		b[0] |= 0x80
	} else if val <= 0x3fffffffffffffff {
		b = make([]byte, 8)
		binary.BigEndian.PutUint64(b, val)
		b[0] |= 0xc0
	} else {
		return fmt.Errorf("value too large for varint")
	}
	_, err := w.Write(b)
	return err
}

func ReadCapsule(r io.Reader) (*Capsule, error) {
	typ, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	length, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	
	val := make([]byte, length)
	if _, err := io.ReadFull(r, val); err != nil {
		return nil, err
	}
	
	return &Capsule{Type: typ, Value: val}, nil
}

func WriteCapsule(w io.Writer, c *Capsule) error {
	if err := WriteVarInt(w, c.Type); err != nil {
		return err
	}
	if err := WriteVarInt(w, uint64(len(c.Value))); err != nil {
		return err
	}
	_, err := w.Write(c.Value)
	return err
}
