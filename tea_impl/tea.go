package tea_impl

import (
	"encoding/binary"
	"errors"
)

type TcTea struct {
	keys [4]uint32
}

func NewTcTea(key []byte) (*TcTea, error) {
	if len(key) != 16 {
		return nil, errors.New("keys length must be 16")
	}

	keys := [4]uint32{}
	for i := 0; i < 4; i++ {
		keys[i] = binary.BigEndian.Uint32(key[i*4 : i*4+4])
	}
	return &TcTea{keys}, nil
}
