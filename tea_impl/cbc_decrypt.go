package tea_impl

import (
	"encoding/binary"
	"fmt"
)

func (t TcTea) CbcDecrypt(buffer []byte) ([]byte, error) {
	if len(buffer) < 10 || len(buffer)%8 != 0 {
		return nil, fmt.Errorf("invalid buffer length")
	}

	plain := make([]byte, len(buffer))
	copy(plain, buffer)

	iv1 := uint64(0)
	iv2 := uint64(0)
	for i := 0; i < len(buffer); i += 8 {
		bufferBlock := plain[i : i+8]
		iv1Next := binary.BigEndian.Uint64(bufferBlock)
		iv2Next := t.ecbDecrypt(iv1Next ^ iv2)
		binary.BigEndian.PutUint64(bufferBlock, iv2Next^iv1)
		iv1, iv2 = iv1Next, iv2Next
	}

	padSize := plain[0] & 7
	startLoc := 1 + padSize + 2
	endLoc := len(plain) - 7

	value := uint8(0)
	for _, b := range plain[endLoc:] {
		value |= b
	}
	if value != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return plain[startLoc:endLoc], nil
}
