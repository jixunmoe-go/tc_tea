package tea_impl

import (
	"crypto/rand"
	"encoding/binary"
)

const kSaltLen = 2
const kZeroLen = 7
const kFixedPaddingLen = 1 + kSaltLen + kZeroLen

func (t TcTea) CbcEncrypt(buffer []byte) ([]byte, error) {
	length := len(buffer) + kFixedPaddingLen
	paddingLength := (8 - (length % 8)) % 8
	outputLength := length + paddingLength

	result := make([]byte, outputLength)
	headerLength := 1 + paddingLength + kSaltLen
	_, err := rand.Read(result[:headerLength])
	if err != nil {
		return nil, err
	}
	result[0] = (result[0] << 3) | uint8(paddingLength&7)
	copy(result[headerLength:headerLength+len(buffer)], buffer)

	iv1 := uint64(0)
	iv2 := uint64(0)
	for i := 0; i < outputLength; i += 8 {
		bufferBlock := result[i : i+8]
		iv2Next := binary.BigEndian.Uint64(bufferBlock) ^ iv1
		iv1Next := t.ecbEncrypt(iv2Next) ^ iv2
		binary.BigEndian.PutUint64(bufferBlock, iv1Next)
		iv1, iv2 = iv1Next, iv2Next
	}
	return result, nil
}
