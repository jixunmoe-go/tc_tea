package tea_impl

import (
	"encoding/binary"
	"errors"
)

const kRounds uint32 = 16
const kDelta uint32 = 0x9e3779b9
const kInitialDecryptionSum uint32 = 0xe3779b90

func ecb_single_round(value uint32, sum uint32, key1 uint32, key2 uint32) uint32 {
	left := (value << 4) + key1
	right := (value >> 5) + key2
	mid := sum + value

	return left ^ mid ^ right
}

func (t TcTea) ecbDecrypt(value uint64) uint64 {
	sum := kInitialDecryptionSum
	y := uint32(value >> 32)
	z := uint32(value)

	for i := uint32(0); i < kRounds; i++ {
		z -= ecb_single_round(y, sum, t.keys[2], t.keys[3])
		y -= ecb_single_round(z, sum, t.keys[0], t.keys[1])
		sum -= kDelta
	}

	return (uint64(y) << 32) | uint64(z)
}

func (t TcTea) ecbDecryptBytes(block []byte) error {
	if len(block) != 8 {
		return errors.New("block size is too small")
	}

	value := binary.BigEndian.Uint64(block)
	value = t.ecbDecrypt(value)
	binary.BigEndian.PutUint64(block, value)
	return nil
}

func (t TcTea) ecbEncrypt(value uint64) uint64 {
	sum := uint32(0)
	y := uint32(value >> 32)
	z := uint32(value)

	for i := uint32(0); i < kRounds; i++ {
		sum += kDelta
		y += ecb_single_round(z, sum, t.keys[0], t.keys[1])
		z += ecb_single_round(y, sum, t.keys[2], t.keys[3])
	}

	return (uint64(y) << 32) | uint64(z)
}

func (t TcTea) ecbEncryptBytes(block []byte) error {
	if len(block) != 8 {
		return errors.New("block size is too small")
	}

	value := binary.BigEndian.Uint64(block)
	value = t.ecbEncrypt(value)
	binary.BigEndian.PutUint64(block, value)
	return nil
}
