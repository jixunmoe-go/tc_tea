package tea_impl

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEcbDecryptBytes(t *testing.T) {
	tea := TcTea{keys: [4]uint32{0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00}}

	buffer := []byte{0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16}
	err := tea.ecbDecryptBytes(buffer)
	if err != nil {
		t.Errorf("ecbDecryptBytes() error = %v", err)
	}
	if !bytes.Equal(buffer, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Errorf("buffer decrypt error")
	}
}

func TestEcbEncryptBytes(t *testing.T) {
	tea := TcTea{keys: [4]uint32{0x7ffffff1, 0x7ffffff2, 0x7ffffff3, 0x7ffffff4}}

	buffer := []byte{0x7f, 1, 2, 3, 0x80, 4, 5, 6}
	err := tea.ecbEncryptBytes(buffer)
	if err != nil {
		t.Errorf("ecbEncryptBytes() error = %v", err)
	}
	if !bytes.Equal(buffer, []byte{0x59, 0x6a, 0x9d, 0x4c, 0x5c, 0xf8, 0x66, 0x24}) {
		fmt.Printf("%x\n", buffer)
		t.Errorf("buffer decrypt error")
	}
}
