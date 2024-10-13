package tea_impl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestTcTea_CbcEncrypt(t *testing.T) {
	tea := TcTea{keys: [4]uint32{0x31323334, 0x35363738, 0x41424344, 0x45464748}}
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xfe}
	data, err := tea.CbcEncrypt(data)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	fmt.Printf("encrypt data: %s\n", hex.EncodeToString(data))
	decrypted, err := tea.CbcDecrypt(data)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xfe}) {
		t.Error("decrypted error")
	}
}
