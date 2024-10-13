package tc_tea

import "github.com/jixunmoe-go/tc_tea/tea_impl"

// Encrypt data with key (16 bytes), using tc_tea CBC mode.
// similar to oi_symmetry_encrypt2
func Encrypt(data, key []byte) ([]byte, error) {
	tea, err := tea_impl.NewTcTea(key)
	if err != nil {
		return nil, err
	}
	return tea.CbcEncrypt(data)
}

// Decrypt data with key (16 bytes), using tc_tea CBC mode.
// similar to oi_symmetry_decrypt2
func Decrypt(data, key []byte) ([]byte, error) {
	tea, err := tea_impl.NewTcTea(key)
	if err != nil {
		return nil, err
	}
	return tea.CbcDecrypt(data)
}
