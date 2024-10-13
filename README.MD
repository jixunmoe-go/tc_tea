# TC_TEA GO

[tc_tea] implemented in GoLang.

[tc_tea]: https://github.com/TarsCloud/TarsCpp/blob/v3.0.20/util/src/tc_tea.cpp#L172

## Usage

```sh
go get github.com/jixunmoe-go/tc_tea@v0.1.0
```

Example usage:

```go
package main

import (
	"bytes"
	"github.com/jixunmoe-go/tc_tea"
	"log"
)

func main() {
	key := []byte("12345678ABCDEFGH")
	encrypted, err := tc_tea.Encrypt([]byte("hello world"), key)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := tc_tea.Decrypt(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(decrypted, []byte("hello world")) {
		log.Fatal("decrypted != []byte(\"hello world\")")
	}
}
```