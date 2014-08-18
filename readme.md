Full Domain Hash
================

[![GoDoc](https://godoc.org/github.com/cryptoballot/fdh?status.svg)](https://godoc.org/github.com/cryptoballot/fdh)

An Full Domain Hash (FDH) is a useful cryptographic construction that extends the size of a hash digest to an arbitrary length

We construct an FDH by computing a number of `cycles` where `cycles=(target length)/(digest length) + 1`
We then compute `FDH(M) = HASH(M||0)||HASH(M||1)||...||HASH(M||cycles−1)` where `HASH` is any hash function defined in package crypto and `||` denotes concatenation

FDHs are usually used with an RSA signature scheme where the target length is the size of the key. See https://en.wikipedia.org/wiki/Full_Domain_Hash

## Example
```go
import (
	"crypto"
	_ "crypto/sha256"
	"github.com/cryptoballot/fdh"
	"fmt"
	"encoding/hex"
)

var message = []byte("ATTACK AT DAWN")

func main() {
	h := fdh.New(crypto.SHA256, 2048)
	h.Write(message)
	digest := h.Sum(nil)
	
	// We now have a SHA256 digest that has been extended from 256 bits to 2048 bits.
	fmt.Println(hex.EncodeToString(digest))
}
```

As a shortcut you can also use the `Sum` function.

```go
import (
	"crypto"
	_ "crypto/md5"
	"github.com/cryptoballot/fdh"
	"log"
)

var message = []byte("ATTACK AT DAWN")

func main() {
	digest := fdh.Sum(crypto.MD5, 1024, message)
	// ... do something with digest ...
}
```
