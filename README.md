Full Domain Hash
================

[![Build Status](https://travis-ci.org/cryptoballot/fdh.svg?branch=master)](https://travis-ci.org/cryptoballot/fdh)
[![Build Status](https://scrutinizer-ci.com/g/cryptoballot/fdh/badges/build.png?b=master)](https://scrutinizer-ci.com/g/cryptoballot/fdh/build-status/master)
[![Go Report Card](https://goreportcard.com/badge/github.com/cryptoballot/fdh)](https://goreportcard.com/report/github.com/cryptoballot/fdh)
[![Coverage Status](https://coveralls.io/repos/github/cryptoballot/fdh/badge.svg?branch=master)](https://coveralls.io/github/cryptoballot/fdh?branch=master)
[![Scrutinizer Issues](https://img.shields.io/badge/scrutinizer-issues-blue.svg)](https://scrutinizer-ci.com/g/cryptoballot/fdh/issues)
[![GoDoc](https://godoc.org/github.com/cryptoballot/fdh?status.svg)](https://godoc.org/github.com/cryptoballot/fdh)


A Full Domain Hash (FDH) is a useful cryptographic construction that extends the size of a hash digest to an arbitrary length. For example, SHA256 can be expanded to 1024 bits instead of the usual 256 bits.

We construct an FDH by computing a number of `cycles` where `cycles=(target length)/(digest length) + 1`
We then compute `FDH(M) = HASH(M||0)||HASH(M||1)||...||HASH(M||cycles−1)`, where `HASH` is any hash function defined in package crypto,  `||` denotes concatenation, and numerical values are binary (`\x01`, `\x02` etc). 

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

## Bash equivalent
```bash
# Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits
echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
echo -n -e 'ATTACK AT DAWN\x02' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
echo -n -e 'ATTACK AT DAWN\x03' | shasum -a 256 | cut -d ' ' -f 1
```
