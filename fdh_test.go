package fdh

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

var message = []byte("ATTACK AT DAWN")

func TestKnownResults(t *testing.T) {
	h := New(crypto.SHA256, 256)
	h.Write(message)
	// echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256
	if hex.EncodeToString(h.Sum(nil)) != "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f1" {
		t.Error("Bad result on known outout")
	}

	h = New(crypto.SHA256, 128)
	h.Write(message)
	// echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256
	if hex.EncodeToString(h.Sum(nil)) != "015d53c7925b4434f00286fe2f0eb283" {
		t.Error("Bad result on known outout")
	}

	h = New(crypto.SHA256, 264)
	h.Write(message)
	h.Sum(nil)
	// echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 && echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256
	if hex.EncodeToString(h.Sum(nil)) != "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158" {
		t.Error("Bad result on known outout")
	}

	h = New(crypto.SHA256, 1024)
	h.Write(message)
	// See READNE.md for bash command under "Bash Equivalent" sectiin.
	if hex.EncodeToString(h.Sum(nil)) != "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158617fec3b813f834cd86ab0dd26b971c46b7ede451b490279628a265edf0a10691095675808b47c0add4300b3181a31109cbc31a945d05562ceb6cca0fea834d9c456fe1abf34a5a775ed572ce571b1dcca03b984102e666e9ab876876fb3af" {
		t.Error("Bad result on known outout")
	}

}

func TestSHA256(t *testing.T) {
	h := New(crypto.SHA256, 1024)
	h.Write(message)
	result := h.Sum(nil)

	if len(result) != 1024/8 {
		t.Error("Hash result not the same length as bit length")
	}
	if h.Size() != len(result) {
		t.Error("Hash result not the same length Size()")
	}
	if h.BlockSize() != sha256.BlockSize {
		t.Error("Incorrect block size")
	}

	// Now let's do it manually and confirm they are the same
	var manual []byte
	h0 := sha256.New()
	h0.Write(message)
	h0.Write([]byte{byte(0)})
	manual = h0.Sum(manual)

	h1 := sha256.New()
	h1.Write(message)
	h1.Write([]byte{byte(1)})
	manual = h1.Sum(manual)

	h2 := sha256.New()
	h2.Write(message)
	h2.Write([]byte{byte(2)})
	manual = h2.Sum(manual)

	h3 := sha256.New()
	h3.Write(message)
	h3.Write([]byte{byte(3)})
	manual = h3.Sum(manual)

	if !bytes.Equal(result, manual) {
		t.Error("Hash result not the same as manually constructed result")
	}

	// Test calling the utility Sum function
	if !bytes.Equal(result, Sum(crypto.SHA256, 1024, message)) {
		t.Error("Hash result not the same when called via Sum")
	}
}

// Writing after calling Sum() should panic
func TestPanicFinalized(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic for writing after being finalized")
		}
	}()

	h := New(crypto.SHA256, 1024)
	h.Write(message)
	h.Sum(nil)
	h.Write(message)
}

// Using an unimported hash should panic
func TestPanicNoImport(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic for using unimported hash")
		}
	}()

	h := New(crypto.MD5, 1024)
	h.Write(message)
	h.Sum(nil)
}

// Using an unimported hash should panic
func TestPanicOddBitlen(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic when using a bitlen that does not fit hash")
		}
	}()

	h := New(crypto.SHA256, 2379)
	h.Write(message)
	h.Sum(nil)
}

// Using an unimported hash should panic
func TestPanicZeroBitlen(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic when using a small bitlen")
		}
	}()

	h := New(crypto.SHA256, 0)
	h.Write(message)
	h.Sum(nil)
}
