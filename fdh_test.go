package fdh

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"
)

var message = []byte("ATTACK AT DAWN")

func TestSHA256(t *testing.T) {
	h := New(crypto.SHA256, 1024)
	h.Write(message)
	result := h.Sum(nil)

	if len(result) != 1024/8 {
		t.Error("Hash result not the same length as bit length")
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
}
