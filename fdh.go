package fdh

import (
	"crypto"
	"hash"
	"math"
	"strconv"
	"sync"
)

// digest represents the partial evaluation of a Full Domain Hash checksum.
type digest struct {
	base  crypto.Hash
	bits  int
	parts []hash.Hash
	final bool // Unlike many hash functions Full Domain Hashes are "finalized" after a call to Sum() and cannot be furthur written to.
}

// New returns a hash.Hash for computing a Full Domain Hash checksum, given a base hash function and a target bit length.
// It will panic if the bitlen is not a multiple of the hash length or if the hash library is not imported.
func New(h crypto.Hash, bitlen int) hash.Hash {
	if !h.Available() {
		panic("fdh: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable. Make sure your hash function is proprely imported.")
	} else if bitlen%8 != 0 {
		panic("fdh: hash digest size should be a multiple of 8")
	} else if bitlen <= 0 {
		panic("fdh: hash digest size cannot be less or equal to zero")
	}

	numparts := int(math.Ceil(float64(bitlen) / float64((h.Size() * 8))))

	d := digest{
		base:  h,
		bits:  bitlen,
		parts: make([]hash.Hash, numparts, numparts),
	}
	d.Reset()
	return &d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	for i := range d.parts {
		d.parts[i] = d.base.New()
	}
	d.final = false
}

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int {
	return d.parts[0].BlockSize()
}

// Size returns the number of bytes Sum will return. This will be the same as the bitlen (with conversion from bits to bytes)
func (d *digest) Size() int {
	return d.bits / 8
}

// Add more data to the running hash.
// Once Sum() is called the hash is finalized and writing to the hash will panic
func (d *digest) Write(p []byte) (int, error) {
	if d.final {
		panic("Cannot write to Full Domain Hash after a call has been made to Sum() and the hash has been finalized.")
	}

	// Write to each component hash asyncronously
	var wg sync.WaitGroup
	for i, h := range d.parts {
		wg.Add(1)
		go func(i int, h hash.Hash) {
			h.Write(p) // Hashes in crypto library don't return errors
			wg.Done()
		}(i, h)
	}
	wg.Wait()

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// Once Sum is called, the hash is finalized and can no longer be written to
func (d *digest) Sum(in []byte) []byte {
	hash := d.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() []byte {
	var sum []byte
	for i, h := range d.parts {
		if !d.final {
			finalByte := byte(i)
			h.Write([]byte{finalByte})
		}
		sum = append(sum, h.Sum(nil)...)
	}
	d.final = true
	return sum[:d.bits/8]
}

// Sum returns the the Full Domain Hash checksum of the data.
func Sum(h crypto.Hash, bitlen int, message []byte) []byte {
	hash := New(h, bitlen)
	hash.Write(message)
	return hash.Sum(nil)
}
