package parser

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/rs/zerolog/log"
)

const (
	gcmBlockSize = 16
	gcmTagSize   = 16
	// gcmMinimumTagSize    = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	// gcmStandardNonceSize = 12
)

// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//
//	the coefficient of x⁰ can be obtained by v.low >> 63.
//	the coefficient of x⁶³ can be obtained by v.low & 1.
//	the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//	the coefficient of x¹²⁷ can be obtained by v.high & 1.
type gcmFieldElement struct {
	low, high uint64
}

// gcm represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	// cipher    Block
	// nonceSize int
	// tagSize   int
	// productTable contains the first sixteen powers of the key, H.
	// However, they are in bit reversed order. See NewGCMWithNonceSize.
	productTable [16]gcmFieldElement
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
func gcmAdd(x, y *gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
func gcmDouble(x *gcmFieldElement) (double gcmFieldElement) {

	msbSet := x.high&1 == 1
	// Because of the bit-ordering, doubling is actually a right shift.

	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

var gcmReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// mul sets y to y*H, where H is the GCM key, fixed during NewGCMWithNonceSize.
func (g *gcm) mul(y *gcmFieldElement) {
	var z gcmFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(gcmReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions. See the comment
			// in NewGCMWithNonceSize.
			t := &g.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func (g *gcm) updateBlocks(y *gcmFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= binary.BigEndian.Uint64(blocks)
		y.high ^= binary.BigEndian.Uint64(blocks[8:])
		g.mul(y)
		blocks = blocks[gcmBlockSize:]
	}
}

// update extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
func (g *gcm) update(y *gcmFieldElement, data []byte) {
	fullBlocks := (len(data) >> 4) << 4
	g.updateBlocks(y, data[:fullBlocks])

	if len(data) != fullBlocks {
		var partialBlock [gcmBlockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		g.updateBlocks(y, partialBlock[:])
	}
}

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// xorBytes xors the bytes in a and b. The destination should have enough
// space, otherwise xorBytes will panic. Returns the number of bytes xor'd.
func xorBytes(dst, a, b []byte) int {
	n := len(a)

	// b in ou case always 16 bytes long
	// n can be lower if plaintext shorter than 16 bytes
	if len(b) < n {
		n = len(b)
	}
	// return no xor if plaintext a.length == 0
	if n == 0 {
		return 0
	}

	_ = dst[n-1]

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	// xorBytesSSE2(&dst[0], &a[0], &b[0], n) // amd64 must have SSE2
	return n
}

func xorWords(dst, a, b []byte) {
	xorBytes(dst, a, b)
}

// Copyright Jan Lauinger, Yinnan Wu

func AuthGCM(tagMaskCipher string, plaintextCipher string, galoisKexCipher string, lenPlain int, lenAdditionalData int) string {

	// decoding
	tagMask, _ := hex.DecodeString(tagMaskCipher)
	cipher1, _ := hex.DecodeString(plaintextCipher)
	galoisKey, _ := hex.DecodeString(galoisKexCipher)

	// init gcm struct
	g := &gcm{}

	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := gcmFieldElement{
		binary.BigEndian.Uint64(galoisKey[:8]),
		binary.BigEndian.Uint64(galoisKey[8:]),
	}
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}

	// auth function logic
	var y gcmFieldElement
	ad := []byte{}
	g.update(&y, ad)
	g.update(&y, cipher1)

	y.low ^= uint64(lenAdditionalData) * 8
	y.high ^= uint64(lenPlain) * 8

	g.mul(&y)

	total := lenPlain + int(gcmTagSize)
	out := make([]byte, total)

	var tag [gcmTagSize]byte

	binary.BigEndian.PutUint64(tag[:], y.low)
	binary.BigEndian.PutUint64(tag[8:], y.high)
	xorWords(tag[:], tag[:], tagMask[:])

	// copy plaintext cipher first 16b
	copy(out[:lenPlain], cipher1)
	// copy auth tag into end 16b
	copy(out[lenPlain:], tag[:])

	return hex.EncodeToString(out)
}

func AuthTag13(tagMaskCipher string, plaintextCipher string, galoisKexCipher string, additional string) string {

	// decoding
	tagMask, _ := hex.DecodeString(tagMaskCipher)
	cipher1, _ := hex.DecodeString(plaintextCipher)
	galoisKey, _ := hex.DecodeString(galoisKexCipher)
	additionalData, _ := hex.DecodeString(additional)

	lenPlain := len(cipher1)
	lenAdditionalData := len(additionalData)

	// init gcm struct
	g := &gcm{}

	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	x := gcmFieldElement{
		binary.BigEndian.Uint64(galoisKey[:8]),
		binary.BigEndian.Uint64(galoisKey[8:]),
	}
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}

	// auth function logic
	var y gcmFieldElement
	// ad := []byte{}
	ad := additionalData
	g.update(&y, ad)
	g.update(&y, cipher1)

	y.low ^= uint64(lenAdditionalData) * 8
	y.high ^= uint64(lenPlain) * 8

	g.mul(&y)

	total := lenPlain + int(gcmTagSize)
	out := make([]byte, total)

	var tag [gcmTagSize]byte

	binary.BigEndian.PutUint64(tag[:], y.low)
	binary.BigEndian.PutUint64(tag[8:], y.high)
	xorWords(tag[:], tag[:], tagMask[:])

	// copy plaintext cipher first 16b
	copy(out[:lenPlain], cipher1)
	// copy auth tag into end 16b
	copy(out[lenPlain:], tag[:])

	return hex.EncodeToString(out)
}

func ReadRecordTagPI(filepath string) (map[string]map[string]string, error) {

	// open file
	file, err := os.Open(filepath)
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return nil, err
	}
	defer file.Close()

	// read in data
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.ReadAll(file)")
		return nil, err
	}

	// parse json
	var objmap map[string]map[string]string
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return nil, err
	}

	return objmap, nil
}
