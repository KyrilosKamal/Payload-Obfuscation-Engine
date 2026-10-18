// Package encode implements the payload-encoding stages: a custom-alphabet
// Base64 codec, a keystream XOR cipher, AES-256-CBC under a PBKDF2-derived key,
// and in-place string masking.
//
// Two ideas tie the package together.
//
// First, an encoded payload is always shipped as a self-describing image:
//
//	[ 24-byte container header ][ algorithm parameters ][ decoder stub ][ payload ]
//
// The header (see container.go) records where the decoder entry point is, where
// the payload starts, and how long the decoded payload should be. That makes the
// output of every stage mechanically inspectable and lets a loader — or this
// package's own Decode — work from the bytes alone, with no side channel.
//
// Second, the decoder is *attached*, not assumed. For Base64 and XOR the decoder
// is real x86-64 machine code that the test suite maps into executable memory
// and runs; for AES it is a parameter block, because a hand-written AES-256
// decryption stub is out of scope and pretending otherwise would be dishonest.
// The distinction is explicit on every stage's Descriptor rather than buried in
// a comment.
package encode

import (
	"fmt"
	"math/rand/v2"
)

// Alphabet is a Base64 alphabet: 64 distinct byte values in encode order, plus a
// padding byte that is guaranteed not to appear in the alphabet.
//
// A per-run shuffled alphabet is what makes the encoding more than obfuscation
// theatre: every rule that looks for a canonical Base64 alphabet, or for the
// `=` padding run that canonical Base64 produces, fails against it.
type Alphabet struct {
	// Symbols maps an index 0..63 to the byte that represents it.
	Symbols [64]byte
	// Pad is the byte used to fill the final partial group.
	Pad byte
	// inverse maps a symbol byte to its index. Computed by Inverse.
	inverse [256]byte
	hasInv  bool
}

// StandardAlphabet is the RFC 4648 alphabet. It exists so the codec can be
// differentially tested against encoding/base64.
func StandardAlphabet() Alphabet {
	var a Alphabet
	copy(a.Symbols[:], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	a.Pad = '='
	a.hasInv = false
	return a
}

// RandomAlphabet returns a shuffled alphabet with a padding byte drawn from
// outside the alphabet.
//
// Restricting the pad byte to bytes the alphabet does not use means the decoder
// can find the padding without a second table, and it means a rule keyed on a
// specific pad character has to know this run's alphabet to match.
func RandomAlphabet(r *rand.Rand) Alphabet {
	var a Alphabet
	perm := r.Perm(256)
	for i := 0; i < 64; i++ {
		a.Symbols[i] = byte(perm[i])
	}
	a.Pad = byte(perm[64])
	return a
}

// Inverse returns the 256-byte symbol -> index table. Bytes that are not
// symbols map to 0; callers that care must range-check the input.
func (a *Alphabet) Inverse() *[256]byte {
	if !a.hasInv {
		for i := range a.inverse {
			a.inverse[i] = 0xFF
		}
		for i, s := range a.Symbols {
			a.inverse[s] = byte(i)
		}
		a.hasInv = true
	}
	return &a.inverse
}

// Validate reports whether the alphabet is usable.
func (a *Alphabet) Validate() error {
	seen := [256]bool{}
	for i, s := range a.Symbols {
		if seen[s] {
			return fmt.Errorf("encode: alphabet symbol %d (%#x) is duplicated", i, s)
		}
		seen[s] = true
	}
	if seen[a.Pad] {
		return fmt.Errorf("encode: padding byte %#x appears in the alphabet", a.Pad)
	}
	return nil
}

// IndexOf returns the symbol index for a byte.
func (a *Alphabet) IndexOf(b byte) (int, bool) {
	v := a.Inverse()[b]
	if v == 0xFF {
		return 0, false
	}
	return int(v), true
}

// EncodeBase64 encodes src with the alphabet, padding the final group.
//
// The output length is always a multiple of four, which is what lets the
// machine-code decoder in stub_base64.go walk the payload four bytes at a time
// without a remainder case.
func (a *Alphabet) EncodeBase64(src []byte) []byte {
	groups := (len(src) + 2) / 3
	out := make([]byte, 0, groups*4)
	for i := 0; i < len(src); i += 3 {
		var b0, b1, b2 byte
		var have1, have2 bool
		b0 = src[i]
		if i+1 < len(src) {
			b1, have1 = src[i+1], true
		}
		if i+2 < len(src) {
			b2, have2 = src[i+2], true
		}
		out = append(out, a.Symbols[b0>>2])
		out = append(out, a.Symbols[(b0&0x03)<<4|b1>>4])
		if have1 {
			out = append(out, a.Symbols[(b1&0x0F)<<2|b2>>6])
		} else {
			out = append(out, a.Pad)
		}
		if have2 {
			out = append(out, a.Symbols[b2&0x3F])
		} else {
			out = append(out, a.Pad)
		}
	}
	return out
}

// DecodeBase64 decodes src and truncates the result to plainLen.
//
// src must be a multiple of four bytes long; the payload length is carried in
// the container header rather than inferred, so a truncated or padded tail is
// unambiguous.
func (a *Alphabet) DecodeBase64(src []byte, plainLen int) ([]byte, error) {
	if len(src)%4 != 0 {
		return nil, fmt.Errorf("encode: base64 input length %d is not a multiple of 4", len(src))
	}
	out := make([]byte, 0, len(src)/4*3)
	for i := 0; i < len(src); i += 4 {
		var v [4]int
		for j := 0; j < 4; j++ {
			c := src[i+j]
			if c == a.Pad {
				v[j] = 0
				continue
			}
			idx, ok := a.IndexOf(c)
			if !ok {
				return nil, fmt.Errorf("encode: byte %#x at offset %d is not in the alphabet", c, i+j)
			}
			v[j] = idx
		}
		x := uint32(v[0])<<18 | uint32(v[1])<<12 | uint32(v[2])<<6 | uint32(v[3])
		out = append(out, byte(x>>16), byte(x>>8), byte(x))
	}
	if plainLen > len(out) {
		return nil, fmt.Errorf("encode: decoded %d bytes, container claims %d", len(out), plainLen)
	}
	return out[:plainLen], nil
}
