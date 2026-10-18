package encode

import (
	"fmt"
	"math/rand/v2"

	"pobf/internal/x86"
)

// XORInfo describes an XOR encoding run.
type XORInfo struct {
	KeyLen   int    `json:"key_len"`
	Chained  bool   `json:"chained"`
	SelfTerm bool   `json:"jump_into_payload"`
	Key      []byte `json:"-"`
}

// xorEncode applies the XOR transform.
//
//	plain keystream   C[i] = P[i] ^ K[i mod k]
//	chained keystream C[i] = P[i] ^ K[i mod k] ^ C[i-1]      (C[-1] = 0)
//
// The chained form is worth having because the effective key for byte i then
// depends on all preceding bytes: recovering one key byte from a crib does not
// peel the rest.
func xorEncode(src, key []byte, chain bool) []byte {
	out := make([]byte, len(src))
	if len(key) == 0 {
		copy(out, src)
		return out
	}
	if !chain {
		for i := range src {
			out[i] = src[i] ^ key[i%len(key)]
		}
		return out
	}
	prev := byte(0)
	for i := range src {
		out[i] = src[i] ^ key[i%len(key)] ^ prev
		prev = out[i]
	}
	return out
}

// xorDecode reverses xorEncode.
//
// The chained form is *not* an involution — the encoder's recurrence feeds on
// its own output — so decoding is a distinct forward pass that recomputes the
// previous ciphertext byte as it goes. This is exactly the loop the emitted
// machine-code stub runs, which is why the two are written to match line for
// line.
func xorDecode(cipher, key []byte, chain bool) []byte {
	out := make([]byte, len(cipher))
	if len(key) == 0 {
		copy(out, cipher)
		return out
	}
	if !chain {
		for i := range cipher {
			out[i] = cipher[i] ^ key[i%len(key)]
		}
		return out
	}
	prev := byte(0)
	for i := range cipher {
		cur := cipher[i]
		out[i] = cur ^ key[i%len(key)] ^ prev
		prev = cur
	}
	return out
}

// XOROptions controls the XOR stage.
type XOROptions struct {
	// KeyLen is the keystream length in bytes.
	KeyLen int
	// Chain enables the self-referential keystream.
	Chain bool
	// JumpIntoPayload makes the emitted stub transfer control to the first
	// decoded byte instead of returning, which is the production form.
	JumpIntoPayload bool
}

// DefaultXOROptions returns the tuned defaults.
func DefaultXOROptions() XOROptions {
	return XOROptions{KeyLen: 32, Chain: true, JumpIntoPayload: false}
}

// BuildXORImage produces a complete XOR-encoded image with a working x86-64
// decoder stub attached.
func BuildXORImage(src []byte, r *rand.Rand, opts XOROptions) (*Image, *XORInfo, error) {
	if opts.KeyLen <= 0 {
		opts.KeyLen = 32
	}
	key := make([]byte, opts.KeyLen)
	for i := range key {
		key[i] = byte(r.UintN(256))
	}
	cur := xorEncode(src, key, opts.Chain)

	// Parameters carry the key so the container is self-describing and Decode
	// needs nothing but the image bytes. The stub reads those same bytes
	// RIP-relatively rather than carrying a duplicate copy, so the image holds
	// the key exactly once.
	params := append([]byte(nil), key...)
	stub := x86.XORSelfDecodeMultiKeyStub(len(key), len(cur), opts.Chain, opts.JumpIntoPayload)

	var flags uint8
	if opts.Chain {
		flags |= 1
	}
	img, err := BuildImage(AlgoXOR, flags, params, stub, cur, len(src), StubMachineCode)
	if err != nil {
		return nil, nil, err
	}
	info := &XORInfo{
		KeyLen:   opts.KeyLen,
		Chained:  opts.Chain,
		SelfTerm: opts.JumpIntoPayload,
		Key:      key,
	}
	img.Notes = append(img.Notes, fmt.Sprintf(
		"XOR decoder stub is %d bytes of executable x86-64 (repeating key of %d, chained=%t)",
		len(stub), opts.KeyLen, opts.Chain))
	return img, info, nil
}

// DecodeXORImage reverses BuildXORImage using only the image bytes.
func DecodeXORImage(img []byte) ([]byte, error) {
	c, err := ParseContainer(img)
	if err != nil {
		return nil, err
	}
	if c.Algorithm != AlgoXOR {
		return nil, fmt.Errorf("encode: image holds algorithm %d, not XOR", c.Algorithm)
	}
	key := c.Params
	if len(key) == 0 {
		return nil, fmt.Errorf("encode: XOR image has an empty key")
	}
	cur := xorDecode(c.Data(img), key, c.Flags&1 != 0)
	if c.PlainLen > len(cur) {
		return nil, fmt.Errorf("encode: XOR image claims %d plaintext bytes but only %d were recovered", c.PlainLen, len(cur))
	}
	return cur[:c.PlainLen], nil
}
