package encode

import (
	"fmt"
	"math/rand/v2"

	"pobf/internal/x86"
)

// Base64Info describes a Base64 encoding run.
type Base64Info struct {
	Alphabet    string `json:"alphabet"`
	Pad         string `json:"pad"`
	Groups      int    `json:"groups"`
	PaddedBytes int    `json:"padded_bytes"`
	JumpToTail  bool   `json:"jump_into_payload"`
}

// Base64Options controls the Base64 stage.
type Base64Options struct {
	// CustomAlphabet shuffles the symbol set per run. Turning it off produces
	// canonical RFC 4648 output, which is useful for the differential test
	// against encoding/base64.
	CustomAlphabet bool
	// JumpIntoPayload makes the stub transfer control to the decoded payload
	// rather than returning.
	JumpIntoPayload bool
}

// DefaultBase64Options returns the tuned defaults.
func DefaultBase64Options() Base64Options {
	return Base64Options{CustomAlphabet: true, JumpIntoPayload: false}
}

// BuildBase64Image encodes src and attaches the in-place decoder stub.
func BuildBase64Image(src []byte, r *rand.Rand, opts Base64Options) (*Image, *Base64Info, error) {
	var alpha Alphabet
	if opts.CustomAlphabet {
		alpha = RandomAlphabet(r)
	} else {
		alpha = StandardAlphabet()
	}
	text := alpha.EncodeBase64(src)
	groups := len(text) / 4
	if groups == 0 {
		return nil, nil, fmt.Errorf("encode: empty payload has no Base64 groups")
	}
	inv := alpha.Inverse()
	plan := x86.Base64DecodeStub(inv, groups, opts.JumpIntoPayload)

	// The alphabet is the parameter block: a loader (or Decode) needs it to
	// rebuild the symbol table, and it is exactly 65 bytes every time.
	params := append([]byte(nil), alpha.Symbols[:]...)
	params = append(params, alpha.Pad)

	img, err := BuildImage(AlgoBase64, 0, params, plan.Code, text, len(src), StubMachineCode)
	if err != nil {
		return nil, nil, err
	}
	info := &Base64Info{
		Alphabet:    string(alpha.Symbols[:]),
		Pad:         fmt.Sprintf("%#x", alpha.Pad),
		Groups:      groups,
		PaddedBytes: groups*4 - len(src),
		JumpToTail:  opts.JumpIntoPayload,
	}
	img.Notes = append(img.Notes, fmt.Sprintf(
		"Base64 decoder stub is %d bytes of executable x86-64 (in-place, %d groups over a shuffled alphabet)",
		len(plan.Code), groups))
	return img, info, nil
}

// DecodeBase64Image reverses BuildBase64Image using only the image bytes.
func DecodeBase64Image(img []byte) ([]byte, error) {
	c, err := ParseContainer(img)
	if err != nil {
		return nil, err
	}
	if c.Algorithm != AlgoBase64 {
		return nil, fmt.Errorf("encode: image holds algorithm %d, not Base64", c.Algorithm)
	}
	if len(c.Params) != 65 {
		return nil, fmt.Errorf("encode: Base64 image has a %d-byte alphabet, want 65", len(c.Params))
	}
	var alpha Alphabet
	copy(alpha.Symbols[:], c.Params[:64])
	alpha.Pad = c.Params[64]
	if err := alpha.Validate(); err != nil {
		return nil, err
	}
	return alpha.DecodeBase64(c.Data(img), c.PlainLen)
}
