package encode

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderSize is the size of the fixed container header that prefixes every
// encoded image.
const HeaderSize = 24

// Magic identifies a payload produced by this engine.
var Magic = [4]byte{'P', 'O', 'B', 'F'}

// Algorithm identifiers stored in the container header.
const (
	AlgoXOR     uint8 = 1
	AlgoAES     uint8 = 2
	AlgoBase64  uint8 = 3
	AlgoStrings uint8 = 4
)

// StubKind says how the decoder for a stage is delivered. It is reported
// verbatim in the analysis output so nobody has to guess whether a stage
// produced executable bytes or a parameter block.
type StubKind string

const (
	// StubMachineCode means the image starts with real x86-64 that performs the
	// decode when executed.
	StubMachineCode StubKind = "machine-code"
	// StubDescriptor means the decoder is described by the parameter block and
	// must be performed by a loader (or by this package's Decode), because the
	// transform cannot be expressed in a few hundred bytes of hand-written
	// machine code.
	StubDescriptor StubKind = "loader-descriptor"
)

// Container is a parsed image header.
type Container struct {
	Version   uint8
	Algorithm uint8
	Flags     uint8
	// EntryOffset is the offset of the decoder's first byte. Zero means the
	// decoder is not executable (a descriptor stub).
	EntryOffset int
	// DataOffset is the offset of the encoded payload.
	DataOffset int
	// PayloadLen is the number of bytes at DataOffset.
	PayloadLen int
	// PlainLen is the number of bytes the decoder produces.
	PlainLen int
	Params   []byte
}

// Image is a built encoder output.
type Image struct {
	// Bytes is the complete image: header, parameters, stub, payload.
	Bytes []byte
	// Container is the parsed view of Bytes.
	Container Container
	// Kind records whether the stub is executable.
	Kind StubKind
	// Notes carries human-readable caveats for the report.
	Notes []string
}

// BuildImage assembles [header][params][stub][payload].
//
// The payload is placed immediately after the stub because the machine-code
// decoders locate it with a RIP-relative LEA resolved against the stub's end;
// keeping the layout fixed means the displacement can be computed once, at
// assembly time, instead of being patched at runtime.
func BuildImage(algo, flags uint8, params, stub, payload []byte, plainLen int, kind StubKind) (*Image, error) {
	if len(stub) == 0 && kind == StubMachineCode {
		return nil, errors.New("encode: machine-code stub required but empty")
	}
	entry := 0
	if kind == StubMachineCode {
		entry = HeaderSize + len(params)
	}
	dataOff := HeaderSize + len(params) + len(stub)

	hdr := make([]byte, HeaderSize)
	copy(hdr[0:4], Magic[:])
	hdr[4] = 1 // version
	hdr[5] = algo
	hdr[6] = flags
	hdr[7] = 0
	binary.LittleEndian.PutUint32(hdr[8:], uint32(entry))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(dataOff))
	binary.LittleEndian.PutUint32(hdr[16:], uint32(plainLen))
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(params)))

	img := make([]byte, 0, dataOff+len(payload))
	img = append(img, hdr...)
	img = append(img, params...)
	img = append(img, stub...)
	img = append(img, payload...)

	c := Container{
		Version: 1, Algorithm: algo, Flags: flags,
		EntryOffset: entry, DataOffset: dataOff, PayloadLen: len(payload),
		PlainLen: plainLen, Params: append([]byte(nil), params...),
	}
	return &Image{Bytes: img, Container: c, Kind: kind}, nil
}

// ErrNoContainer reports that a buffer is not an encoded image.
var ErrNoContainer = errors.New("encode: buffer has no POBF container header")

// ParseContainer reads the header at the start of b.
func ParseContainer(b []byte) (*Container, error) {
	if len(b) < HeaderSize {
		return nil, ErrNoContainer
	}
	for i := 0; i < 4; i++ {
		if b[i] != Magic[i] {
			return nil, ErrNoContainer
		}
	}
	c := &Container{
		Version:     b[4],
		Algorithm:   b[5],
		Flags:       b[6],
		EntryOffset: int(binary.LittleEndian.Uint32(b[8:])),
		DataOffset:  int(binary.LittleEndian.Uint32(b[12:])),
		PlainLen:    int(binary.LittleEndian.Uint32(b[16:])),
	}
	paramLen := int(binary.LittleEndian.Uint32(b[20:]))
	if c.Version != 1 {
		return nil, fmt.Errorf("encode: unsupported container version %d", c.Version)
	}
	if HeaderSize+paramLen > len(b) {
		return nil, fmt.Errorf("encode: parameter block of %d bytes runs past the end of the buffer", paramLen)
	}
	c.Params = append([]byte(nil), b[HeaderSize:HeaderSize+paramLen]...)
	if c.DataOffset < HeaderSize+paramLen || c.DataOffset > len(b) {
		return nil, fmt.Errorf("encode: data offset %d is outside the buffer", c.DataOffset)
	}
	c.PayloadLen = len(b) - c.DataOffset
	if c.EntryOffset != 0 && (c.EntryOffset < HeaderSize+paramLen || c.EntryOffset >= c.DataOffset) {
		return nil, fmt.Errorf("encode: entry offset %d does not point into the stub region", c.EntryOffset)
	}
	return c, nil
}

// Data returns the encoded payload of an image.
func (c *Container) Data(b []byte) []byte { return b[c.DataOffset:] }

// Stub returns the decoder stub region of an image.
func (c *Container) Stub(b []byte) []byte { return b[c.EntryOffset:c.DataOffset] }

// IsEncodedImage reports whether b looks like the output of an encoding stage.
// The analysis layer uses it to decide whether to offer the engine-side decode.
func IsEncodedImage(b []byte) bool {
	_, err := ParseContainer(b)
	return err == nil
}
