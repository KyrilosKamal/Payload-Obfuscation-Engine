package encode

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strings"

	"pobf/internal/x86"
)

// StringRecordSize is the size of one mask-table entry.
const StringRecordSize = 9

// StringMask describes one masked literal run.
type StringMask struct {
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Key    byte   `json:"-"`
	Text   string `json:"text"`
}

// StringInfo describes a string-obfuscation run.
type StringInfo struct {
	Runs          []StringMask `json:"runs"`
	MaskedBytes   int          `json:"masked_bytes"`
	TotalLiterals int          `json:"total_literals"`
	MinLength     int          `json:"min_length"`
}

// StringOptions controls literal masking.
type StringOptions struct {
	// MinLength is the shortest printable run treated as a literal.
	MinLength int
	// MaxRuns caps how many runs are masked (0 = unlimited).
	MaxRuns int
	// JumpIntoPayload makes the rebuild stub hand control to the payload when it
	// finishes, which is the production form.
	JumpIntoPayload bool
}

// DefaultStringOptions returns the tuned defaults.
func DefaultStringOptions() StringOptions {
	return StringOptions{MinLength: 6, JumpIntoPayload: false}
}

func isPrintable(b byte) bool { return b >= 0x20 && b < 0x7F }

// findLiterals returns the printable runs at least min bytes long.
func findLiterals(b []byte, min int) [][2]int {
	var runs [][2]int
	for i := 0; i < len(b); {
		if !isPrintable(b[i]) {
			i++
			continue
		}
		j := i
		for j < len(b) && isPrintable(b[j]) {
			j++
		}
		if j-i >= min {
			runs = append(runs, [2]int{i, j - i})
		}
		i = j
	}
	return runs
}

// BuildStringImage masks printable runs in src and attaches an executable
// rebuild stub.
//
// The masked bytes stay in place, so the payload's length and internal layout
// (every relative displacement) are unchanged; only the literal bytes differ.
// The payload becomes un-runnable until the stub has run, which is the point:
// nothing in it spells an API name any more.
//
// The image layout is [header][mask table][stub][payload]: the stub locates both
// the table and the payload with RIP-relative LEAs fixed at assembly time, and
// the payload keeps the length and layout it had, so nothing inside it shifts.
func BuildStringImage(src []byte, r *rand.Rand, opts StringOptions) (*Image, *StringInfo, error) {
	if opts.MinLength <= 0 {
		opts.MinLength = 6
	}
	masked := append([]byte(nil), src...)
	runs := findLiterals(masked, opts.MinLength)
	info := &StringInfo{MinLength: opts.MinLength, TotalLiterals: len(runs)}
	if len(runs) == 0 {
		return nil, info, fmt.Errorf("encode: payload has no printable run of %d or more bytes to mask", opts.MinLength)
	}
	if opts.MaxRuns > 0 && len(runs) > opts.MaxRuns {
		runs = runs[:opts.MaxRuns]
	}

	table := make([]byte, 0, len(runs)*StringRecordSize)
	for _, run := range runs {
		off, length := run[0], run[1]
		key := byte(r.UintN(255) + 1) // never zero: a zero key masks nothing
		for i := 0; i < length; i++ {
			masked[off+i] ^= key
		}
		var rec [StringRecordSize]byte
		binary.LittleEndian.PutUint32(rec[0:], uint32(off))
		binary.LittleEndian.PutUint32(rec[4:], uint32(length))
		rec[8] = key
		table = append(table, rec[:]...)
		info.Runs = append(info.Runs, StringMask{
			Offset: off, Length: length, Key: key,
			Text: string(src[off : off+length]),
		})
		info.MaskedBytes += length
	}

	stub := x86.StringRedecodeStub(len(table), len(runs))
	img, err := BuildImage(AlgoStrings, 0, table, stub, masked, len(src), StubMachineCode)
	if err != nil {
		return nil, nil, err
	}
	if img.Container.DataOffset != len(img.Bytes)-len(masked) {
		return nil, nil, fmt.Errorf("encode: internal layout error, payload offset mismatch")
	}
	img.Notes = append(img.Notes, fmt.Sprintf(
		"literal rebuild stub is %d bytes of executable x86-64 covering %d masked run(s), %d bytes",
		len(stub), len(info.Runs), info.MaskedBytes))
	return img, info, nil
}

// DecodeStringImage reverses BuildStringImage from the image bytes alone: the
// mask table is embedded, so no key material is needed.
func DecodeStringImage(img []byte) ([]byte, error) {
	c, err := ParseContainer(img)
	if err != nil {
		return nil, err
	}
	if c.Algorithm != AlgoStrings {
		return nil, fmt.Errorf("encode: image holds algorithm %d, not string masking", c.Algorithm)
	}
	if len(c.Params)%StringRecordSize != 0 {
		return nil, fmt.Errorf("encode: string mask table length %d is not a multiple of %d", len(c.Params), StringRecordSize)
	}
	out := append([]byte(nil), c.Data(img)...)
	for off := 0; off+StringRecordSize <= len(c.Params); off += StringRecordSize {
		rec := c.Params[off:]
		start := int(binary.LittleEndian.Uint32(rec[0:]))
		length := int(binary.LittleEndian.Uint32(rec[4:]))
		key := rec[8]
		if start < 0 || length < 0 || start+length > len(out) {
			return nil, fmt.Errorf("encode: mask record %d covers [%d,%d), outside the %d-byte payload",
				off/StringRecordSize, start, start+length, len(out))
		}
		for i := 0; i < length; i++ {
			out[start+i] ^= key
		}
	}
	if c.PlainLen != len(out) {
		return nil, fmt.Errorf("encode: string image claims %d plaintext bytes, recovered %d", c.PlainLen, len(out))
	}
	return out, nil
}

// Literals returns the printable runs a payload contains, for reporting.
func Literals(b []byte, min int) []string {
	var out []string
	for _, run := range findLiterals(b, min) {
		out = append(out, string(b[run[0]:run[0]+run[1]]))
	}
	return out
}

// SummariseLiterals renders a bounded, comma-separated preview of the literals a
// payload exposes, which is what a signature author would underline.
func SummariseLiterals(b []byte, min, max int) string {
	all := Literals(b, min)
	if len(all) == 0 {
		return "(none)"
	}
	if max > 0 && len(all) > max {
		all = append(all[:max], fmt.Sprintf("... +%d more", len(all)-max))
	}
	for i, s := range all {
		if len(s) > 48 {
			all[i] = s[:45] + "..."
		}
	}
	return strings.Join(all, ", ")
}
