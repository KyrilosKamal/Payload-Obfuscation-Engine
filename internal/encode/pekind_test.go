package encode

import (
	"bytes"
	"encoding/binary"
	"testing"

	"pobf/internal/testpe"
)

// TestIsPE pins the shape test and, more importantly, the near misses. A false
// positive here would make the report claim a container requirement that does
// not apply; a false negative would let a PE through silently.
func TestIsPE(t *testing.T) {
	pe := testpe.Build(true)
	if !IsPE(pe) {
		t.Fatal("a PE built by testpe must be recognised")
	}

	// 0x40 bytes of "MZ" followed by a chosen e_lfanew and trailing bytes.
	withLfanew := func(at uint32, tail string) []byte {
		b := make([]byte, 0x40+len(tail))
		b[0], b[1] = 'M', 'Z'
		binary.LittleEndian.PutUint32(b[0x3c:], at)
		copy(b[0x40:], tail)
		return b
	}

	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"nil", nil, false},
		{"empty", []byte{}, false},
		{"too short for MZ", []byte{'M', 'Z'}, false},
		{"wrong magic", append([]byte{'M', 'X'}, pe[2:]...), false},
		{"lfanew past the end", withLfanew(0x1000, "PE\x00\x00"), false},
		{"lfanew at the very end", withLfanew(0x40, ""), false},
		{"lfanew points at data", withLfanew(0x40, "NOPE"), false},
		{"valid minimal shape", withLfanew(0x40, "PE\x00\x00"), true},
		{"real PE", pe, true},
	}
	for _, tc := range cases {
		if got := IsPE(tc.b); got != tc.want {
			t.Errorf("IsPE(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestClassifyInputNamesAPE checks that a PE input is labelled and, crucially,
// that the label carries the explanation with it: a PE in means a container out.
func TestClassifyInputNamesAPE(t *testing.T) {
	kind, note := ClassifyInput(testpe.Build(true))
	if kind != InputPE {
		t.Errorf("kind = %q, want %q", kind, InputPE)
	}
	if note == "" {
		t.Fatal("a PE input must come with an explanation of what the artefact is")
	}
	if note != PEContainerNote {
		t.Errorf("note must be the shared wording so the stage detail and the report cannot drift:\n got %q\nwant %q", note, PEContainerNote)
	}

	kind, note = ClassifyInput([]byte{0x90, 0x90, 0xC3})
	if kind != InputRaw || note != "" {
		t.Errorf("a raw payload must stay unlabelled, got kind=%q note=%q", kind, note)
	}
}

// TestStagesRoundTripAPE is the claim that makes a PE a legitimate input: every
// encoding stage hands back the exact original file. It is the difference
// between "obfuscated" and "destroyed".
func TestStagesRoundTripAPE(t *testing.T) {
	pe := testpe.Build(true)

	t.Run("xor", func(t *testing.T) {
		img, _, err := BuildXORImage(pe, testRand(7, "pe/xor"), DefaultXOROptions())
		if err != nil {
			t.Fatalf("BuildXORImage: %v", err)
		}
		got, err := DecodeXORImage(img.Bytes)
		if err != nil {
			t.Fatalf("DecodeXORImage: %v", err)
		}
		if !bytes.Equal(got, pe) {
			t.Errorf("xor round trip is not byte-exact: %d bytes back, %d in", len(got), len(pe))
		}
	})

	t.Run("base64", func(t *testing.T) {
		img, _, err := BuildBase64Image(pe, testRand(7, "pe/b64"), DefaultBase64Options())
		if err != nil {
			t.Fatalf("BuildBase64Image: %v", err)
		}
		got, err := DecodeBase64Image(img.Bytes)
		if err != nil {
			t.Fatalf("DecodeBase64Image: %v", err)
		}
		if !bytes.Equal(got, pe) {
			t.Errorf("base64 round trip is not byte-exact: %d bytes back, %d in", len(got), len(pe))
		}
	})

	t.Run("strings", func(t *testing.T) {
		// The interesting one: strings rewrites payload bytes in place, so the
		// only thing that makes it safe on a PE is that the masked runs are
		// recoverable exactly.
		img, info, err := BuildStringImage(pe, testRand(7, "pe/strings"), DefaultStringOptions())
		if err != nil {
			t.Fatalf("BuildStringImage: %v", err)
		}
		if len(info.Runs) == 0 {
			t.Fatal("the dense PE fixture should have literals to mask")
		}
		got, err := DecodeStringImage(img.Bytes)
		if err != nil {
			t.Fatalf("DecodeStringImage: %v", err)
		}
		if !bytes.Equal(got, pe) {
			t.Errorf("strings round trip is not byte-exact: %d bytes back, %d in", len(got), len(pe))
		}
		if bytes.Contains(img.Bytes, []byte("kernel32.dll")) {
			t.Error("an import name the fixture uses is still visible in the artefact")
		}
	})
}
