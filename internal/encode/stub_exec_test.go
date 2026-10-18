//go:build linux && amd64

package encode

import (
	"bytes"
	"sync"
	"testing"

	"pobf/internal/rng"
	"pobf/internal/x86/native"
)

// The stubs this package attaches are only worth the bytes they occupy if they
// actually decode. These tests map each produced image into executable memory,
// jump to the container's declared entry point, and compare the bytes left in
// memory against the original payload — with no Go code in the decode path.

var headroomOnce sync.Once

// ensureHeadroom grows the goroutine stack before generated code that pushes
// below RSP is executed. See internal/x86/native.GrowStack.
func ensureHeadroom() { headroomOnce.Do(native.GrowStack) }

// runImageEntry maps the image and calls its declared entry point with no
// arguments.
func runImageEntry(t *testing.T, img []byte, entry int) *native.Region {
	t.Helper()
	ensureHeadroom()
	reg, err := native.NewRegion(img)
	if err != nil {
		t.Fatalf("map executable memory: %v", err)
	}
	native.Call4(uintptr(reg.Base())+uintptr(entry), 0, 0, 0, 0)
	return reg
}

func TestXORStubReallyDecodes(t *testing.T) {
	src := []byte("the stub must decode this without any help from Go")
	for _, chain := range []bool{false, true} {
		for seed := int64(1); seed <= 4; seed++ {
			opts := XOROptions{KeyLen: 16, Chain: chain}
			img, _, err := BuildXORImage(src, rng.Derive(seed, "xor-exec"), opts)
			if err != nil {
				t.Fatalf("chain %t seed %d: %v", chain, seed, err)
			}
			c := img.Container
			reg := runImageEntry(t, img.Bytes, c.EntryOffset)
			got := append([]byte(nil), reg.Bytes()[c.DataOffset:c.DataOffset+c.PlainLen]...)
			_ = reg.Free()
			if !bytes.Equal(got, src) {
				t.Fatalf("chain %t seed %d: stub produced %q, want %q", chain, seed, got, src)
			}
		}
	}
}

func TestBase64StubReallyDecodes(t *testing.T) {
	src := []byte("a custom alphabet plus a machine-code decoder")
	for seed := int64(1); seed <= 4; seed++ {
		img, _, err := BuildBase64Image(src, rng.Derive(seed, "b64-exec"), DefaultBase64Options())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		c := img.Container
		reg := runImageEntry(t, img.Bytes, c.EntryOffset)
		got := append([]byte(nil), reg.Bytes()[c.DataOffset:c.DataOffset+c.PlainLen]...)
		_ = reg.Free()
		if !bytes.Equal(got, src) {
			t.Fatalf("seed %d: stub produced % x\n  want             % x", seed, got, src)
		}
	}
}

func TestBase64StubDecodesEveryLengthModulo3(t *testing.T) {
	// The final group is padded, so each residue class has to be checked: a
	// decoder that gets the padding wrong still works for len%3==0.
	for n := 1; n <= 24; n++ {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(0x30 + i)
		}
		img, _, err := BuildBase64Image(src, rng.Derive(int64(n), "b64-len"), DefaultBase64Options())
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		c := img.Container
		reg := runImageEntry(t, img.Bytes, c.EntryOffset)
		got := append([]byte(nil), reg.Bytes()[c.DataOffset:c.DataOffset+c.PlainLen]...)
		_ = reg.Free()
		if !bytes.Equal(got, src) {
			t.Fatalf("len %d: stub produced % x, want % x", n, got, src)
		}
	}
}

// TestStringStubRebuildsAndRuns is the end-to-end string-stage test: the stub
// restores the masked literals and then hands control to the payload, which
// executes and returns the value the payload's own code computes. If either the
// rebuild or the hand-off were wrong, the call would either read the wrong
// literal or not return at all.
func TestStringStubRebuildsAndRuns(t *testing.T) {
	// mov eax, 42 ; ret  followed by an ASCII literal the code never reads.
	code := []byte{0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3}
	literal := []byte("VirtualAlloc CreateRemoteThread")
	payload := append(append([]byte(nil), code...), literal...)

	img, info, err := BuildStringImage(payload, rng.Derive(1, "strings-exec"), DefaultStringOptions())
	if err != nil {
		t.Fatal(err)
	}
	if info.MaskedBytes < len(literal) {
		t.Fatalf("expected the literal to be masked, masked only %d bytes", info.MaskedBytes)
	}
	if bytes.Contains(img.Bytes, literal) {
		t.Fatal("the literal is still present verbatim in the image")
	}

	c := img.Container
	ensureHeadroom()
	reg, err := native.NewRegion(img.Bytes)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	ret := native.Call5(uintptr(reg.Base())+uintptr(c.EntryOffset), 0, 0, 0, 0)
	rebuilt := append([]byte(nil), reg.Bytes()[c.DataOffset:c.DataOffset+c.PlainLen]...)
	_ = reg.Free()

	if ret != 42 {
		t.Fatalf("payload returned %d, want 42 (the stub did not hand off correctly)", ret)
	}
	if !bytes.Equal(rebuilt, payload) {
		t.Fatalf("stub rebuilt %q,\n  want      %q", rebuilt, payload)
	}
}

// TestAESDescriptorIsNotExecutable documents, as a test, the one honest gap in
// the stub chain: the AES stage ships a parameter block rather than machine
// code, so it must say so.
func TestAESDescriptorIsNotExecutable(t *testing.T) {
	img, _, err := BuildAESImage([]byte("payload"), rng.Derive(1, "aes-exec"), AESOptions{Iterations: 500}, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if img.Kind != StubDescriptor {
		t.Fatalf("AES stub kind is %q, want %q", img.Kind, StubDescriptor)
	}
	if img.Container.EntryOffset != 0 {
		t.Fatalf("descriptor stub declares executable entry offset %d", img.Container.EntryOffset)
	}
	if len(img.Notes) == 0 {
		t.Fatal("expected the descriptor caveat to be reported")
	}
}
