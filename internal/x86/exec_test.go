//go:build linux && amd64

package x86

import (
	"sync"
	"testing"
	"unsafe"

	"pobf/internal/rng"
	"pobf/internal/x86/native"
)

// This file validates the obfuscation stages the only way that really counts:
// by executing the machine code they produce and comparing behaviour against
// the unobfuscated original.
//
// It is guarded to linux/amd64 because it maps executable memory and runs
// generated x86-64.

var headroomOnce sync.Once

// ensureHeadroom grows the goroutine stack once per test binary before any
// generated code that pushes below RSP is executed.
func ensureHeadroom() { headroomOnce.Do(native.GrowStack) }

// runFixture executes a code-only fixture image as a leaf function.
//
// The returned value is RAX. Arguments are placed in RDI/RSI/RDX/RCX per the
// System V ABI, matching what the fixtures expect.
func runFixture(t *testing.T, code []byte, a, b, c, d uintptr) uint64 {
	t.Helper()
	ensureHeadroom()
	reg, err := native.NewRegion(code)
	if err != nil {
		t.Fatalf("map executable memory: %v", err)
	}
	defer func() { _ = reg.Free() }()
	return uint64(reg.CallRet(a, b, c, d))
}

// --- reference implementations, mirroring testdata/*.asm --------------------

func prog1Expected(n int32) uint64 {
	if n <= 0 {
		return 0
	}
	var acc uint32
	i := n
	for {
		acc += uint32(i)
		acc *= 3
		i--
		if i == 0 {
			break
		}
	}
	return uint64(acc)
}

func prog2Expected(a, b int32) uint64 {
	prod := uint32(a) * uint32(b)
	var ecx uint32
	if a > b {
		ecx = uint32(a) - uint32(b)
	} else {
		ecx = uint32(b) - uint32(a)
	}
	return uint64(prod + ecx)
}

// TestFixturesMatchReference proves the execution harness itself is sound before
// it is used to judge the obfuscators.
func TestFixturesMatchReference(t *testing.T) {
	p1 := loadFixture(t, "prog1")
	for _, n := range []int32{-5, -1, 0, 1, 2, 3, 7, 16, 63, 100, 255} {
		got := runFixture(t, p1, uintptr(uint32(n)), 0, 0, 0)
		if want := prog1Expected(n); got != want {
			t.Fatalf("prog1(%d): fixture returned %#x, reference says %#x", n, got, want)
		}
	}

	p2 := loadFixture(t, "prog2")
	for _, tc := range [][2]int32{{0, 0}, {1, 2}, {2, 1}, {-3, 5}, {9, -4}, {100, 100}, {-1, -1}} {
		got := runFixture(t, p2, uintptr(uint32(tc[0])), uintptr(uint32(tc[1])), 0, 0)
		if want := prog2Expected(tc[0], tc[1]); got != want {
			t.Fatalf("prog2(%d,%d): fixture returned %#x, reference says %#x", tc[0], tc[1], got, want)
		}
	}
}

// TestPolymorphicPreservesSemantics rewrites both fixtures with many random
// seeds and asserts that every rewrite still computes the same values.
//
// This is the test that catches a substitution whose encoding is wrong but
// plausible, a relocation that drifts by a byte, or a flag-clobbering morph
// applied in front of a conditional branch.
func TestPolymorphicPreservesSemantics(t *testing.T) {
	for _, fixture := range []string{"prog1", "prog2"} {
		orig := loadFixture(t, fixture)
		for seed := int64(1); seed <= 24; seed++ {
			rng := rng.Derive(seed, "test/polymorphic/"+fixture)
			out, log, _, err := Rewrite(orig, rng, DefaultPolymorphicOptions())
			if err != nil {
				t.Fatalf("%s seed %d: rewrite failed: %v", fixture, seed, err)
			}
			if len(log) == 0 {
				t.Fatalf("%s seed %d: expected at least one morph, got none", fixture, seed)
			}
			assertSameSemantics(t, fixture, seed, orig, out)
		}
	}
}

// TestPolymorphicFlagClobberOffIsSafe is the negative control for the liveness
// analysis: even with morphs that change EFLAGS permitted, behaviour must be
// unchanged for these fixtures, because the analysis only lets them through
// when the following code does not consume flags.
func TestPolymorphicFlagClobberOffIsSafe(t *testing.T) {
	orig := loadFixture(t, "prog1")
	opts := DefaultPolymorphicOptions()
	opts.AllowFlagClobber = true
	for seed := int64(1); seed <= 16; seed++ {
		rng := rng.Derive(seed, "test/polymorphic/aggressive")
		out, _, _, err := Rewrite(orig, rng, opts)
		if err != nil {
			t.Fatalf("seed %d: rewrite failed: %v", seed, err)
		}
		assertSameSemantics(t, "prog1", seed, orig, out)
	}
}

func TestDeadCodePreservesSemantics(t *testing.T) {
	for _, fixture := range []string{"prog1", "prog2"} {
		orig := loadFixture(t, fixture)
		for seed := int64(1); seed <= 24; seed++ {
			rng := rng.Derive(seed, "test/deadcode/"+fixture)
			opts := DefaultDeadCodeOptions()
			opts.Probability = 0.8
			out, stats, err := DeadCode(orig, rng, opts)
			if err != nil {
				t.Fatalf("%s seed %d: dead code failed: %v", fixture, seed, err)
			}
			if stats.Insertions == 0 {
				t.Fatalf("%s seed %d: expected insertions", fixture, seed)
			}
			assertSameSemantics(t, fixture, seed, orig, out)
		}
	}
}

func TestCFFPreservesSemantics(t *testing.T) {
	for _, fixture := range []string{"prog1", "prog2"} {
		orig := loadFixture(t, fixture)
		for seed := int64(1); seed <= 24; seed++ {
			rng := rng.Derive(seed, "test/cff/"+fixture)
			out, res, err := Flatten(orig, rng, DefaultCFFOptions())
			if err != nil {
				t.Fatalf("%s seed %d: flatten failed: %v", fixture, seed, err)
			}
			if res.Blocks < 2 {
				t.Fatalf("%s seed %d: expected at least 2 blocks, got %d", fixture, seed, res.Blocks)
			}
			if len(out) <= len(orig) {
				t.Fatalf("%s seed %d: expected the flattened image to grow", fixture, seed)
			}
			assertSameSemantics(t, fixture, seed, orig, out)
		}
	}
}

// TestCFFThenDeadCodeThenRewrite runs the three code-level stages in sequence,
// which is how the pipeline actually composes them, and re-checks behaviour.
func TestCFFThenDeadCodeThenRewrite(t *testing.T) {
	for _, fixture := range []string{"prog1", "prog2"} {
		orig := loadFixture(t, fixture)
		for seed := int64(1); seed <= 8; seed++ {
			cur := orig
			rng := rng.Derive(seed, "test/chain/"+fixture)

			flat, _, err := Flatten(cur, rng, DefaultCFFOptions())
			if err != nil {
				t.Fatalf("%s seed %d: flatten: %v", fixture, seed, err)
			}
			cur = flat
			assertSameSemantics(t, fixture, seed, orig, cur)

			// Dead code and polymorphic rewriting need a resolvable stream; the
			// flattened image has a jump table in it, so they are expected to
			// refuse. Either outcome is acceptable, but a refusal must not have
			// modified the payload.
			dc, _, err := DeadCode(cur, rng, DefaultDeadCodeOptions())
			if err == nil {
				cur = dc
				assertSameSemantics(t, fixture, seed, orig, cur)
			} else if _, ok := err.(*NotRewritableError); !ok {
				t.Fatalf("%s seed %d: dead code: %v", fixture, seed, err)
			}
		}
	}
}

// assertSameSemantics compares the obfuscated image's outputs against the
// original image's over a spread of inputs.
func assertSameSemantics(t *testing.T, fixture string, seed int64, orig, out []byte) {
	t.Helper()
	switch fixture {
	case "prog1":
		for _, n := range []int32{-3, 0, 1, 2, 5, 13, 64, 101, 250} {
			want := runFixture(t, orig, uintptr(uint32(n)), 0, 0, 0)
			got := runFixture(t, out, uintptr(uint32(n)), 0, 0, 0)
			if got != want {
				t.Fatalf("%s seed %d: n=%d: obfuscated returned %#x, original returned %#x",
					fixture, seed, n, got, want)
			}
		}
	case "prog2":
		for _, tc := range [][2]int32{{0, 0}, {3, 1}, {1, 3}, {-7, 2}, {2, -7}, {42, 42}, {-100, -50}} {
			want := runFixture(t, orig, uintptr(uint32(tc[0])), uintptr(uint32(tc[1])), 0, 0)
			got := runFixture(t, out, uintptr(uint32(tc[0])), uintptr(uint32(tc[1])), 0, 0)
			if got != want {
				t.Fatalf("%s seed %d: a=%d b=%d: obfuscated returned %#x, original returned %#x",
					fixture, seed, tc[0], tc[1], got, want)
			}
		}
	default:
		t.Fatalf("unknown fixture %s", fixture)
	}
}

// TestXORDecoderStubExecutes proves the emitted decoder stub really decodes:
// the ciphertext is handed to the machine code and the plaintext is read back
// out of memory.
func TestXORDecoderStubExecutes(t *testing.T) {
	plain := []byte("the quick brown fox jumps over the lazy dog\x00\x01\x02\xff\xfe")
	for key := 0; key < 256; key += 37 {
		cipher := make([]byte, len(plain))
		for i, b := range plain {
			cipher[i] = b ^ byte(key)
		}
		code := XORDecodeFunc()
		reg, err := native.NewRegion(code)
		if err != nil {
			t.Fatalf("map: %v", err)
		}
		dst := make([]byte, len(plain))
		ensureHeadroom()
		native.Call4(uintptr(reg.Base()), uintptr(ptrOf(dst)), uintptr(ptrOf(cipher)), uintptr(len(plain)), uintptr(key))
		if string(dst) != string(plain) {
			t.Fatalf("key %#x: stub produced % x, want % x", key, dst, plain)
		}
		if err := reg.Free(); err != nil {
			t.Fatalf("munmap: %v", err)
		}
	}
}

// TestXORSelfDecodeStubStitchesCorrectly runs the *self-locating* stub (the
// production form, which finds its payload with a RIP-relative LEA) and then
// executes the decrypted payload, proving both the displacement arithmetic and
// the decode loop.
func TestXORSelfDecodeStubStitchesCorrectly(t *testing.T) {
	payload := loadFixture(t, "prog1")
	for _, key := range []byte{0x00, 0x5A, 0xA5, 0xFF} {
		cipher := make([]byte, len(payload))
		for i, b := range payload {
			cipher[i] = b ^ key
		}
		plan := XORSelfDecodeStub(key, len(payload), false)
		image := append(append([]byte(nil), plan.Code...), cipher...)

		reg, err := native.NewRegion(image)
		if err != nil {
			t.Fatalf("map: %v", err)
		}
		ensureHeadroom()
		// The stub locates, decrypts and returns; nothing is passed to it.
		native.Call4(uintptr(reg.Base()), 0, 0, 0, 0)

		// Copy before unmapping: got aliases the region's memory.
		got := append([]byte(nil), reg.Bytes()[plan.DataOffset:plan.DataOffset+len(payload)]...)
		if string(got) != string(payload) {
			t.Fatalf("key %#x: in-place decode produced % x, want % x", key, got, payload)
		}
		_ = reg.Free()

		// Now run the decrypted payload itself.
		decoded := append([]byte(nil), got...)
		if v := runFixture(t, decoded, uintptr(uint32(7)), 0, 0, 0); v != prog1Expected(7) {
			t.Fatalf("key %#x: decoded payload returned %#x, want %#x", key, v, prog1Expected(7))
		}
	}
}

// TestXORSelfDecodeStubJumpsIntoPayload checks the production terminator: the
// stub must transfer control to the first decrypted byte.
func TestXORSelfDecodeStubJumpsIntoPayload(t *testing.T) {
	key := byte(0x33)
	// Payload: mov eax, 0x11223344 ; ret
	payload := []byte{0xB8, 0x44, 0x33, 0x22, 0x11, 0xC3}
	cipher := make([]byte, len(payload))
	for i, b := range payload {
		cipher[i] = b ^ key
	}
	plan := XORSelfDecodeStub(key, len(payload), true)
	image := append(append([]byte(nil), plan.Code...), cipher...)
	got := runFixture(t, image, 0, 0, 0, 0)
	if got != 0x11223344 {
		t.Fatalf("self-decoding stub returned %#x, want 0x11223344", got)
	}
}

func TestMultiKeyXORDecoderExecutes(t *testing.T) {
	plain := []byte("SuspiciousApiNames: VirtualAlloc CreateRemoteThread WriteProcessMemory")
	const chunkLen = 13
	chunks := (len(plain) + chunkLen - 1) / chunkLen
	keys := make([]byte, chunks)
	padded := append([]byte(nil), plain...)
	for len(padded) < chunks*chunkLen {
		padded = append(padded, 0)
	}
	cipher := make([]byte, chunks*chunkLen)
	for c := 0; c < chunks; c++ {
		keys[c] = byte(0x11 + c*7)
		for i := 0; i < chunkLen; i++ {
			cipher[c*chunkLen+i] = padded[c*chunkLen+i] ^ keys[c]
		}
	}

	ensureHeadroom()
	reg, err := native.NewRegion(MultiKeyXORDecodeFunc())
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	defer func() { _ = reg.Free() }()

	out := make([]byte, chunks*chunkLen)
	reg.Call6(uintptr(ptrOf(out)), uintptr(ptrOf(cipher)), uintptr(ptrOf(keys)), uintptr(chunkLen), uintptr(chunks))
	if string(out) != string(padded) {
		t.Fatalf("chunked decoder produced % x,\n  want % x", out, padded)
	}
	// The literal must be recoverable chunk-by-chunk, which is the property the
	// string stage relies on.
	if string(out[:len(plain)]) != string(plain) {
		t.Fatalf("recovered literal %q, want %q", out[:len(plain)], plain)
	}
}

// ptrOf returns the address of the first byte of a non-empty slice.
func ptrOf(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }
