package encode

import (
	"bytes"
	stdbase64 "encoding/base64"
	"math/rand/v2"
	"strings"
	"testing"

	"pobf/internal/rng"
)

func testRand(seed int64, label string) *rand.Rand { return rng.Derive(seed, label) }

// TestStandardAlphabetMatchesRFC4648 is the differential check that keeps the
// hand-written codec honest: an alphabet-agnostic implementation is only
// trustworthy if it agrees with the standard library on the standard alphabet.
func TestStandardAlphabetMatchesRFC4648(t *testing.T) {
	a := StandardAlphabet()
	for n := 0; n <= 40; n++ {
		src := make([]byte, n)
		for i := range src {
			src[i] = byte(i*7 + 1)
		}
		got := string(a.EncodeBase64(src))
		want := stdbase64.StdEncoding.EncodeToString(src)
		if got != want {
			t.Fatalf("len %d: encoder produced %q, RFC 4648 says %q", n, got, want)
		}
		back, err := a.DecodeBase64([]byte(got), n)
		if err != nil {
			t.Fatalf("len %d: decode: %v", n, err)
		}
		if !bytes.Equal(back, src) {
			t.Fatalf("len %d: round trip produced % x, want % x", n, back, src)
		}
	}
}

func TestRandomAlphabetRoundTrip(t *testing.T) {
	for seed := int64(1); seed <= 16; seed++ {
		a := RandomAlphabet(testRand(seed, "alphabet"))
		if err := a.Validate(); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for n := 0; n <= 33; n++ {
			src := make([]byte, n)
			r := testRand(seed, "payload")
			for i := range src {
				src[i] = byte(r.UintN(256))
			}
			text := a.EncodeBase64(src)
			if len(text)%4 != 0 {
				t.Fatalf("seed %d len %d: encoded length %d is not a multiple of 4", seed, n, len(text))
			}
			back, err := a.DecodeBase64(text, n)
			if err != nil {
				t.Fatalf("seed %d len %d: %v", seed, n, err)
			}
			if !bytes.Equal(back, src) {
				t.Fatalf("seed %d len %d: round trip mismatch", seed, n)
			}
		}
	}
}

// TestRandomAlphabetDiffersPerRun is the point of the custom alphabet: two seeds
// must not produce the same encoding of the same bytes.
func TestRandomAlphabetDiffersPerRun(t *testing.T) {
	src := []byte("VirtualAlloc WriteProcessMemory CreateRemoteThread")
	al1 := RandomAlphabet(testRand(1, "a"))
	al2 := RandomAlphabet(testRand(2, "a"))
	a1 := al1.EncodeBase64(src)
	a2 := al2.EncodeBase64(src)
	if bytes.Equal(a1, a2) {
		t.Fatal("two different seeds produced identical Base64 output")
	}
	if strings.Contains(string(a1), "VirtualAlloc") {
		t.Fatal("encoded output still contains the plaintext literal")
	}
}

func TestXORImageRoundTrip(t *testing.T) {
	src := []byte("the quick brown fox jumps over the lazy dog")
	for seed := int64(1); seed <= 8; seed++ {
		opts := DefaultXOROptions()
		img, info, err := BuildXORImage(src, testRand(seed, "xor"), opts)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if !IsEncodedImage(img.Bytes) {
			t.Fatalf("seed %d: output is not a parseable container", seed)
		}
		if bytes.Contains(img.Bytes, []byte("quick brown")) {
			t.Fatalf("seed %d: plaintext survived encoding", seed)
		}
		got, err := DecodeXORImage(img.Bytes)
		if err != nil {
			t.Fatalf("seed %d: decode: %v", seed, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("seed %d: round trip mismatch: %q", seed, got)
		}
		if img.Kind != StubMachineCode {
			t.Fatalf("seed %d: XOR must ship an executable stub, got %q", seed, img.Kind)
		}
		if info.KeyLen != opts.KeyLen {
			t.Fatalf("seed %d: reported key length %d, want %d", seed, info.KeyLen, opts.KeyLen)
		}
	}
}

func TestXORImageChainedKeystream(t *testing.T) {
	src := []byte("round trip through a self-referential keystream")
	for _, chain := range []bool{false, true} {
		for seed := int64(1); seed <= 6; seed++ {
			opts := XOROptions{KeyLen: 24, Chain: chain}
			img, info, err := BuildXORImage(src, testRand(seed, "xor-chain"), opts)
			if err != nil {
				t.Fatalf("chain %t seed %d: %v", chain, seed, err)
			}
			got, err := DecodeXORImage(img.Bytes)
			if err != nil {
				t.Fatalf("chain %t seed %d: decode: %v", chain, seed, err)
			}
			if !bytes.Equal(got, src) {
				t.Fatalf("chain %t seed %d: mismatch", chain, seed)
			}
			if info.Chained != chain {
				t.Fatalf("chain %t seed %d: report says chained=%t", chain, seed, info.Chained)
			}
		}
	}
}

// TestXORTransformIsInvertible pins the recurrence itself, independently of the
// container: the chained encoder feeds on its own output, so a naive "XOR twice"
// decoder would look correct on the first byte and diverge afterwards.
func TestXORTransformIsInvertible(t *testing.T) {
	key := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	src := make([]byte, 97)
	for i := range src {
		src[i] = byte(i*11 + 3)
	}
	for _, chain := range []bool{false, true} {
		ct := xorEncode(src, key, chain)
		if chain && bytes.Equal(ct, src) {
			t.Fatal("chained encoding was a no-op")
		}
		pt := xorDecode(ct, key, chain)
		if !bytes.Equal(pt, src) {
			t.Fatalf("chain %t: transform is not invertible", chain)
		}
		if chain && bytes.Equal(xorDecode(ct, key, false), src) {
			t.Fatal("the unchained decoder recovered a chained ciphertext, so the test cannot tell them apart")
		}
	}
}

func TestAESImageRoundTrip(t *testing.T) {
	src := []byte("AES-256-CBC under PBKDF2-HMAC-SHA256")
	// A low iteration count keeps the test fast; production defaults are 200k.
	opts := AESOptions{Iterations: 1000, SaltLen: 16}
	for seed := int64(1); seed <= 4; seed++ {
		img, info, err := BuildAESImage(src, testRand(seed, "aes"), opts, "correct horse battery staple")
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if img.Kind != StubDescriptor {
			t.Fatalf("seed %d: AES stub kind is %q, want %q", seed, img.Kind, StubDescriptor)
		}
		if bytes.Contains(img.Bytes, src) {
			t.Fatalf("seed %d: plaintext survived encryption", seed)
		}
		got, err := DecodeAESImage(img.Bytes, "correct horse battery staple")
		if err != nil {
			t.Fatalf("seed %d: decode: %v", seed, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("seed %d: round trip mismatch", seed)
		}
		if _, err := DecodeAESImage(img.Bytes, "wrong passphrase"); err == nil {
			t.Fatalf("seed %d: decryption with the wrong passphrase succeeded", seed)
		}
		if info.KeyBits != 256 {
			t.Fatalf("seed %d: key size %d, want 256", seed, info.KeyBits)
		}
	}
}

func TestAESImagesAreDistinct(t *testing.T) {
	src := []byte("same plaintext, two runs")
	opts := AESOptions{Iterations: 1000, SaltLen: 16}
	a, _, err := BuildAESImage(src, testRand(1, "aes"), opts, "shared-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := BuildAESImage(src, testRand(2, "aes"), opts, "shared-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Bytes, b.Bytes) {
		t.Fatal("two runs with the same passphrase produced identical ciphertext (salt or IV is not random)")
	}
}

func TestBase64ImageRoundTrip(t *testing.T) {
	src := []byte("encode this payload with a shuffled alphabet")
	for seed := int64(1); seed <= 8; seed++ {
		img, _, err := BuildBase64Image(src, testRand(seed, "b64"), DefaultBase64Options())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		got, err := DecodeBase64Image(img.Bytes)
		if err != nil {
			t.Fatalf("seed %d: decode: %v", seed, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("seed %d: round trip mismatch", seed)
		}
	}
}

func TestStringImageRoundTrip(t *testing.T) {
	src := []byte("code bytes then a VirtualAlloc literal and a /etc/passwd path")
	for seed := int64(1); seed <= 8; seed++ {
		img, info, err := BuildStringImage(src, testRand(seed, "strings"), DefaultStringOptions())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if info.MaskedBytes == 0 {
			t.Fatalf("seed %d: nothing was masked", seed)
		}
		got, err := DecodeStringImage(img.Bytes)
		if err != nil {
			t.Fatalf("seed %d: decode: %v", seed, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("seed %d: round trip mismatch: %q", seed, got)
		}
		if bytes.Contains(img.Bytes, []byte("VirtualAlloc")) {
			t.Fatalf("seed %d: the masked literal is still present verbatim", seed)
		}
	}
}

func TestContainerRejectsGarbage(t *testing.T) {
	if _, err := ParseContainer([]byte("not a container")); err == nil {
		t.Fatal("expected an error for a buffer without a header")
	}
	if _, err := ParseContainer(make([]byte, HeaderSize)); err == nil {
		t.Fatal("expected an error for a header with the wrong magic")
	}
	img, _, err := BuildBase64Image([]byte("abc"), testRand(1, "b64"), DefaultBase64Options())
	if err != nil {
		t.Fatal(err)
	}
	truncated := img.Bytes[:img.Container.DataOffset+1]
	if _, err := ParseContainer(truncated); err != nil {
		// Truncation is only rejected if the declared region no longer fits.
		t.Logf("truncated container rejected: %v", err)
	}
}

func TestPKCS7RoundTrip(t *testing.T) {
	for n := 0; n <= 40; n++ {
		src := bytes.Repeat([]byte{0xAB}, n)
		padded := pkcs7Pad(src, 16)
		if len(padded)%16 != 0 || len(padded) < n+1 {
			t.Fatalf("len %d: padding produced %d bytes", n, len(padded))
		}
		back, err := pkcs7Unpad(padded, 16)
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if !bytes.Equal(back, src) {
			t.Fatalf("len %d: unpadding mismatch", n)
		}
	}
	if _, err := pkcs7Unpad([]byte{1, 2, 3}, 16); err == nil {
		t.Fatal("expected a rejection for a non-multiple length")
	}
	if _, err := pkcs7Unpad(bytes.Repeat([]byte{0x00}, 16), 16); err == nil {
		t.Fatal("expected a rejection for zero padding")
	}
}
