package encode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"

	"crypto/pbkdf2"
)

// AESInfo describes an AES-256-CBC encoding run.
type AESInfo struct {
	Passphrase    string `json:"passphrase"`
	Iterations    int    `json:"iterations"`
	KeyBits       int    `json:"key_bits"`
	Salt          string `json:"salt"`
	IV            string `json:"iv"`
	MaxInsertions int    `json:"-"`
}

// aesParams is the binary parameter block stored in the container.
//
//	0  keyLen  uint8  (always 32, kept explicit so the format can grow)
//	1  iters   uint32
//	5  salt    [16]byte
//	21 iv      [16]byte
const aesParamSize = 1 + 4 + 16 + 16

// AESOptions controls the AES stage.
type AESOptions struct {
	// Passphrase seeds PBKDF2. Empty means "generate a random one and record it
	// in the stage's Details", which is what makes each run produce a distinct
	// ciphertext for the same input.
	Passphrase string
	// Iterations is the PBKDF2 work factor.
	Iterations int
	// SaltLen is the PBKDF2 salt length in bytes.
	SaltLen int
}

// DefaultAESOptions returns the tuned defaults.
func DefaultAESOptions() AESOptions {
	return AESOptions{Iterations: 200000, SaltLen: 16}
}

// PasswordLength is the length of a generated passphrase.
const PasswordLength = 24

// RandomPassphrase returns a printable random passphrase from crypto/rand.
//
// The obfuscation itself may be seeded for reproducibility, but a key that an
// attacker can predict from a seed is not a key. Generated passphrases therefore
// come from the OS entropy pool unless the caller supplies one.
func RandomPassphrase() (string, error) {
	buf := make([]byte, PasswordLength)
	if _, err := io.ReadFull(cryptorand.Reader, buf); err != nil {
		return "", fmt.Errorf("encode: reading passphrase entropy: %w", err)
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}

// DeriveKey runs PBKDF2-HMAC-SHA256.
func DeriveKey(passphrase string, salt []byte, iterations, keyLen int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
}

func pkcs7Pad(b []byte, block int) []byte {
	n := block - len(b)%block
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

func pkcs7Unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 || len(b)%block != 0 {
		return nil, fmt.Errorf("encode: ciphertext length %d is not a multiple of the block size", len(b))
	}
	n := int(b[len(b)-1])
	if n == 0 || n > block || n > len(b) {
		return nil, fmt.Errorf("encode: invalid PKCS#7 padding length %d", n)
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, fmt.Errorf("encode: inconsistent PKCS#7 padding")
		}
	}
	return b[:len(b)-n], nil
}

// BuildAESImage encrypts src with AES-256-CBC under a PBKDF2-derived key.
//
// StubKind is reported as a descriptor: the decryption is described by the
// parameter block (salt, IV, iteration count) and must be carried out by a
// loader, because a correct hand-written AES-256-CBC decryption stub is far
// beyond the scope of a generated decoder. DeriveKey and DecryptAES below are
// that loader, and the test suite runs them as the self-extraction proof.
func BuildAESImage(src []byte, r *rand.Rand, opts AESOptions, passphrase string) (*Image, *AESInfo, error) {
	if opts.Iterations <= 0 {
		opts.Iterations = 200000
	}
	if opts.SaltLen <= 0 {
		opts.SaltLen = 16
	}
	if opts.SaltLen != 16 {
		return nil, nil, fmt.Errorf("encode: only a 16-byte salt is supported (got %d)", opts.SaltLen)
	}
	if passphrase == "" {
		p, err := RandomPassphrase()
		if err != nil {
			return nil, nil, err
		}
		passphrase = p
	}

	salt := make([]byte, opts.SaltLen)
	iv := make([]byte, aes.BlockSize)
	for i := range salt {
		salt[i] = byte(r.UintN(256))
	}
	for i := range iv {
		iv[i] = byte(r.UintN(256))
	}

	key, err := DeriveKey(passphrase, salt, opts.Iterations, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("encode: PBKDF2: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	padded := pkcs7Pad(src, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	params := make([]byte, aesParamSize)
	params[0] = 32
	binary.LittleEndian.PutUint32(params[1:], uint32(opts.Iterations))
	copy(params[5:21], salt)
	copy(params[21:37], iv)

	img, err := BuildImage(AlgoAES, 0, params, nil, ct, len(src), StubDescriptor)
	if err != nil {
		return nil, nil, err
	}
	info := &AESInfo{
		Passphrase: passphrase,
		Iterations: opts.Iterations,
		KeyBits:    256,
		Salt:       fmt.Sprintf("%x", salt),
		IV:         fmt.Sprintf("%x", iv),
	}
	img.Notes = append(img.Notes, fmt.Sprintf(
		"AES-256-CBC under PBKDF2-HMAC-SHA256 (%d iterations): decoder is a %d-byte loader descriptor, not executable bytes",
		opts.Iterations, aesParamSize))
	return img, info, nil
}

// DecodeAESImage reverses BuildAESImage. It needs the passphrase, because the
// whole point of the stage is that the key is not in the payload.
func DecodeAESImage(img []byte, passphrase string) ([]byte, error) {
	c, err := ParseContainer(img)
	if err != nil {
		return nil, err
	}
	if c.Algorithm != AlgoAES {
		return nil, fmt.Errorf("encode: image holds algorithm %d, not AES", c.Algorithm)
	}
	if len(c.Params) != aesParamSize {
		return nil, fmt.Errorf("encode: AES image has a %d-byte parameter block, want %d", len(c.Params), aesParamSize)
	}
	keyLen := int(c.Params[0])
	iters := int(binary.LittleEndian.Uint32(c.Params[1:]))
	salt := c.Params[5:21]
	iv := c.Params[21:37]

	key, err := DeriveKey(passphrase, salt, iters, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct := c.Data(img)
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encode: ciphertext length %d is not a positive multiple of %d", len(ct), aes.BlockSize)
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pt, err = pkcs7Unpad(pt, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	if c.PlainLen != len(pt) {
		return nil, fmt.Errorf("encode: AES image claims %d plaintext bytes, recovered %d", c.PlainLen, len(pt))
	}
	return pt, nil
}

// KeyCheck returns a short fingerprint of a passphrase, so the report can name
// the key without printing it.
func KeyCheck(passphrase string) string {
	sum := hmac.New(sha256.New, []byte("pobf-key-check"))
	sum.Write([]byte(passphrase))
	return fmt.Sprintf("%x", sum.Sum(nil)[:6])
}
