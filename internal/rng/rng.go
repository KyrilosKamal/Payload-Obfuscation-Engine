// Package rng provides deterministic random sources derived from a seed and a
// label.
//
// Obfuscation needs randomness (keys, alphabets, morph choices) but must also be
// reproducible: a report that says "seed 12345 produced this sample" is only
// useful if seed 12345 always produces that sample. Deriving an independent
// stream per labelled component additionally means that adding an unrelated
// stage does not perturb an existing stage's output, which is what makes the
// benchmark mode's comparisons meaningful.
package rng

import (
	"hash/fnv"
	"math/rand/v2"
)

// Derive returns a deterministic random source for a seed and label.
func Derive(seed int64, label string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(label))
	_, _ = h.Write([]byte{0})
	var sb [8]byte
	v := uint64(seed)
	for i := 0; i < 8; i++ {
		sb[i] = byte(v >> (8 * i))
	}
	_, _ = h.Write(sb[:])
	sum := h.Sum64()
	return rand.New(rand.NewPCG(sum, sum*0x2545F4914F6CDD1D+0x9E3779B97F4A7C15))
}

// New returns a random source from a raw seed pair.
func New(a, b uint64) *rand.Rand { return rand.New(rand.NewPCG(a, b)) }

// Bytes returns n cryptographically-uninteresting but seed-derived bytes.
func Bytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.UintN(256))
	}
	return b
}

// ShuffledBytes returns a permutation of 0..n-1 as bytes.
func ShuffledBytes(r *rand.Rand, n int) []byte {
	idx := r.Perm(n)
	out := make([]byte, n)
	for i, v := range idx {
		out[i] = byte(v)
	}
	return out
}
