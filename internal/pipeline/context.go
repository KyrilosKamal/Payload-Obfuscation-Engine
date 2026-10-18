package pipeline

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"math/rand/v2"

	"pobf/internal/rng"
)

// Options are the knobs shared by every stage in a run.
type Options struct {
	// AllowFlagClobber permits instruction substitutions that change the value
	// of the EFLAGS register. Off by default: a substitution is only applied
	// when the next instruction does not consume flags (see x86.FlagLive).
	AllowFlagClobber bool
	// MaxInsertions caps how many dead-code snippets a single pass may inject.
	MaxInsertions int
	// MinStringLen is the shortest printable run the string stage treats as an
	// ASCII literal worth obfuscating.
	MinStringLen int
	// Passphrase seeds the AES stage's PBKDF2 derivation. Empty means "derive a
	// random one and record it in the stub descriptor".
	Passphrase string
	// CFPMaxBlocks caps control-flow flattening. Zero means unlimited.
	CFPMaxBlocks int
	// Verbose enables per-substitution logging.
	Verbose bool
}

// DefaultOptions returns the option set used when the caller does not specify
// one.
func DefaultOptions() Options {
	return Options{
		AllowFlagClobber: false,
		MaxInsertions:    64,
		MinStringLen:     6,
	}
}

// Context is handed to every stage at construction time. It carries the seeded
// random source that makes obfuscation reproducible (critical for tests and for
// reproducing a reported sample) plus the run-wide options and logger.
type Context struct {
	Seed    int64
	Options Options
	Log     *slog.Logger

	rng *rand.Rand
}

// NewContext builds a Context. A seed of 0 means "choose one": the engine then
// uses a non-deterministic seed so that a run without an explicit seed produces
// a fresh sample every time, while an explicit seed gives byte-for-byte
// reproducibility. The effective seed is always readable from Context.Seed, so
// a sample can be reproduced after the fact by passing that value back.
func NewContext(seed int64, opts Options, log *slog.Logger) *Context {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if seed == 0 {
		seed = randomSeed()
	}
	return &Context{
		Seed:    seed,
		Options: opts,
		Log:     log,
		rng:     rand.New(rand.NewPCG(uint64(seed), uint64(seed)*0x9E3779B97F4A7C15+0xDA3E39CB94B95BDB)),
	}
}

// randomSeed draws a seed from the operating system.
//
// crypto/rand rather than math/rand, because this value decides the XOR key and
// the AES salt: sourcing it from a predictable stream would make "a fresh key
// per run" a false claim.
func randomSeed() int64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice on any supported platform. Fall
		// back to the runtime's non-deterministic source rather than to a
		// constant, which would silently make every run identical.
		return rand.Int64()
	}
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// Rand returns the run-wide random source.
func (c *Context) Rand() *rand.Rand { return c.rng }

// Derive returns an independent, deterministic random source for a named stage.
//
// Deriving per stage (rather than sharing one stream) means that adding or
// removing an unrelated stage does not change a stage's output for a given
// seed. That property is what lets the benchmark mode compare stage
// combinations fairly.
func (c *Context) Derive(label string) *rand.Rand {
	return DeriveRNG(c.Seed, label)
}

// DeriveRNG builds a deterministic RNG from a seed and a label.
func DeriveRNG(seed int64, label string) *rand.Rand { return rng.Derive(seed, label) }
