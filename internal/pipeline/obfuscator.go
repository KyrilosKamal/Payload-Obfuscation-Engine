// Package pipeline defines the composable obfuscation pipeline.
//
// The central abstraction is deliberately minimal: an obfuscation stage is
// anything that turns bytes into bytes. Stages are chained in an arbitrary
// order by the caller, which mirrors how real obfuscation frameworks (Veil,
// Shikata Ga Nai, Cobalt Strike's artifact kit) are assembled from independent
// transforms.
package pipeline

import (
	"fmt"
	"time"

	"pobf/internal/entropy"
)

// Obfuscator is the core pipeline contract: take a payload, return a payload.
//
// Implementations must be pure with respect to their input (never mutate in)
// and must be safe to call repeatedly. Randomness is provided at construction
// time via Context so that Apply itself stays a simple function.
type Obfuscator interface {
	Apply(in []byte) ([]byte, error)
}

// Kind classifies a stage for reporting and benchmarking purposes.
type Kind string

const (
	KindEncoding    Kind = "encoding"
	KindEncryption  Kind = "encryption"
	KindPolymorphic Kind = "polymorphic"
	KindDeadCode    Kind = "deadcode"
	KindControlFlow Kind = "control-flow"
	KindStrings     Kind = "strings"
)

// Stage is an Obfuscator that can describe itself. Every stage shipped in this
// repository implements Stage, but the pipeline only requires Obfuscator so
// that callers can plug in their own transforms.
type Stage interface {
	Obfuscator
	// Name is the stable identifier used on the command line, in the HTTP API
	// and in reports.
	Name() string
	// Description is a one-line human-readable summary.
	Description() string
	// Kind classifies the technique.
	Kind() Kind
}

// Detailable is implemented by stages that want to hand structured metadata to
// the reporting layer (keys generated, substitutions applied, blocks created,
// ...). Details must describe the most recent Apply call.
type Detailable interface {
	Details() map[string]any
}

// Reversible is implemented by stages that embed a decoder stub and can
// therefore demonstrate self-extraction: Decode undoes Apply for the bytes that
// the emitted stub would recover at runtime.
//
// This is what makes the encoding stages honest: the "runtime stub" is not a
// comment, it is a specification that the engine itself executes.
type Reversible interface {
	Decode(in []byte) ([]byte, error)
}

// Applicator is implemented by stages that can say whether their most recent
// Apply actually transformed the payload.
//
// A stage may decline a payload (see ErrSkipped in internal/stages): it refuses
// a data blob offered to the instruction rewriter, or a PE offered to an
// in-place rewriter, and passes the bytes through unchanged. Reversing such a
// stage is meaningless -- there is no decoder in the stream -- so DecodeAll asks
// instead of guessing, and the verification step refuses to call the result
// "verified".
type Applicator interface {
	Applied() bool
}

// Step records what a single stage did to a single payload.
type Step struct {
	Round       int            `json:"round"`
	Name        string         `json:"name"`
	Kind        Kind           `json:"kind"`
	InSize      int            `json:"in_size"`
	OutSize     int            `json:"out_size"`
	DurationMS  float64        `json:"duration_ms"`
	EntropyIn   float64        `json:"entropy_in"`
	EntropyOut  float64        `json:"entropy_out"`
	Details     map[string]any `json:"details,omitempty"`
	Error       string         `json:"error,omitempty"`
	err         error          `json:"-"`
	duration    time.Duration
	skippedFlag bool
}

// Result is the outcome of running a pipeline.
type Result struct {
	Input  []byte `json:"-"`
	Output []byte `json:"-"`
	Steps  []Step `json:"steps"`
	Rounds int    `json:"rounds"`
}

// Err accepts the error captured by a step (see Pipeline.RunSteps).
func (s *Step) Err() error { return s.err }

// Pipeline is an ordered list of stages applied to a payload.
type Pipeline struct {
	stages []Stage
}

// New builds a pipeline from the given stages, in order.
func New(stages ...Stage) *Pipeline { return &Pipeline{stages: stages} }

// Append adds stages to the end of the pipeline.
func (p *Pipeline) Append(stages ...Stage) *Pipeline {
	p.stages = append(p.stages, stages...)
	return p
}

// Stages returns the configured stages.
func (p *Pipeline) Stages() []Stage { return append([]Stage(nil), p.stages...) }

// Len reports how many stages are configured.
func (p *Pipeline) Len() int { return len(p.stages) }

// Run applies every stage once, returning the final payload and the recorded
// steps. If a stage fails, Run stops and returns the error together with the
// steps recorded so far.
func (p *Pipeline) Run(in []byte) (*Result, error) {
	res := &Result{Input: append([]byte(nil), in...), Rounds: 1}
	cur := in
	for i, st := range p.stages {
		start := time.Now()
		out, err := st.Apply(cur)
		step := Step{
			Round:      1,
			Name:       st.Name(),
			Kind:       st.Kind(),
			InSize:     len(cur),
			OutSize:    len(out),
			EntropyIn:  entropy.Shannon(cur),
			EntropyOut: entropy.Shannon(out),
			duration:   time.Since(start),
			err:        err,
		}
		step.DurationMS = float64(step.duration.Microseconds()) / 1000.0
		if d, ok := st.(Detailable); ok {
			step.Details = d.Details()
		}
		if err != nil {
			step.Error = err.Error()
			res.Steps = append(res.Steps, step)
			return res, fmt.Errorf("stage %d (%s): %w", i+1, st.Name(), err)
		}
		res.Steps = append(res.Steps, step)
		cur = out
	}
	res.Output = cur
	return res, nil
}

// RunRounds applies the full pipeline `rounds` times. Every iteration is
// recorded separately so the reporting layer can show how entropy and
// detection evolve across rounds.
func (p *Pipeline) RunRounds(in []byte, rounds int) (*Result, error) {
	if rounds < 1 {
		rounds = 1
	}
	res := &Result{Input: append([]byte(nil), in...), Rounds: rounds}
	cur := in
	for r := 1; r <= rounds; r++ {
		for i, st := range p.stages {
			start := time.Now()
			out, err := st.Apply(cur)
			step := Step{
				Round:      r,
				Name:       st.Name(),
				Kind:       st.Kind(),
				InSize:     len(cur),
				OutSize:    len(out),
				EntropyIn:  entropy.Shannon(cur),
				EntropyOut: entropy.Shannon(out),
				duration:   time.Since(start),
				err:        err,
			}
			step.DurationMS = float64(step.duration.Microseconds()) / 1000.0
			if d, ok := st.(Detailable); ok {
				step.Details = d.Details()
			}
			if err != nil {
				step.Error = err.Error()
				res.Steps = append(res.Steps, step)
				return res, fmt.Errorf("round %d stage %d (%s): %w", r, i+1, st.Name(), err)
			}
			res.Steps = append(res.Steps, step)
			cur = out
		}
	}
	res.Output = cur
	return res, nil
}

// DecodeAll walks the pipeline in reverse, applying every Reversible stage's
// decoder. It is the engine-side proof that the emitted decoder stubs actually
// describe an invertible transform.
//
// Stages that are not Reversible (polymorphic rewriting, dead code insertion,
// control-flow flattening) are semantics-preserving transformations, not
// invertible ones, and are skipped with a note in the returned list.
//
// A stage that declined the payload is also skipped: it passed the bytes
// through untouched, so there is no decoder stub in the stream to run, and
// attempting the decode would report a failure that never happened.
func (p *Pipeline) DecodeAll(in []byte) (out []byte, notes []string, err error) {
	out = in
	for i := len(p.stages) - 1; i >= 0; i-- {
		st := p.stages[i]
		rev, ok := st.(Reversible)
		if !ok {
			notes = append(notes, fmt.Sprintf("%s: not invertible (semantics-preserving transform)", st.Name()))
			continue
		}
		if ap, ok := st.(Applicator); ok && !ap.Applied() {
			notes = append(notes, fmt.Sprintf("%s: declined the payload, nothing to invert", st.Name()))
			continue
		}
		next, derr := rev.Decode(out)
		if derr != nil {
			return nil, notes, fmt.Errorf("decoding stage %s: %w", st.Name(), derr)
		}
		out = next
		notes = append(notes, fmt.Sprintf("%s: decoded via embedded stub", st.Name()))
	}
	return out, notes, nil
}
