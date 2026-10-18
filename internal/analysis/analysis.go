package analysis

import (
	"errors"
	"fmt"
	"time"

	"pobf/internal/encode"
	"pobf/internal/entropy"
	"pobf/internal/pipeline"
	"pobf/internal/stages"
	"pobf/internal/yara"
)

// Scanner is the detection oracle. *yara.Ruleset satisfies it.
type Scanner interface {
	Scan(b []byte) ([]yara.Finding, error)
	Names() []string
}

// Step is one stage's effect on the payload, with the detection counts taken
// immediately before and after it.
type Step struct {
	Index int           `json:"index"`
	Round int           `json:"round"`
	Name  string        `json:"name"`
	Kind  pipeline.Kind `json:"kind"`

	InSize  int `json:"in_size"`
	OutSize int `json:"out_size"`
	Delta   int `json:"delta"`

	EntropyIn  float64 `json:"entropy_in"`
	EntropyOut float64 `json:"entropy_out"`

	DurationMS float64 `json:"duration_ms"`

	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
	StubKind   string `json:"stub_kind,omitempty"`
	// PayloadKind names the shape the stage was handed ("raw" or "pe"). It is
	// reported because a stage's meaning changes with it: an encoding stage over
	// a PE produces a container to be decoded, never a loadable file.
	PayloadKind string `json:"payload_kind,omitempty"`

	DetectionsBefore int `json:"detections_before"`
	DetectionsAfter  int `json:"detections_after"`

	// Cleared lists rules that fired before this stage and no longer do, which
	// is the stage's actual contribution to evasion.
	Cleared []string `json:"cleared,omitempty"`
	// Added lists rules that started firing because of this stage. This is not
	// hypothetical: dead-code insertion can create a NOP sled, and every
	// encoding stage adds a decoder stub that the ruleset recognises on
	// purpose.
	Added []string `json:"added,omitempty"`

	Details map[string]any `json:"details,omitempty"`
}

// Report is the full result of running a pipeline over one payload.
type Report struct {
	Label    string   `json:"label"`
	Pipeline []string `json:"pipeline"`
	Rounds   int      `json:"rounds"`
	Seed     int64    `json:"seed"`

	TotalRules int `json:"total_rules"`

	Before Profile `json:"before"`
	After  Profile `json:"after"`

	// BeforeBlob and AfterBlob are kept so the renderer can produce the
	// byte-level diff. They are excluded from JSON: the report is meant to be
	// readable and the payloads are large and binary.
	BeforeBlob []byte `json:"-"`
	AfterBlob  []byte `json:"-"`

	FindingsBefore []yara.Finding `json:"findings_before,omitempty"`
	FindingsAfter  []yara.Finding `json:"findings_after,omitempty"`

	DetectionBefore float64 `json:"detection_rate_before"`
	DetectionAfter  float64 `json:"detection_rate_after"`

	Steps []Step `json:"steps"`

	// Verified reports whether the engine could walk the pipeline backwards and
	// recover the original bytes from the embedded decoder stubs. It is false
	// when the pipeline contains a stage that is not invertible by construction
	// (polymorphic rewriting, dead code, flattening) or when more than one round
	// was applied.
	Verified bool `json:"verified"`

	// Notes records observations that qualify the numbers, such as a stage that
	// declined to run.
	Notes []string `json:"notes,omitempty"`

	TotalMS float64 `json:"total_ms"`
}

// Rate computes a detection rate from a finding count and the ruleset size.
func Rate(count, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(count) / float64(total)
}

// EvasionGain is the fraction of the firing rules that stopped firing.
func (r *Report) EvasionGain() float64 {
	if r.DetectionBefore == 0 {
		return 0
	}
	return 1 - r.DetectionAfter/r.DetectionBefore
}

// Growth is the final size multiplier.
func (r *Report) Growth() float64 { return r.Before.Growth(r.After) }

// SkippedStages lists the stages that declined to transform the payload.
func (r *Report) SkippedStages() []string {
	var out []string
	for _, s := range r.Steps {
		if s.Skipped {
			out = append(out, s.Name)
		}
	}
	return out
}

// Options configures a run.
type Options struct {
	// Rounds repeats the whole pipeline. Detection is measured after every
	// stage of every round.
	Rounds int
	// Seed is recorded for reproducibility; the stages themselves are already
	// bound to a seeded context by the caller.
	Seed int64
	// Verify asks the engine to decode its own output via the embedded stubs.
	Verify bool
	// Scan enables the YARA measurement. With it off the report contains only
	// static shape, which is what `--benchmark` uses when ranking hundreds of
	// combinations.
	Scan bool
}

// Analyzer runs pipelines and measures them.
type Analyzer struct {
	Scanner Scanner
	rules   int
}

// New builds an Analyzer. A nil scanner disables detection measurement.
func New(sc Scanner) *Analyzer {
	a := &Analyzer{Scanner: sc}
	if sc != nil {
		a.rules = len(sc.Names())
	}
	return a
}

// Rules reports how many rules the scanner holds.
func (a *Analyzer) Rules() int { return a.rules }

// Analyze applies the stages in order to input, measuring after each one.
//
// The stages must already be constructed against a seeded Context; Analyze does
// not create them, so the caller controls reproducibility and the HTTP API can
// keep per-request state out of shared objects.
func (a *Analyzer) Analyze(label string, input []byte, stageList []pipeline.Stage, opts Options) (*Report, error) {
	rounds := opts.Rounds
	if rounds < 1 {
		rounds = 1
	}
	start := time.Now()
	rep := &Report{
		Label:      label,
		Rounds:     rounds,
		Seed:       opts.Seed,
		TotalRules: a.rules,
		Before:     ProfileBytes(input),
	}
	var names []string
	for _, st := range stageList {
		names = append(names, st.Name())
	}
	rep.Pipeline = names

	before, err := a.scan(input, opts)
	if err != nil {
		return nil, err
	}
	rep.FindingsBefore = before

	cur := input
	for r := 1; r <= rounds; r++ {
		for i, st := range stageList {
			stepStart := time.Now()
			out, applyErr := st.Apply(cur)
			dur := time.Since(stepStart)

			step := Step{
				Index:      i + 1,
				Round:      r,
				Name:       st.Name(),
				Kind:       st.Kind(),
				InSize:     len(cur),
				EntropyIn:  entropy.Shannon(cur),
				DurationMS: float64(dur.Microseconds()) / 1000.0,
				Details:    detailsOf(st),
			}
			if applyErr != nil {
				var skipped *stages.ErrSkipped
				if !errors.As(applyErr, &skipped) {
					return nil, fmt.Errorf("stage %d (%s): %w", i+1, st.Name(), applyErr)
				}
				step.Skipped = true
				step.SkipReason = skipped.Reason
				step.OutSize = len(cur)
				step.EntropyOut = step.EntropyIn
				step.DetectionsBefore = countFindings(before)
				step.DetectionsAfter = step.DetectionsBefore
				rep.Steps = append(rep.Steps, step)
				rep.Notes = append(rep.Notes, fmt.Sprintf("round %d: %s skipped (%s); payload passed through unchanged", r, st.Name(), skipped.Reason))
				continue
			}

			out = append([]byte(nil), out...)
			step.OutSize = len(out)
			step.Delta = step.OutSize - step.InSize
			step.EntropyOut = entropy.Shannon(out)
			if kind, ok := step.Details["stub_kind"].(string); ok {
				step.StubKind = kind
			}
			if kind, ok := step.Details["payload_kind"].(string); ok {
				step.PayloadKind = kind
			}
			step.DetectionsBefore = countFindings(before)

			after, err := a.scan(out, opts)
			if err != nil {
				return nil, err
			}
			step.DetectionsAfter = countFindings(after)
			step.Cleared, step.Added = diffRules(before, after)

			rep.Steps = append(rep.Steps, step)
			before = after
			cur = out
		}
	}

	rep.After = ProfileBytes(cur)
	rep.FindingsAfter = before
	rep.BeforeBlob = append([]byte(nil), input...)
	rep.AfterBlob = append([]byte(nil), cur...)
	rep.DetectionBefore = Rate(countFindings(rep.FindingsBefore), a.rules)
	rep.DetectionAfter = Rate(countFindings(rep.FindingsAfter), a.rules)

	if note := peInputNote(rep.Steps); note != "" {
		rep.Notes = append(rep.Notes, note)
	}

	if opts.Verify && rounds == 1 {
		out, notes, err := pipeline.New(stageList...).DecodeAll(cur)
		rep.Notes = append(rep.Notes, notes...)
		switch {
		case err != nil:
			rep.Notes = append(rep.Notes, "self-extraction failed: "+err.Error())
		case !anyReversible(stageList):
			// Nothing in this pipeline emitted a decoder stub, so a round trip
			// cannot demonstrate anything. Saying "verified" here would be
			// vacuous and misleading, so the report says why instead.
			rep.Notes = append(rep.Notes, "no reversible stage in the pipeline: self-extraction is not applicable, the bytes pass through unchanged")
		case len(out) == len(input):
			rep.Verified = true
			rep.Notes = append(rep.Notes, fmt.Sprintf("self-extraction recovered %d bytes", len(out)))
		default:
			rep.Notes = append(rep.Notes, fmt.Sprintf("self-extraction recovered %d bytes, input was %d", len(out), len(input)))
		}
	}
	rep.TotalMS = float64(time.Since(start).Microseconds()) / 1000.0
	return rep, nil
}

func (a *Analyzer) scan(b []byte, opts Options) ([]yara.Finding, error) {
	if !opts.Scan || a.Scanner == nil {
		return nil, nil
	}
	return a.Scanner.Scan(b)
}

func countFindings(f []yara.Finding) int { return len(f) }

// anyReversible reports whether the pipeline contains at least one reversible
// stage that actually ran. Checking only the type would let a pipeline whose
// encoding stage declined the payload report a verified self-extraction: the
// bytes would be byte-for-byte identical, which round-trips trivially and proves
// nothing.
func anyReversible(stageList []pipeline.Stage) bool {
	for _, st := range stageList {
		if _, ok := st.(pipeline.Reversible); !ok {
			continue
		}
		if ap, ok := st.(pipeline.Applicator); ok && !ap.Applied() {
			continue
		}
		return true
	}
	return false
}

// peInputNote hoists the "this input was a PE" caveat to the top of the report.
//
// Each container stage already records the payload kind in its own details, but
// the terminal renderer shows report notes and not step details, and "what did I
// just produce" is the first question anyone asks about an obfuscated PE. The
// answer is not "a PE": a PE loader reads the import table and the data
// directories before any decoder of ours runs, so the artefact has to be decoded
// back to the original image rather than loaded or jumped into.
func peInputNote(steps []Step) string {
	for _, s := range steps {
		if s.PayloadKind == string(encode.InputPE) {
			return "a container stage wrapped a PE: " + encode.PEContainerNote
		}
	}
	return ""
}

func detailsOf(st pipeline.Stage) map[string]any {
	if d, ok := st.(pipeline.Detailable); ok {
		if m := d.Details(); m != nil {
			return m
		}
	}
	return nil
}

// diffRules returns the rules that disappeared and the rules that appeared.
func diffRules(before, after []yara.Finding) (cleared, added []string) {
	b := map[string]bool{}
	for _, f := range before {
		b[f.Rule] = true
	}
	seen := map[string]bool{}
	for _, f := range after {
		seen[f.Rule] = true
		if !b[f.Rule] {
			added = append(added, f.Rule)
		}
	}
	for _, f := range before {
		if !seen[f.Rule] {
			cleared = append(cleared, f.Rule)
		}
	}
	return dedup(cleared), dedup(added)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
