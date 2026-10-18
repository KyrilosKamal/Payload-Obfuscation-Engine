package x86

import (
	"fmt"
	"math/rand/v2"
)

// PolymorphicOptions controls the instruction rewriter.
type PolymorphicOptions struct {
	// AllowFlagClobber permits morphs that change EFLAGS even when the
	// following code still depends on them. Off by default, because "add rax, 1
	// -> inc rax" silently drops the CF update and will break adc chains.
	AllowFlagClobber bool
	// Probability that an instruction with an available morph is actually
	// morphed, in [0,1].
	Probability float64
	// MaxSubstitutions caps the number of morphs applied (0 = unlimited).
	MaxSubstitutions int
}

// DefaultPolymorphicOptions returns the tuned defaults.
func DefaultPolymorphicOptions() PolymorphicOptions {
	return PolymorphicOptions{Probability: 0.75, MaxSubstitutions: 0}
}

// Morph records one applied substitution for the report.
type Morph struct {
	Offset    int    `json:"offset"`
	From      string `json:"from"`
	To        string `json:"to"`
	Rule      string `json:"rule"`
	SizeDelta int    `json:"size_delta"`
}

// NotRewritableError reports that a payload cannot be instruction-rewritten.
// Stages treat it as a skip, not a failure: rewriting a data blob as if it were
// code would corrupt it.
type NotRewritableError struct{ Reason string }

func (e *NotRewritableError) Error() string {
	return "payload is not instruction-rewritable: " + e.Reason
}

// Rewrite performs metamorphic substitution on an instruction stream.
//
// It returns the rewritten bytes, the list of applied morphs, and the mapping
// from original offsets to new offsets.
func Rewrite(b []byte, rng *rand.Rand, opts PolymorphicOptions) ([]byte, []Morph, map[int]int, error) {
	instrs := Disassemble(b)
	if ok, reason := Relocatable(instrs); !ok {
		return nil, nil, nil, &NotRewritableError{Reason: reason}
	}
	targets := map[int]bool{}
	for i := range instrs {
		if instrs[i].HasTarget {
			targets[instrs[i].Target] = true
		}
	}

	edits := map[int]Edit{}
	var log []Morph
	consumed := map[int]bool{}
	// Growing a substitution inside a short branch's range can push that branch
	// out of range, so growth is charged against a budget up front. Shrinking is
	// always safe.
	budget := NewBranchBudget(instrs)

	// try applies a morph at instruction i, reporting whether it did. It is a
	// closure because the force-first-morph pass below needs the exact same
	// legality checks.
	try := func(i int, force bool) bool {
		if consumed[i] {
			return false
		}
		if opts.MaxSubstitutions > 0 && len(log) >= opts.MaxSubstitutions {
			return false
		}
		in := &instrs[i]
		if !in.Decoded || len(in.Raw) == 0 {
			return false
		}

		winners := applicableMorphs(in, instrs, i, targets, opts)
		if len(winners) == 0 {
			return false
		}
		if !force && rng.Float64() > clamp01(opts.Probability) {
			return false
		}
		m := winners[rng.IntN(len(winners))]

		// Pair morphs consume the following instruction.
		var next *Instr
		nextIdx := -1
		if m.Pair != nil && i+1 < len(instrs) {
			if m.Pair(in, &instrs[i+1]) {
				next = &instrs[i+1]
				nextIdx = i + 1
			}
		}

		// A morph that erases bytes must not erase a branch target: an incoming
		// jump would land on whatever follows, skipping the flag/register effect
		// the original instruction had.
		if next != nil {
			out := m.PairEmit(in, next)
			if len(out) == 0 && (targets[in.Off] || targets[next.Off]) {
				return false
			}
			delta := len(out) - (in.Len + next.Len)
			if !budget.Allow(in.Off, delta) {
				return false
			}
			budget.Commit(in.Off, delta)
			edits[i] = Edit{Emit: func(res resolveFunc) ([]byte, error) { return out, nil }, Len: len(out)}
			edits[nextIdx] = Edit{Emit: func(resolveFunc) ([]byte, error) { return nil, nil }, Len: 0}
			consumed[nextIdx] = true
			log = append(log, Morph{
				Offset: in.Off, From: in.String() + " ; " + next.String(),
				To: disasmOne(out), Rule: m.Name, SizeDelta: delta,
			})
			return true
		}

		n, err := m.Size(in)
		if err != nil {
			return false
		}
		if n == 0 && targets[in.Off] {
			return false
		}
		// Reject no-op rewrites that change nothing.
		if n == in.Len && string(mustEmit(m, in)) == string(in.Raw) {
			return false
		}
		if !budget.Allow(in.Off, n-in.Len) {
			return false
		}
		budget.Commit(in.Off, n-in.Len)
		morph := m
		edits[i] = Edit{
			Len:  n,
			Emit: func(res resolveFunc) ([]byte, error) { return morph.Emit(in, res) },
		}
		log = append(log, Morph{
			Offset: in.Off, From: in.String(), To: disasmOne(mustEmit(m, in)),
			Rule: m.Name, SizeDelta: n - in.Len,
		})
		return true
	}

	// Visit sites in a shuffled order so the choice of which instructions are
	// morphed is uncorrelated with their position in the file.
	for _, i := range rng.Perm(len(instrs)) {
		try(i, false)
	}

	// A payload with morphable instructions but no applied morph is a wasted
	// opportunity, and at Probability < 1 it happens by chance. Force one so the
	// stage's contract ("this stage transforms code") holds for every seed.
	if len(log) == 0 {
		for _, i := range rng.Perm(len(instrs)) {
			if try(i, true) {
				break
			}
		}
	}

	out, newMap, err := BuildStream(instrs, edits)
	if err != nil {
		// A morph can turn out to be infeasible only once the new layout is
		// known (a near jump that no longer fits in rel8). Drop the offending
		// edit and retry rather than emitting a broken payload.
		out, newMap, log, err = retryWithoutFailure(instrs, edits, log, err)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// Final sanity check: the result must still be a clean instruction stream.
	check := Disassemble(out)
	if ok, bad := IsClean(check); !ok {
		return nil, nil, nil, &NotRewritableError{
			Reason: fmt.Sprintf("rewrite produced %d undecodable bytes; refusing to emit", bad),
		}
	}
	return out, log, newMap, nil
}

func mustEmit(m Substitution, in *Instr) []byte {
	b, err := m.Emit(in, func(int) (int, bool) { return 0, true })
	if err != nil {
		return nil
	}
	return b
}

// retryWithoutFailure removes morphs one at a time until the stream builds.
func retryWithoutFailure(instrs []Instr, edits map[int]Edit, log []Morph, cause error) ([]byte, map[int]int, []Morph, error) {
	cur := make(map[int]Edit, len(edits))
	for k, v := range edits {
		cur[k] = v
	}
	curLog := append([]Morph(nil), log...)
	for attempts := 0; attempts < 64; attempts++ {
		// Drop the highest-offset edit, which is the most likely to be the one
		// whose displacement cannot be encoded.
		worst := -1
		for k := range cur {
			if k > worst {
				worst = k
			}
		}
		if worst < 0 {
			return nil, nil, nil, cause
		}
		delete(cur, worst)
		filtered := make([]Morph, 0, len(curLog))
		for _, m := range curLog {
			if m.Offset != instrs[worst].Off {
				filtered = append(filtered, m)
			}
		}
		curLog = filtered
		out, newMap, err := BuildStream(instrs, cur)
		if err == nil {
			return out, newMap, curLog, nil
		}
	}
	return nil, nil, nil, cause
}

// applicableMorphs returns the morphs that may legally be applied to
// instruction i.
func applicableMorphs(in *Instr, instrs []Instr, i int, targets map[int]bool, opts PolymorphicOptions) []Substitution {
	live := flagsLiveAfter(instrs, i)
	var out []Substitution
	for si := range Substitutions {
		s := &Substitutions[si]
		if !s.Match(in) {
			continue
		}
		if s.Effect == FlagsModified && live && !opts.AllowFlagClobber {
			continue
		}
		// Pair morphs must have a partner.
		if s.Pair != nil {
			if i+1 >= len(instrs) || !s.Pair(in, &instrs[i+1]) {
				continue
			}
			if targets[instrs[i+1].Off] && len(s.PairEmit(in, &instrs[i+1])) == 0 {
				continue
			}
		}
		out = append(out, *s)
	}
	return out
}

// flagsLiveAfter reports whether the EFLAGS value produced by instruction i is
// consumed before anything overwrites it.
//
// This is the standard linear liveness scan: walk forward until the first
// instruction that reads flags (live) or writes them (dead). It is exact for
// straight-line code, which is where the metamorphic morphs matter, and
// conservative at control-flow boundaries.
func flagsLiveAfter(instrs []Instr, i int) bool {
	for j := i + 1; j < len(instrs); j++ {
		in := &instrs[j]
		if in.ReadsFlags {
			return true
		}
		if in.WritesFlags {
			return false
		}
		if in.Terminates() {
			return false
		}
	}
	return false
}

// disasmOne renders the first instruction of b, for logging.
func disasmOne(b []byte) string {
	if len(b) == 0 {
		return "(removed)"
	}
	instrs := Disassemble(b)
	if len(instrs) == 0 {
		return "?"
	}
	return instrs[0].String()
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
