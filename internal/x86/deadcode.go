package x86

import (
	"math/rand/v2"
)

// SnippetKind classifies injected dead code.
type SnippetKind string

const (
	SnippetNopSled  SnippetKind = "nop-sled"
	SnippetNoOp     SnippetKind = "do-nothing"
	SnippetOpaque   SnippetKind = "opaque-predicate"
	SnippetJunkCall SnippetKind = "junk-call"
)

// DeadCodeOptions controls dead-code injection.
type DeadCodeOptions struct {
	// MaxInsertions caps the number of snippets injected in one pass.
	MaxInsertions int
	// Probability is the chance a candidate position receives a snippet.
	Probability float64
	// MinNops and MaxNops bound a NOP sled's length in bytes.
	MinNops, MaxNops int
	// Trailing appends a snippet after the final instruction. Anything appended
	// past the last instruction cannot shift an existing offset, so it is always
	// safe even for payloads with unresolved control flow.
	Trailing bool
}

// DefaultDeadCodeOptions returns the tuned defaults.
func DefaultDeadCodeOptions() DeadCodeOptions {
	return DeadCodeOptions{MaxInsertions: 64, Probability: 0.35, MinNops: 1, MaxNops: 8, Trailing: false}
}

// DeadCodeStats summarises an injection pass.
type DeadCodeStats struct {
	Insertions int            `json:"insertions"`
	BytesAdded int            `json:"bytes_added"`
	ByKind     map[string]int `json:"by_kind"`
	// OnData is set when the payload could not be relocated as code and the
	// snippet was appended after the last instruction instead.
	AppendOnly bool   `json:"append_only"`
	Reason     string `json:"reason,omitempty"`
	// Sites lists the (original) offsets where snippets were inserted.
	Sites []int `json:"sites,omitempty"`
	// SitesRejected counts candidate positions that were dropped because
	// inserting there would have pushed a short branch out of range. Reporting
	// it keeps the difference between "found no sites" and "ran out of room"
	// visible.
	SitesRejected int `json:"sites_rejected,omitempty"`
	// Constrained is set when the payload contains at least one rel8 branch
	// whose range limits insertion.
	Constrained bool `json:"constrained,omitempty"`
}

// deadSnippets are the fixed-shape inert sequences. Each one must satisfy three
// properties: it leaves every general-purpose register unchanged, leaves EFLAGS
// unchanged, and leaves the stack balanced. native_amd64_test.go executes each
// of these inside a real decoder stub to prove it.
var (
	// nopEncodings are all architecturally valid NOPs of assorted lengths.
	nopEncodings = [][]byte{
		{0x90},
		{0x66, 0x90},
		{0x0F, 0x1F, 0x00},
		{0x0F, 0x1F, 0x40, 0x00},
		{0x0F, 0x1F, 0x44, 0x00, 0x00},
		{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
		{0x48, 0x87, 0xC0}, // xchg rax, rax
		{0x48, 0x89, 0xC0}, // mov rax, rax
	}
	// pushPopNops are stack-balanced do-nothing register saves.
	pushPopNops = [][]byte{
		{0x50, 0x58},             // push rax; pop rax
		{0x53, 0x5B},             // push rbx; pop rbx
		{0x51, 0x59},             // push rcx; pop rcx
		{0x52, 0x5A},             // push rdx; pop rdx
		{0x56, 0x5E},             // push rsi; pop rsi
		{0x57, 0x5F},             // push rdi; pop rdi
		{0x41, 0x50, 0x41, 0x58}, // push r8; pop r8
		{0x41, 0x54, 0x41, 0x5C}, // push r12; pop r12
	}
	// flagDecoys clobber flags and a register; they are only ever emitted
	// wrapped in pushfq/popfq with a register-restoring partner, so the net
	// effect on both flags and registers is nil.
	flagDecoys = [][]byte{
		{0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC8},                   // inc rax; dec rax
		{0x48, 0xFF, 0xC1, 0x48, 0xFF, 0xC9},                   // inc rcx; dec rcx
		{0x48, 0xF7, 0xD0, 0x48, 0xF7, 0xD0},                   // not rax; not rax
		{0x48, 0x83, 0xC0, 0x07, 0x48, 0x83, 0xE8, 0x07},       // add rax, 7; sub rax, 7
		{0x48, 0x87, 0xC0, 0x48, 0xF7, 0xD0, 0x48, 0xF7, 0xD0}, // xchg rax,rax; not rax; not rax
	}
)

// snippetOpaquePredicate emits an always-taken jump over junk bytes. The junk is
// never executed, so it can be anything; the jump itself does not touch EFLAGS.
func snippetOpaquePredicate(a *Assembler, rng *rand.Rand, nopLen int) {
	skip := a.NewLabel()
	JmpRel8(a, skip)
	a.EmitBytes(junkBytes(rng, nopLen))
	a.Bind(skip)
}

// snippetFlagSandwich emits pushfq / decoy / popfq: the decoy freely clobbers a
// register and flags, and both are restored before the following instruction.
func snippetFlagSandwich(a *Assembler, rng *rand.Rand) {
	a.Emit(0x9C) // pushfq
	a.EmitBytes(flagDecoys[rng.IntN(len(flagDecoys))])
	a.Emit(0x9D) // popfq
}

// snippetJunkCall emits a call to the very next instruction followed by a stack
// balance, wrapped in a flag sandwich. The "function" returns immediately.
func snippetJunkCall(a *Assembler) {
	a.Emit(0x9C)                   // pushfq
	a.Emit(0xE8, 0, 0, 0, 0)       // call $+5 (targets the next instruction)
	a.Emit(0x48, 0x83, 0xC4, 0x08) // add rsp, 8  (discard the return address)
	a.Emit(0x9D)                   // popfq
}

// junkBytes produces a run of harmless filler bytes.
func junkBytes(rng *rand.Rand, n int) []byte {
	var out []byte
	for len(out) < n {
		out = append(out, nopEncodings[rng.IntN(len(nopEncodings))]...)
	}
	return out
}

// DeadCode inserts inert instruction sequences into a payload.
//
// Insertion is only performed at instruction boundaries, and because every
// relative operand is relocated by BuildStream the inserted bytes may sit
// anywhere in the stream without invalidating a single branch. Payloads whose
// control flow cannot be resolved are not rewritten at all; the caller decides
// whether to append instead (see Trailing).
func DeadCode(b []byte, rng *rand.Rand, opts DeadCodeOptions) ([]byte, *DeadCodeStats, error) {
	stats := &DeadCodeStats{ByKind: map[string]int{}}
	instrs := Disassemble(b)
	ok, reason := Relocatable(instrs)
	if !ok {
		if !opts.Trailing {
			return nil, stats, &NotRewritableError{Reason: reason}
		}
		stats.AppendOnly = true
		stats.Reason = reason
		extra, kind := deadCodePrologue(rng, opts)
		out := append(append([]byte(nil), b...), extra...)
		stats.Insertions = 1
		stats.BytesAdded = len(out) - len(b)
		stats.ByKind[string(kind)] = 1
		return out, stats, nil
	}

	targets := map[int]bool{}
	for i := range instrs {
		if instrs[i].HasTarget {
			targets[instrs[i].Target] = true
		}
	}

	edits := map[int]Edit{}
	// Short branches bound how much may be inserted inside their range, so the
	// planner spends a budget rather than discovering the overflow when the
	// stream is rebuilt.
	budget := NewBranchBudget(instrs)
	stats.Constrained = budget.Bounded()
	for i := range instrs {
		if stats.Insertions >= opts.MaxInsertions {
			break
		}
		if !instrs[i].Decoded {
			continue
		}
		// Do not split a branch from its target: it is legal (the target just
		// relocates), but it makes the injected code far easier to filter out.
		if targets[instrs[i].Off] {
			continue
		}
		if rng.Float64() > clamp01(opts.Probability) {
			continue
		}
		snip, kind := deadCodePrologue(rng, opts)
		if len(snip) == 0 {
			continue
		}
		if !budget.Allow(instrs[i].Off, len(snip)) {
			stats.SitesRejected++
			continue
		}
		budget.Commit(instrs[i].Off, len(snip))
		edits[i] = Edit{Before: snip}
		stats.Insertions++
		stats.BytesAdded += len(snip)
		stats.Sites = append(stats.Sites, instrs[i].Off)
		stats.ByKind[string(kind)]++
	}

	out := b
	if len(edits) > 0 {
		built, _, err := BuildStream(instrs, edits)
		if err != nil {
			return nil, stats, err
		}
		out = built
	}
	// Fall back to a trailing append only when nothing was inserted at a real
	// site. Appending unconditionally would be gratuitous: a snippet after the
	// final terminator makes the payload stop ending at a terminator, which a
	// later control-flow flattening pass then has to refuse. The fallback still
	// covers the two cases that need it -- a payload whose sampling happened to
	// select no sites, and (above) a payload whose control flow cannot be
	// resolved at all.
	if opts.Trailing && stats.Insertions == 0 {
		extra, kind := deadCodePrologue(rng, opts)
		if len(extra) > 0 {
			out = append(append([]byte(nil), out...), extra...)
			stats.Insertions++
			stats.BytesAdded += len(extra)
			stats.ByKind[string(kind)]++
		}
	}
	return out, stats, nil
}

// deadCodePrologue picks one snippet at random and assembles it.
func deadCodePrologue(rng *rand.Rand, opts DeadCodeOptions) ([]byte, SnippetKind) {
	a := NewAssembler()
	switch rng.IntN(4) {
	case 0:
		n := opts.MinNops
		if opts.MaxNops > opts.MinNops {
			n += rng.IntN(opts.MaxNops - opts.MinNops + 1)
		}
		a.EmitBytes(junkBytes(rng, n))
		return a.MustBytes(), SnippetNopSled
	case 1:
		a.EmitBytes(pushPopNops[rng.IntN(len(pushPopNops))])
		a.EmitBytes(junkBytes(rng, 1+rng.IntN(3)))
		return a.MustBytes(), SnippetNoOp
	case 2:
		snippetOpaquePredicate(a, rng, 2+rng.IntN(6))
		snippetFlagSandwich(a, rng)
		return a.MustBytes(), SnippetOpaque
	default:
		snippetJunkCall(a)
		a.EmitBytes(junkBytes(rng, rng.IntN(3)))
		return a.MustBytes(), SnippetJunkCall
	}
}
