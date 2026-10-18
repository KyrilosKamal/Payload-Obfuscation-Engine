package x86

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// relKind distinguishes the two x86-64 constructs whose encoding depends on the
// instruction's position.
type relKind uint8

const (
	relNone relKind = iota
	// relBranch is a relative branch displacement (JMP/Jcc/CALL/LOOP rel8|rel32).
	relBranch
	// relRIP is a RIP-relative memory displacement ([RIP+disp32]).
	relRIP
)

func (k relKind) String() string {
	switch k {
	case relBranch:
		return "branch"
	case relRIP:
		return "rip-relative"
	}
	return "none"
}

// relativeOperand reports whether the instruction carries a position-dependent
// displacement, and the buffer offset it currently points at.
//
// This is what makes a size-changing transform safe: instead of guessing where
// the displacement lives, the decoder already told us (Inst.PCRel records the
// length of the PC-relative field) and the operand type tells us what it means.
func relativeOperand(in *Instr) (relKind, int, bool) {
	if !in.Decoded {
		return relNone, 0, false
	}
	for _, a := range in.Inst.Args {
		if a == nil {
			continue
		}
		switch v := a.(type) {
		case x86asm.Rel:
			return relBranch, in.Off + in.Len + int(v), true
		case x86asm.Mem:
			if v.Base == x86asm.RIP {
				return relRIP, in.Off + in.Len + int(v.Disp), true
			}
		}
	}
	return relNone, 0, false
}

// relFieldSize is the width in bytes of the position-dependent field.
func relFieldSize(in *Instr) int {
	if in.Inst.PCRel > 0 {
		return in.Inst.PCRel
	}
	return 4
}

// Edit describes a modification to one instruction position in a stream.
type Edit struct {
	// Before is emitted immediately before this instruction.
	Before []byte
	// After is emitted immediately after this instruction.
	After []byte
	// Emit, when non-nil, replaces the instruction's encoding. Len must give
	// the replacement's size so that offsets can be computed before emission.
	// The closure receives a resolver mapping an original instruction offset to
	// its new offset.
	Emit func(res resolveFunc) ([]byte, error)
	// Len is the size of the replacement produced by Emit.
	Len int
}

// BuildStream re-emits an instruction stream with optional per-instruction
// edits and patches every position-dependent operand.
//
// It returns the new bytes and a slice mapping an instruction's original offset
// to its new offset. This is the shared foundation of dead-code insertion,
// polymorphic rewriting and control-flow flattening: in all three cases bytes
// move, and a stale relative displacement is the difference between a working
// payload and a crashed process.
func BuildStream(instrs []Instr, edits map[int]Edit) ([]byte, map[int]int, error) {
	// Pass 1: compute new offsets (depends only on sizes).
	newOff := make([]int, len(instrs))
	pos := 0
	for i := range instrs {
		e := edits[i]
		pos += len(e.Before)
		newOff[i] = pos
		switch {
		case e.Emit != nil:
			if e.Len < 0 {
				return nil, nil, fmt.Errorf("edit %d: negative replacement length", i)
			}
			pos += e.Len
		default:
			pos += instrs[i].Len
		}
		pos += len(e.After)
	}

	// Original offset -> new offset, for relocation of relative operands.
	byOldOff := make(map[int]int, len(instrs))
	for i := range instrs {
		byOldOff[instrs[i].Off] = newOff[i]
	}
	resolve := func(oldOff int) (int, bool) {
		v, ok := byOldOff[oldOff]
		return v, ok
	}

	// Pass 2: emit and fix up.
	buf := make([]byte, 0, pos)
	for i := range instrs {
		e := edits[i]
		buf = append(buf, e.Before...)
		start := len(buf)

		var enc []byte
		if e.Emit != nil {
			out, err := e.Emit(resolve)
			if err != nil {
				return nil, nil, fmt.Errorf("instruction %d at %#x: %w", i, instrs[i].Off, err)
			}
			if len(out) != e.Len {
				return nil, nil, fmt.Errorf("instruction %d at %#x: Emit produced %d bytes, Len says %d",
					i, instrs[i].Off, len(out), e.Len)
			}
			enc = out
		} else {
			enc = instrs[i].Raw
			buf = append(buf, enc...)
			if err := patchRelativeOperand(buf, start, &instrs[i], resolve); err != nil {
				return nil, nil, err
			}
			buf = append(buf, e.After...)
			continue
		}
		buf = append(buf, enc...)
		buf = append(buf, e.After...)
	}
	return buf, byOldOff, nil
}

// DisplacementError reports that a length change pushed a short branch out of
// the ±127 byte range its encoding allows.
//
// The byte-adding stages consult BranchBudget before they place anything, so
// reaching this means the payload has a branch pattern the budget did not model.
// It is a refusal, not a bug: the caller must not emit a stream it cannot
// relocate, and the stage layer turns it into a skip with this reason.
type DisplacementError struct {
	Instr string
	Off   int
	Rel   int
}

func (e *DisplacementError) Error() string {
	return fmt.Sprintf("x86: %s at %#x needs a wider displacement after relocation (%d)",
		e.Instr, e.Off, e.Rel)
}

// patchRelativeOperand rewrites the PC-relative field of an instruction copied
// verbatim into its new position.
func patchRelativeOperand(buf []byte, newStart int, in *Instr, resolve func(int) (int, bool)) error {
	kind, oldTarget, ok := relativeOperand(in)
	if !ok {
		return nil
	}
	size := relFieldSize(in)
	fieldAt := newStart + in.Len - size
	if fieldAt < 0 || fieldAt+size > len(buf) {
		return fmt.Errorf("x86: relative field out of range for %s at %#x", in.String(), in.Off)
	}
	newTarget, ok := resolve(oldTarget)
	if !ok {
		// The displacement points outside the instruction stream. For a
		// self-contained payload this means either external/unresolved control
		// flow or data being misread as code; either way we must not silently
		// emit a payload that no longer works.
		return fmt.Errorf("x86: %s at %#x has %s target %#x outside the stream",
			in.String(), in.Off, kind, oldTarget)
	}
	rel := newTarget - (newStart + in.Len)
	switch size {
	case 1:
		if rel < -128 || rel > 127 {
			return &DisplacementError{Instr: in.String(), Off: in.Off, Rel: rel}
		}
		buf[fieldAt] = byte(int8(rel))
	case 4:
		binary.LittleEndian.PutUint32(buf[fieldAt:], uint32(int32(rel)))
	default:
		return fmt.Errorf("x86: unsupported relative field width %d", size)
	}
	return nil
}

// Relocatable reports whether a payload can be safely re-laid-out: every byte
// decodes, no instruction jumps through a register or memory operand, and every
// branch target lands inside the stream.
//
// Returns a description of the first blocker found so the stage can explain why
// it refused to touch a payload instead of emitting something broken.
func Relocatable(instrs []Instr) (bool, string) {
	for i := range instrs {
		in := &instrs[i]
		if !in.Decoded {
			return false, fmt.Sprintf("undecodable byte at offset %#x (data regions cannot be relocated)", in.Off)
		}
		if in.IsIndirect {
			return false, fmt.Sprintf("indirect transfer %q at offset %#x (target unknowable statically)", in.String(), in.Off)
		}
		if in.IsTrap {
			return false, fmt.Sprintf("trap instruction %q at offset %#x", in.String(), in.Off)
		}
		kind, target, ok := relativeOperand(in)
		if !ok {
			continue
		}
		if _, found := offsetIndex(instrs, target); !found {
			return false, fmt.Sprintf("%s at offset %#x points at %#x, which is not an instruction boundary",
				kind, in.Off, target)
		}
	}
	return true, ""
}

func offsetIndex(instrs []Instr, off int) (int, bool) {
	for i := range instrs {
		if instrs[i].Off == off {
			return i, true
		}
	}
	return 0, false
}

// CFG is the control-flow graph recovered from a linear sweep.
type CFG struct {
	Instrs []Instr
	// Index maps an instruction offset to its index in Instrs.
	Index map[int]int
	// Targets holds every offset that is the destination of a branch.
	Targets map[int]bool
	// Indirect counts transfers whose destination is not statically known.
	Indirect int
	// External counts branches whose target lies outside the buffer.
	External int
	// Blocks are the basic blocks in original address order.
	Blocks []Block
}

// Block is a maximal straight-line run of instructions.
type Block struct {
	Index  int
	Start  int   // offset of the first instruction
	End    int   // offset just past the last instruction
	Instrs []int // indices into CFG.Instrs
	// Succ lists successor block indices (fallthrough and branch targets).
	Succ []int
}

// LastInstr returns the index of the block's final instruction.
func (b *Block) LastInstr() int { return b.Instrs[len(b.Instrs)-1] }

// Analyze builds the CFG.
func Analyze(instrs []Instr) *CFG {
	cfg := &CFG{
		Instrs:  instrs,
		Index:   make(map[int]int, len(instrs)),
		Targets: map[int]bool{},
	}
	for i := range instrs {
		cfg.Index[instrs[i].Off] = i
	}
	for i := range instrs {
		in := &instrs[i]
		if in.IsIndirect {
			cfg.Indirect++
		}
		kind, target, ok := relativeOperand(in)
		if !ok {
			continue
		}
		if kind == relRIP {
			// A RIP-relative data reference is relocatable but is not a
			// control-flow edge.
			continue
		}
		if _, found := cfg.Index[target]; found {
			cfg.Targets[target] = true
		} else {
			cfg.External++
			cfg.Targets[target] = true
		}
	}
	cfg.buildBlocks()
	return cfg
}

// Leaders returns the set of basic-block entry offsets.
func (cfg *CFG) Leaders() map[int]bool {
	leaders := map[int]bool{}
	if len(cfg.Instrs) == 0 {
		return leaders
	}
	leaders[cfg.Instrs[0].Off] = true
	for i := range cfg.Instrs {
		in := &cfg.Instrs[i]
		if in.HasTarget {
			leaders[in.Target] = true
		}
		if (in.IsCond || in.IsCall || in.IsJmp) && in.FallThrough < cfg.endOffset() {
			leaders[in.FallThrough] = true
		}
	}
	return leaders
}

func (cfg *CFG) endOffset() int {
	if len(cfg.Instrs) == 0 {
		return 0
	}
	last := cfg.Instrs[len(cfg.Instrs)-1]
	return last.Off + last.Len
}

func (cfg *CFG) buildBlocks() {
	if len(cfg.Instrs) == 0 {
		return
	}
	leaders := cfg.Leaders()
	var cur *Block
	for i := range cfg.Instrs {
		in := &cfg.Instrs[i]
		if leaders[in.Off] {
			if cur != nil {
				cfg.Blocks = append(cfg.Blocks, *cur)
			}
			cur = &Block{Index: len(cfg.Blocks), Start: in.Off, Instrs: []int{i}}
		} else if cur == nil {
			cur = &Block{Index: len(cfg.Blocks), Start: in.Off, Instrs: []int{i}}
		} else {
			cur.Instrs = append(cur.Instrs, i)
		}
		cur.End = in.Off + in.Len
		if in.Terminates() || in.IsCond {
			cfg.Blocks = append(cfg.Blocks, *cur)
			cur = nil
		}
	}
	if cur != nil {
		cfg.Blocks = append(cfg.Blocks, *cur)
	}
	// Successors.
	for bi := range cfg.Blocks {
		b := &cfg.Blocks[bi]
		last := &cfg.Instrs[b.LastInstr()]
		if last.IsCond {
			if t, ok := cfg.Index[last.Target]; ok {
				b.Succ = append(b.Succ, cfg.blockOf(t))
			}
			if last.FallThrough < cfg.endOffset() {
				if t, ok := cfg.Index[last.FallThrough]; ok {
					b.Succ = append(b.Succ, cfg.blockOf(t))
				}
			}
		} else if last.IsJmp {
			if t, ok := cfg.Index[last.Target]; ok {
				b.Succ = append(b.Succ, cfg.blockOf(t))
			}
		} else if !last.Terminates() {
			if last.FallThrough < cfg.endOffset() {
				if t, ok := cfg.Index[last.FallThrough]; ok {
					b.Succ = append(b.Succ, cfg.blockOf(t))
				}
			}
		}
	}
}

func (cfg *CFG) blockOf(instrIdx int) int {
	off := cfg.Instrs[instrIdx].Off
	for bi := range cfg.Blocks {
		b := &cfg.Blocks[bi]
		if off >= b.Start && off < b.End {
			return bi
		}
	}
	return -1
}
