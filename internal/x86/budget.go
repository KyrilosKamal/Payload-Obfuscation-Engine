package x86

// BranchBudget tracks how many bytes may still be added at each offset before a
// short (rel8) branch no longer reaches its target.
//
// A rel8 displacement is the one place where "insert some bytes" is not
// unconditional. Inserting a snippet between a `jne` and its target pushes the
// target further away, and past 127 bytes the encoding is simply invalid. The
// engine cannot widen the branch in place -- that would move the target's bytes
// by two, which is exactly the layout being computed -- so the byte-adding
// stages consult a budget first and skip the sites they cannot afford instead of
// discovering the problem after the fact.
//
// A substitution that re-encodes one instruction into a longer equivalent is
// counted the same way, at the instruction's own offset.
type BranchBudget struct {
	spans []branchSpan
}

// branchSpan is the inclusive range of insertion offsets that move one rel8
// branch's target further away, plus the number of bytes that may still be added
// anywhere in that range.
//
// A span is not tracked per offset but per range: two insertions in the same
// range add up, so the budget has to be spent, not just checked.
type branchSpan struct {
	lo, hi int
	slack  int
}

// NewBranchBudget computes the budget for one instruction stream.
func NewBranchBudget(instrs []Instr) *BranchBudget {
	b := &BranchBudget{}
	for i := range instrs {
		in := &instrs[i]
		if !in.Decoded || in.Inst.PCRel != 1 {
			continue // only 8-bit displacements are tight
		}
		kind, target, ok := relativeOperand(in)
		if !ok || kind != relBranch {
			continue
		}
		end := in.Off + in.Len
		disp := target - end
		var lo, hi, slack int
		if disp >= 0 {
			// Forward: the range runs from just after the branch to the target
			// instruction. Inserting immediately before the target moves it too,
			// so the target's own offset is inside the range.
			lo, hi, slack = end, target, 127-disp
		} else {
			// Backward: inserting immediately before the target moves both ends
			// and changes nothing, so the range starts one byte later. Inserting
			// before the branch itself moves only the branch, so its offset is
			// inside the range.
			lo, hi, slack = target+1, in.Off, disp+128
		}
		if slack < 0 {
			slack = 0
		}
		b.spans = append(b.spans, branchSpan{lo: lo, hi: hi, slack: slack})
	}
	return b
}

// Allow reports whether growth bytes may be added at offset at.
func (b *BranchBudget) Allow(at, growth int) bool {
	if growth <= 0 {
		return true
	}
	for i := range b.spans {
		s := &b.spans[i]
		if at < s.lo || at > s.hi {
			continue
		}
		if growth > s.slack {
			return false
		}
	}
	return true
}

// Commit records that growth bytes were added at offset at.
func (b *BranchBudget) Commit(at, growth int) {
	if growth <= 0 {
		return
	}
	for i := range b.spans {
		s := &b.spans[i]
		if at >= s.lo && at <= s.hi {
			s.slack -= growth
		}
	}
}

// Slack reports the largest growth Allow would accept at offset at. It returns
// a very large number when no branch constrains the offset, so callers can
// compare it against a snippet size without special-casing "unbounded".
func (b *BranchBudget) Slack(at int) int {
	out := 1 << 30
	for i := range b.spans {
		s := &b.spans[i]
		if at < s.lo || at > s.hi {
			continue
		}
		if s.slack < out {
			out = s.slack
		}
	}
	return out
}

// Bounded reports whether any rel8 branch constrains this stream at all.
func (b *BranchBudget) Bounded() bool { return len(b.spans) > 0 }
