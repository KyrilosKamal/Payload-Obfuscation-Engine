package x86

import (
	"bytes"
	"testing"

	"pobf/internal/rng"
)

// tightLoop builds a payload whose backward branch has almost no room left: a
// body of nops followed by `dec rcx; jnz top; ret`.
//
// The point is the rel8 displacement. With a 120-byte body the `jnz` reaches
// back 125 bytes, so only 3 more bytes may be added anywhere inside the loop
// before the encoding is simply invalid. This is the shape that a length-growing
// transform has to notice *before* it commits, not after.
func tightLoop(bodyLen int) []byte {
	a := NewAssembler()
	top := a.NewLabel()
	a.Bind(top)
	a.EmitBytes(bytes.Repeat([]byte{0x90}, bodyLen))
	a.Emit(0x48, 0xFF, 0xC9) // dec rcx
	JccRel8(a, 0x85, top)    // jnz top
	a.Emit(0xC3)             // ret
	return a.MustBytes()
}

func TestBranchBudgetTracksASingleTightBranch(t *testing.T) {
	payload := tightLoop(120)
	instrs := Disassemble(payload)
	b := NewBranchBudget(instrs)
	if !b.Bounded() {
		t.Fatal("a stream with a rel8 backward branch must be reported as bounded")
	}

	// The jnz sits at offset 123 and reaches back to 0, so it has 3 bytes of
	// slack; the offset of the loop top itself is free, because inserting there
	// moves both ends of the branch together.
	const loopTop, mid = 0, 60
	if got := b.Slack(mid); got != 3 {
		t.Fatalf("slack inside the loop = %d, want 3", got)
	}
	if !b.Allow(mid, 3) {
		t.Error("3 bytes should fit")
	}
	if b.Allow(mid, 4) {
		t.Error("4 bytes should not fit")
	}
	if got := b.Slack(loopTop); got < 1<<20 {
		t.Errorf("the loop top is outside the branch's range and should be unconstrained, got %d", got)
	}
	if got := b.Slack(125); got < 1<<20 {
		t.Errorf("after the branch the budget is unconstrained, got %d", got)
	}

	// The budget is spent, not merely checked: two insertions in the same range
	// add up.
	b.Commit(mid, 2)
	if !b.Allow(mid+1, 1) {
		t.Error("1 byte should still fit after spending 2 of 3")
	}
	if b.Allow(mid+1, 2) {
		t.Error("2 bytes should not fit after spending 2 of 3")
	}
	b.Commit(mid+1, 1)
	if b.Allow(mid+2, 1) {
		t.Error("the budget is exhausted, nothing further should fit")
	}
}

func TestBranchBudgetIgnoresWideDisplacements(t *testing.T) {
	// A forward jmp over 200 bytes is rel32 here, so the budget must not invent
	// a constraint. The same holds for a payload with no branches at all.
	a := NewAssembler()
	over := a.NewLabel()
	JmpRel32(a, over)
	a.EmitBytes(bytes.Repeat([]byte{0x90}, 200))
	a.Bind(over)
	a.Emit(0xC3)
	if b := NewBranchBudget(Disassemble(a.MustBytes())); b.Bounded() {
		t.Error("a rel32 jump is not a tight constraint and must not appear in the budget")
	}

	for _, payload := range [][]byte{{}, {0xC3}, bytes.Repeat([]byte{0x90}, 8)} {
		if b := NewBranchBudget(Disassemble(payload)); b.Bounded() {
			t.Errorf("payload % x should be unbounded", payload)
		}
	}
}

func TestDeadCodeNeverOverflowsAShortBranch(t *testing.T) {
	// Regression: insertion used to be planned without regard for the rel8
	// displacement of the branches it straddled, so a payload with a nearly-full
	// short branch made the whole pass fail with "needs a wider displacement".
	// The stage must instead insert everywhere it can afford and report the
	// sites it had to skip.
	payload := tightLoop(120)
	for seed := 1; seed <= 300; seed++ {
		opts := DefaultDeadCodeOptions()
		opts.MaxInsertions = 500
		opts.Probability = 1
		out, stats, err := DeadCode(payload, rng.Derive(int64(seed), "budget/deadcode"), opts)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if len(out) <= len(payload) {
			t.Fatalf("seed %d: nothing was inserted at all", seed)
		}
		if !stats.Constrained {
			t.Fatalf("seed %d: the payload was not reported as constrained", seed)
		}
		if stats.SitesRejected == 0 {
			t.Fatalf("seed %d: the loop body holds 120 sites and only 3 bytes of slack, so some must be rejected", seed)
		}
		instrs := Disassemble(out)
		if ok, bad := IsClean(instrs); !ok {
			t.Fatalf("seed %d: output has %d undecodable bytes", seed, bad)
		}
		if ok, reason := Relocatable(instrs); !ok {
			t.Fatalf("seed %d: output is not relocatable: %s", seed, reason)
		}
	}
}

func TestRewriteNeverOverflowsAShortBranch(t *testing.T) {
	// The same guarantee for the metamorphic rewriter: a substitution that grows
	// an instruction inside a nearly-full short branch must be dropped rather
	// than emitted.
	payload := tightLoop(120)
	for seed := 1; seed <= 300; seed++ {
		opts := DefaultPolymorphicOptions()
		opts.Probability = 1
		out, log, _, err := Rewrite(payload, rng.Derive(int64(seed), "budget/rewrite"), opts)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if len(log) == 0 {
			t.Fatalf("seed %d: a payload of 120 NOPs must be morphed", seed)
		}
		// Only one +2 substitution fits inside 3 bytes of slack.
		grown := 0
		for _, m := range log {
			if m.SizeDelta > 0 {
				grown += m.SizeDelta
			}
		}
		if grown > 3 {
			t.Fatalf("seed %d: morphed %d bytes of growth inside a branch with 3 bytes of slack\n%+v",
				seed, grown, log[:min(len(log), 8)])
		}
		instrs := Disassemble(out)
		if ok, bad := IsClean(instrs); !ok {
			t.Fatalf("seed %d: output has %d undecodable bytes", seed, bad)
		}
		if ok, reason := Relocatable(instrs); !ok {
			t.Fatalf("seed %d: output is not relocatable: %s", seed, reason)
		}
	}
}
