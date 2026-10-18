//go:build linux && amd64

package x86

import (
	"bytes"
	"fmt"
	"testing"

	"pobf/internal/rng"
	"pobf/internal/x86/native"
)

// The dead-code stage claims that every snippet it injects is *inert*: it leaves
// all general-purpose registers, EFLAGS and the stack exactly as it found them.
// A wrong claim here is invisible in the fixture tests (the fixtures only
// observe the return value and a few registers), so it gets its own harness that
// observes everything.

// probeState is the machine state the probe records.
type probeState struct {
	RSP   uint64
	Regs  map[int]uint64
	Flags uint64
}

// probeSlotIndex assigns each captured value a fixed slot in the output buffer.
var probeCaptured = []int{0, 1, 2, 3, 5, 6, 8, 9, 10, 11, 12, 13, 15}

const probeFlagsSlot = 14

// probeFlags is the EFLAGS image the probe installs before running a snippet:
// CF, PF, AF, ZF and IF set, everything else clear. IF must stay set or the
// process would be running with interrupts disabled.
const probeFlags = uint32(0xAD7)

func probeSlotOffset(i int) int8 { return int8(i * 8) }

// buildStateProbe assembles a function that seeds a known register/flag state,
// runs `snippet`, records the resulting state to the buffer in RDI, and restores
// the callee-saved registers before returning.
//
// R14 is deliberately absent: the Go runtime keeps its g pointer there, and a
// JIT'd function that clobbered it could not return into Go at all. Its
// preservation is covered implicitly by every execution test in this file.
func buildStateProbe(snippet []byte) []byte {
	a := NewAssembler()

	// Spill the callee-saved registers we are about to use as scratch so the Go
	// caller gets them back intact.
	for _, r := range []int{3, 5, 12, 13, 15} { // rbx, rbp, r12, r13, r15
		a.EmitBytes(PushReg(r))
	}

	// Seed the probed registers with distinct, recognisable values.
	for i, r := range probeCaptured {
		a.EmitBytes(MovRegImm64(r, uint64(0x1000_0000_0000_0000)+uint64(i)))
	}

	// Install a known EFLAGS image.
	a.Emit(0x68) // push imm32
	a.Imm32(int32(probeFlags))
	a.Emit(0x9D) // popfq

	a.EmitBytes(snippet)

	// Record the state.
	a.EmitBytes(MemDisp8RM(0x89, true, 4, 7, probeSlotOffset(0))) // mov [rdi+0], rsp
	for i, r := range probeCaptured {
		a.EmitBytes(MemDisp8RM(0x89, true, r, 7, probeSlotOffset(i+1)))
	}
	a.Emit(0x9C) // pushfq
	a.Emit(0x58) // pop rax (rax was already recorded)
	a.EmitBytes(MemDisp8RM(0x89, true, 0, 7, probeSlotOffset(probeFlagsSlot)))

	// Restore the callee-saved registers.
	for _, r := range []int{15, 13, 12, 5, 3} {
		a.EmitBytes(PopReg(r))
	}
	a.Emit(0x31, 0xC0) // xor eax, eax
	a.Emit(0xC3)       // ret
	return a.MustBytes()
}

// runStateProbe executes the probe and decodes the recorded state.
func runStateProbe(t *testing.T, snippet []byte) probeState {
	t.Helper()
	ensureHeadroom()
	reg, err := native.NewRegion(buildStateProbe(snippet))
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	defer func() { _ = reg.Free() }()

	out := make([]byte, (probeFlagsSlot+1)*8)
	native.Call4(uintptr(reg.Base()), uintptr(ptrOf(out)), 0, 0, 0)

	st := probeState{Regs: map[int]uint64{}}
	rd := func(i int) uint64 {
		b := out[i*8 : i*8+8]
		return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	}
	st.RSP = rd(0)
	for i, r := range probeCaptured {
		st.Regs[r] = rd(i + 1)
	}
	st.Flags = rd(probeFlagsSlot)
	return st
}

func (s probeState) String() string {
	return fmt.Sprintf("rsp=%#x flags=%#x regs=%v", s.RSP, s.Flags, s.Regs)
}

// TestSnippetsPreserveState is the contract check for every dead-code snippet:
// executing it must not perturb any probed register, EFLAGS, or RSP.
func TestSnippetsPreserveState(t *testing.T) {
	// Sanity: the control probe really does impose a deterministic state, and
	// the captured flags are the ones we asked for. Without this the comparison
	// below could pass vacuously.
	control := runStateProbe(t, nil)
	if got, want := control.Flags&0xAD7, uint64(probeFlags); got != want {
		t.Fatalf("control probe captured flags %#x, expected the seeded %#x", got, want)
	}
	for i, r := range probeCaptured {
		if got, want := control.Regs[r], uint64(0x1000_0000_0000_0000)+uint64(i); got != want {
			t.Fatalf("control probe read %s as %#x, expected the seeded %#x", RegName(r), got, want)
		}
	}
	if control.Flags&0x40 == 0 {
		t.Fatalf("control probe lost ZF: flags %#x", control.Flags)
	}

	var snippets [][]byte
	snippets = append(snippets, nil) // the control itself must be stable
	for _, e := range nopEncodings {
		snippets = append(snippets, e)
	}
	for _, e := range pushPopNops {
		snippets = append(snippets, e)
	}
	for _, e := range flagDecoys {
		// Bare decoys are expected to clobber flags, so they are only asserted
		// inert inside a flag sandwich.
		a := NewAssembler()
		snippetFlagSandwichWith(a, e)
		snippets = append(snippets, a.MustBytes())
	}
	// Every shape the generator can produce, over many draws.
	for seed := int64(1); seed <= 60; seed++ {
		snip, _ := deadCodePrologue(rng.Derive(seed, "test/deadcode-probe"), DefaultDeadCodeOptions())
		snippets = append(snippets, snip)
	}

	for i, snip := range snippets {
		got := runStateProbe(t, snip)
		if got.RSP != control.RSP {
			t.Errorf("snippet %d (% x): RSP changed from %#x to %#x (stack not balanced)", i, snip, control.RSP, got.RSP)
		}
		if got.Flags != control.Flags {
			t.Errorf("snippet %d (% x): EFLAGS changed from %#x to %#x", i, snip, control.Flags, got.Flags)
		}
		for _, r := range probeCaptured {
			if got.Regs[r] != control.Regs[r] {
				t.Errorf("snippet %d (% x): %s changed from %#x to %#x",
					i, snip, RegName(r), control.Regs[r], got.Regs[r])
			}
		}
	}
}

// snippetFlagSandwichWith is snippetFlagSandwich with an explicit decoy, so the
// probe can exercise every decoy rather than a random sample.
func snippetFlagSandwichWith(a *Assembler, decoy []byte) {
	a.Emit(0x9C) // pushfq
	a.EmitBytes(decoy)
	a.Emit(0x9D) // popfq
}

// TestDeadCodeStageInertness runs the *stage* over a payload and then executes
// the result, which is the end-to-end version of the check above: the reported
// snippets are compiled into a real payload and the payload still computes the
// right answer.
func TestDeadCodeStageInertness(t *testing.T) {
	orig := loadFixture(t, "prog1")
	opts := DefaultDeadCodeOptions()
	opts.Probability = 1.0
	out, stats, err := DeadCode(orig, rng.Derive(5, "test/deadcode-stage"), opts)
	if err != nil {
		t.Fatalf("dead code: %v", err)
	}
	if stats.Insertions == 0 {
		t.Fatal("expected insertions at a probability of 1.0")
	}
	if bytes.Equal(out, orig) {
		t.Fatal("expected the payload to change")
	}
	assertSameSemantics(t, "prog1", 5, orig, out)
}
