package x86

import (
	"os"
	"path/filepath"
	"testing"

	"pobf/internal/rng"
)

// syscallPayload is a small, inert, relocatable routine that ends in a syscall
// and a return.
//
// It is built here rather than loaded from a fixture so the classifier test is
// self-contained: the point is the classification of one instruction, so the
// test should not depend on `make fixtures` having run.
func syscallPayload() []byte {
	a := NewAssembler()
	a.Emit(0x31, 0xC0)                   // xor eax, eax
	a.Emit(0xB9, 0x08, 0x00, 0x00, 0x00) // mov ecx, 8
	top := a.NewLabel()
	a.Bind(top)
	a.Emit(0x01, 0xC8)                   // add eax, ecx
	a.Emit(0x48, 0xFF, 0xC9)             // dec rcx
	JccRel8(a, 0x85, top)                // jnz top
	a.Emit(0xB8, 0x3C, 0x00, 0x00, 0x00) // mov eax, 60
	a.Emit(0x0F, 0x05)                   // syscall
	a.Emit(0xC3)                         // ret
	return a.MustBytes()
}

// TestSyscallIsFallthroughNotATrap is a regression test for a classification
// that made the code-level stages useless on real input.
//
// SYSCALL enters the kernel and returns to the *following* instruction, so
// control flow continues linearly and everything after it is relocatable.
// Classifying it as a trap (alongside HLT and UD2) meant Relocatable() refused
// any payload containing one -- which is essentially every real payload.
func TestSyscallIsFallthroughNotATrap(t *testing.T) {
	instrs := Disassemble(syscallPayload())

	var sys *Instr
	for i := range instrs {
		if instrs[i].String() == "SYSCALL" {
			sys = &instrs[i]
		}
	}
	if sys == nil {
		t.Fatal("the payload must contain a SYSCALL")
	}
	if sys.IsTrap {
		t.Error("SYSCALL returns to the next instruction; it is not a trap")
	}
	if !sys.IsSyscall {
		t.Error("SYSCALL should be marked IsSyscall so the distinction stays visible")
	}
	if sys.Terminates() {
		t.Error("SYSCALL falls through, so it must not terminate control flow")
	}
	if ok, reason := Relocatable(instrs); !ok {
		t.Errorf("a payload containing a syscall must be relocatable: %s", reason)
	}

	// The instructions that genuinely do not fall through must still refuse.
	for _, raw := range [][]byte{
		{0x0F, 0x07}, // sysret
		{0xF4},       // hlt
		{0x0F, 0x0B}, // ud2
	} {
		in := Disassemble(raw)
		if ok, _ := Relocatable(in); ok {
			t.Errorf("% x should still be treated as non-relocatable", raw)
		}
	}
}

// TestCodeStagesAcceptASyscallPayload checks that all three instruction-level
// stages run on a payload containing a syscall, and that the syscall itself is
// preserved verbatim. Rewriting around a system call is fine; rewriting the
// call is not.
func TestCodeStagesAcceptASyscallPayload(t *testing.T) {
	const label = "syscall"
	payload := syscallPayload()

	out, log, _, err := Rewrite(payload, rng.Derive(3, label+"/polymorph"), DefaultPolymorphicOptions())
	if err != nil {
		t.Fatalf("polymorph refused a payload with a syscall: %v", err)
	}
	if len(log) == 0 {
		t.Error("expected the rewriter to substitute something")
	}
	if !hasBytes(out, 0x0F, 0x05) {
		t.Error("the syscall opcode must survive rewriting verbatim")
	}
	if ok, bad := IsClean(Disassemble(out)); !ok {
		t.Errorf("rewritten payload has %d undecodable bytes", bad)
	}

	dc := DefaultDeadCodeOptions()
	dc.Trailing = true
	out, stats, err := DeadCode(out, rng.Derive(3, label+"/deadcode"), dc)
	if err != nil {
		t.Fatalf("deadcode refused a payload with a syscall: %v", err)
	}
	if stats.Insertions == 0 {
		t.Error("expected dead code to be inserted")
	}
	if !hasBytes(out, 0x0F, 0x05) {
		t.Error("the syscall opcode must survive dead-code insertion")
	}

	out, _, err = Flatten(out, rng.Derive(3, label+"/cff"), DefaultCFFOptions())
	if err != nil {
		t.Fatalf("cff refused a payload with a syscall: %v", err)
	}
	if !hasBytes(out, 0x0F, 0x05) {
		t.Error("the syscall opcode must survive control-flow flattening")
	}
}

// TestSyscallFixtureIsRelocatable guards the shipped fixture: it exists to be
// the thing that catches a regression in the classifier, so it has to be a
// payload the code stages can actually process.
func TestSyscallFixtureIsRelocatable(t *testing.T) {
	p := filepath.Join("..", "..", "testdata", "syscall_stub.bin")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run `make fixtures`)", err)
	}
	instrs := Disassemble(b)
	if ok, bad := IsClean(instrs); !ok {
		t.Fatalf("the fixture has %d undecodable bytes", bad)
	}
	if ok, reason := Relocatable(instrs); !ok {
		t.Fatalf("the fixture is not relocatable: %s", reason)
	}
	if !hasBytes(b, 0x0F, 0x05) {
		t.Fatal("the fixture is supposed to contain a syscall")
	}
}

// hasBytes reports whether seq occurs in b.
func hasBytes(b []byte, seq ...byte) bool {
	if len(seq) == 0 {
		return true
	}
outer:
	for i := 0; i+len(seq) <= len(b); i++ {
		for j := range seq {
			if b[i+j] != seq[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
