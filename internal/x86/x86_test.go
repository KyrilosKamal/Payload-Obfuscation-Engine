package x86

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pobf/internal/rng"
)

// loadFixture reads a nasm-assembled code-only image (see testdata/*.asm).
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("testdata", name+".bin")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("fixture %s not assembled (run `make fixtures`): %v", p, err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture %s is empty", p)
	}
	return b
}

func findSub(t *testing.T, name string) *Substitution {
	t.Helper()
	for i := range Substitutions {
		if Substitutions[i].Name == name {
			return &Substitutions[i]
		}
	}
	t.Fatalf("substitution %q not in table", name)
	return nil
}

// TestSubstitutionEncodings pins the exact bytes every morph emits.
//
// Semantics are covered by the executable tests; this test exists because
// "plausible but wrong encoding" is the failure mode those tests are worst at
// localising, and a byte-level vector table localises it immediately.
func TestSubstitutionEncodings(t *testing.T) {
	probe := func(int) (int, bool) { return 0, true }
	cases := []struct {
		rule string
		in   []byte
		want []byte
	}{
		{"mov32_0_to_xor", []byte{0xB8, 0, 0, 0, 0}, []byte{0x31, 0xC0}},
		{"mov32_0_to_xor", []byte{0xBF, 0, 0, 0, 0}, []byte{0x31, 0xFF}}, // mov edi,0
		{"mov64_0_to_xor", []byte{0x48, 0xC7, 0xC0, 0, 0, 0, 0}, []byte{0x31, 0xC0}},
		{"mov8_0_to_xor", []byte{0xB0, 0}, []byte{0x30, 0xC0}},
		{"xor_to_mov0", []byte{0x31, 0xC0}, []byte{0xB8, 0, 0, 0, 0}},
		{"xor_to_mov0", []byte{0x48, 0x31, 0xC9}, []byte{0x48, 0xC7, 0xC1, 0, 0, 0, 0}},
		{"add1_to_inc", []byte{0x83, 0xC0, 0x01}, []byte{0xFF, 0xC0}},
		{"sub1_to_dec", []byte{0x83, 0xE8, 0x01}, []byte{0xFF, 0xC8}},
		{"inc_to_add1", []byte{0xFF, 0xC0}, []byte{0x83, 0xC0, 0x01}},
		{"dec_to_sub1", []byte{0xFF, 0xC8}, []byte{0x83, 0xE8, 0x01}},
		{"mov64_to_push_pop", []byte{0x48, 0x89, 0xD8}, []byte{0x53, 0x58}}, // mov rax,rbx
		{"mov64_to_push_pop", []byte{0x48, 0x89, 0xC3}, []byte{0x50, 0x5B}}, // mov rbx,rax
		{"or_to_test", []byte{0x48, 0x09, 0xC0}, []byte{0x48, 0x85, 0xC0}},
		{"test_to_or", []byte{0x48, 0x85, 0xC0}, []byte{0x48, 0x09, 0xC0}},
		{"sub_self_to_xor", []byte{0x29, 0xC0}, []byte{0x31, 0xC0}},
		{"cmp0_to_test", []byte{0x83, 0xF8, 0x00}, []byte{0x85, 0xC0}},
		{"movzx_to_and", []byte{0x0F, 0xB6, 0xC0}, []byte{0x81, 0xE0, 0xFF, 0x00, 0x00, 0x00}},
		{"neg_to_not_inc", []byte{0x48, 0xF7, 0xD8}, []byte{0x48, 0xF7, 0xD0, 0x48, 0xFF, 0xC0}},
		{"shl1_to_add_self", []byte{0xD1, 0xE0}, []byte{0x01, 0xC0}},
		{"add_self_to_shl1", []byte{0x01, 0xC0}, []byte{0xC1, 0xE0, 0x01}},
		{"and_all_ones_to_nop", []byte{0x83, 0xE0, 0xFF}, []byte{}},
		{"add0_to_nop", []byte{0x83, 0xC0, 0x00}, []byte{}},
		{"lea_self_to_mov", []byte{0x48, 0x8D, 0x00}, []byte{0x48, 0x89, 0xC0}},
		{"nop1_to_nop3", []byte{0x90}, []byte{0x0F, 0x1F, 0x00}},
		{"nop3_to_nop2", []byte{0x0F, 0x1F, 0x00}, []byte{0x66, 0x90}},
		{"nop2_to_nop1", []byte{0x66, 0x90}, []byte{0x90}},
		{"xchg_self_to_nop", []byte{0x48, 0x87, 0xC0}, []byte{0x90}},
	}
	for _, tc := range cases {
		instrs := Disassemble(tc.in)
		if len(instrs) == 0 {
			t.Fatalf("%s: input % x did not decode", tc.rule, tc.in)
		}
		in := &instrs[0]
		sub := findSub(t, tc.rule)
		if !sub.Match(in) {
			t.Fatalf("%s: does not match % x (%s)", tc.rule, tc.in, in.String())
		}
		got, err := sub.Emit(in, probe)
		if err != nil {
			t.Fatalf("%s: emit: %v", tc.rule, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s(% x): got % x, want % x", tc.rule, tc.in, got, tc.want)
		}
		if n, err := sub.Size(in); err != nil || n != len(tc.want) {
			t.Errorf("%s: Size = %d (err %v), want %d", tc.rule, n, err, len(tc.want))
		}
	}
}

// TestSubstitutionsAllDecode is a structural sanity check: every morph must emit
// something the disassembler accepts, otherwise the rewriter would produce a
// stream that fails its own clean-decode check.
func TestSubstitutionsAllDecode(t *testing.T) {
	probe := func(int) (int, bool) { return 0, true }
	all := loadAllFixtures(t)
	for si := range Substitutions {
		sub := &Substitutions[si]
		// Pair morphs have no standalone Emit; they are exercised by the
		// rewriter tests instead.
		if sub.Emit == nil || sub.Match == nil {
			continue
		}
		applied := 0
		for _, code := range all {
			decoded := Disassemble(code)
			for i := range decoded {
				in := decoded[i]
				if !sub.Match(&in) {
					continue
				}
				out, err := sub.Emit(&in, probe)
				if err != nil {
					t.Fatalf("%s: emit(%s): %v", sub.Name, in.String(), err)
				}
				if len(out) == 0 {
					applied++
					continue
				}
				back := Disassemble(out)
				if len(back) == 0 || !back[0].Decoded {
					t.Fatalf("%s: emitted bytes % x do not decode", sub.Name, out)
				}
				applied++
			}
		}
		if applied == 0 {
			t.Logf("note: %s never matched the fixtures", sub.Name)
		}
	}
	// The table must satisfy the "at least 15 equivalences" requirement.
	if len(Substitutions) < 15 {
		t.Fatalf("substitution table has %d entries, want at least 15", len(Substitutions))
	}
}

func loadAllFixtures(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	for _, n := range []string{"prog1", "prog2"} {
		out = append(out, loadFixture(t, n))
	}
	return out
}

// TestBuildStreamRelocates verifies that inserting bytes shifts a relative
// branch's displacement correctly. Getting this wrong is the classic way an
// obfuscator produces a payload that crashes only sometimes.
func TestBuildStreamRelocates(t *testing.T) {
	// jmp +1 -> offset 3 (the ret), nop, ret
	orig := []byte{0xEB, 0x01, 0x90, 0xC3}
	instrs := Disassemble(orig)
	if len(instrs) != 3 {
		t.Fatalf("decoded %d instructions, want 3", len(instrs))
	}
	if !instrs[0].IsJmp || instrs[0].Target != 3 {
		t.Fatalf("expected the first instruction to be jmp -> 3, got %s -> %d", instrs[0].String(), instrs[0].Target)
	}
	edits := map[int]Edit{1: {Before: []byte{0x0F, 0x1F, 0x00}}} // 3-byte nop before the second instruction
	out, newMap, err := BuildStream(instrs, edits)
	if err != nil {
		t.Fatalf("BuildStream: %v", err)
	}
	want := []byte{0xEB, 0x04, 0x0F, 0x1F, 0x00, 0x90, 0xC3}
	if !bytes.Equal(out, want) {
		t.Fatalf("got % x, want % x", out, want)
	}
	if newMap[3] != 6 {
		t.Fatalf("old offset 3 mapped to %d, want 6", newMap[3])
	}
	// The branch must still target the ret.
	got := Disassemble(out)
	if !got[0].IsJmp || got[0].Target != 6 {
		t.Fatalf("relocated jump targets %d, want 6", got[0].Target)
	}
}

// TestBuildStreamRejectsUnencodableWidening checks that a rel8 branch which can
// no longer reach its target is an error rather than a silently truncated
// displacement.
func TestBuildStreamRejectsUnencodableWidening(t *testing.T) {
	orig := []byte{0xEB, 0x00, 0x90, 0xC3} // jmp -> offset 2
	instrs := Disassemble(orig)
	big := bytes.Repeat([]byte{0x90}, 200)
	edits := map[int]Edit{1: {Before: big}} // push the target (instruction 1) 200 bytes away
	if _, _, err := BuildStream(instrs, edits); err == nil {
		t.Fatal("expected an error when a rel8 displacement no longer fits")
	}
}

func TestRelocatable(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want bool
	}{
		{"nop;ret", []byte{0x90, 0xC3}, true},
		{"jmp rax", []byte{0xFF, 0xE0}, false},
		{"call rax", []byte{0xFF, 0xD0}, false},
		{"jmp [rip+x]", []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, false},
		{"hlt", []byte{0xF4}, false},
		{"jmp off the end", []byte{0xE9, 0x00, 0x00, 0x00, 0x00}, false},
		{"loop to self", []byte{0xEB, 0xFE}, true},
	}
	for _, tc := range cases {
		ok, reason := Relocatable(Disassemble(tc.code))
		if ok != tc.want {
			t.Errorf("%s: Relocatable = %v (%s), want %v", tc.name, ok, reason, tc.want)
		}
	}
}

func TestAnalyzeBlockCount(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		blocks  int
	}{{"prog1", 3}, {"prog2", 4}} {
		code := loadFixture(t, tc.fixture)
		cfg := Analyze(Disassemble(code))
		if len(cfg.Blocks) != tc.blocks {
			t.Errorf("%s: found %d blocks, want %d", tc.fixture, len(cfg.Blocks), tc.blocks)
			for _, b := range cfg.Blocks {
				t.Logf("  block %d: %#x..%#x instrs=%d succ=%v", b.Index, b.Start, b.End, len(b.Instrs), b.Succ)
			}
		}
		if cfg.Indirect != 0 || cfg.External != 0 {
			t.Errorf("%s: unexpected unresolved flow (indirect=%d external=%d)", tc.fixture, cfg.Indirect, cfg.External)
		}
	}
}

func TestDeadCodeSnippetKindsAreProduced(t *testing.T) {
	code := loadFixture(t, "prog1")
	seen := map[string]bool{}
	for seed := int64(1); seed <= 40; seed++ {
		rng := rng.Derive(seed, "test/deadcode/kinds")
		opts := DefaultDeadCodeOptions()
		opts.Probability = 1.0
		_, stats, err := DeadCode(code, rng, opts)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for k := range stats.ByKind {
			seen[k] = true
		}
	}
	for _, want := range []string{string(SnippetNopSled), string(SnippetNoOp), string(SnippetOpaque), string(SnippetJunkCall)} {
		if !seen[want] {
			t.Errorf("snippet kind %q was never generated", want)
		}
	}
}

// TestObjdumpAgreesWithEmitter validates the emitted stubs with an independent
// disassembler. It is skipped when objdump is unavailable.
func TestObjdumpAgreesWithEmitter(t *testing.T) {
	objdump, err := exec.LookPath("objdump")
	if err != nil {
		t.Skip("objdump not installed")
	}
	code := loadFixture(t, "prog1")
	rewritten, _, _, err := Rewrite(code, rng.Derive(9, "objdump"), DefaultPolymorphicOptions())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	flat, fres, err := Flatten(code, rng.Derive(9, "objdump/cff"), DefaultCFFOptions())
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}

	// A flattened image ends in a data section (the state/target slots and the
	// jump table), which is intentionally not decodable as instructions, so only
	// the code region is handed to objdump.
	blobs := map[string][]byte{
		"xor_decode_func":  XORDecodeFunc(),
		"xor_self_decode":  XORSelfDecodeStub(0x41, 16, true).Code,
		"multi_key_decode": MultiKeyXORDecodeFunc(),
		"rewritten":        rewritten,
		"flattened":        flat[:fres.CodeSize],
	}
	for name, blob := range blobs {
		p := filepath.Join(t.TempDir(), name+".bin")
		if err := os.WriteFile(p, blob, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(objdump, "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", p).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: objdump: %v\n%s", name, err, out)
		}
		// objdump prints "(bad)" for undecodable bytes.
		if strings.Contains(string(out), "(bad)") {
			t.Errorf("%s: objdump found undecodable bytes:\n%s", name, out)
		}
	}
}
