package analysis

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pobf/internal/encode"
	"pobf/internal/pipeline"
	_ "pobf/internal/stages"
	"pobf/internal/testpe"
	"pobf/internal/x86"
	"pobf/internal/yara"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// pePayload is a structurally valid PE32+ image with a high-entropy .text
// section and four kernel32 imports. It is the "real artifact" fixture: the
// ruleset detects it on import names, on section entropy and on the injection
// import pair, which is what makes the before/after deltas meaningful.
func pePayload() []byte { return testpe.Build(true) }

// codePayload is pure, decodable x86-64 with no embedded data. 416 bytes built
// by repeating the two assembled fixtures, which keeps the branch displacement
// inside each copy correct. It is the "shellcode-shaped" fixture: the
// instruction-level stages (polymorph, deadcode, cff) can only run on something
// like this.
func codePayload(t *testing.T) []byte {
	t.Helper()
	one, err := os.ReadFile(filepath.Join("..", "x86", "testdata", "prog1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := os.ReadFile(filepath.Join("..", "x86", "testdata", "prog2.bin"))
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for i := 0; i < 8; i++ {
		out = append(out, one...)
		out = append(out, two...)
	}
	return out
}

func rules(t *testing.T) *yara.Ruleset {
	t.Helper()
	rs, err := yara.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// loadFixture reads one of the shipped shape fixtures. They are assembled from
// testdata/*.asm by `make fixtures` and committed, so a missing file is a setup
// problem and is reported as one.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("%v (run `make fixtures` to regenerate the testdata payloads)", err)
	}
	if len(b) == 0 {
		t.Fatalf("testdata/%s is empty", name)
	}
	return b
}

// stagesFor builds freshly constructed stages, which is what a caller of the
// HTTP API does per request and what keeps the benchmark fair.
func stagesFor(t *testing.T, seed int64, names ...string) []pipeline.Stage {
	t.Helper()
	ctx := pipeline.NewContext(seed, pipeline.DefaultOptions(), nil)
	out := make([]pipeline.Stage, 0, len(names))
	for _, n := range names {
		st, err := pipeline.NewStage(n, ctx)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, st)
	}
	return out
}

func analyze(t *testing.T, label string, payload []byte, names ...string) *Report {
	t.Helper()
	a := New(rules(t))
	rep, err := a.Analyze(label, payload, stagesFor(t, 1, names...), Options{
		Rounds: 1, Seed: 1, Scan: true, Verify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// ---------------------------------------------------------------------------
// profiling
// ---------------------------------------------------------------------------

func TestProfileEntropyBounds(t *testing.T) {
	zeros := ProfileBytes(make([]byte, 4096))
	if zeros.Entropy != 0 {
		t.Errorf("entropy of an all-zero blob = %v, want 0", zeros.Entropy)
	}
	if zeros.ZeroRatio != 1 {
		t.Errorf("zero ratio = %v, want 1", zeros.ZeroRatio)
	}
	if zeros.StructuredChunkRatio != 1 {
		t.Errorf("an all-zero blob is entirely structured, got %v", zeros.StructuredChunkRatio)
	}

	rng := rand.New(rand.NewSource(1))
	random := make([]byte, 8192)
	rng.Read(random)
	p := ProfileBytes(random)
	if p.Entropy < 7.9 {
		t.Errorf("entropy of 8 KiB of random = %v, want ~8", p.Entropy)
	}
	if p.DistinctBytes != 256 {
		t.Errorf("distinct bytes = %d, want 256", p.DistinctBytes)
	}
	if p.StructuredChunkRatio > 0.05 {
		t.Errorf("random data should have almost no low-entropy chunks, got %v", p.StructuredChunkRatio)
	}

	text := ProfileBytes(bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 40))
	if text.PrintableRatio != 1 {
		t.Errorf("printable ratio of prose = %v, want 1", text.PrintableRatio)
	}
	if text.Entropy >= 5 {
		t.Errorf("prose entropy = %v, want well under 5", text.Entropy)
	}
}

func TestProfileLocatesHighEntropyChunk(t *testing.T) {
	// Three low-entropy chunks, then one random chunk, then more zeroes. The
	// peak must land on chunk 3 and the structure ratio must reflect that most
	// chunks are still structured.
	blob := make([]byte, ChunkSize*5)
	rng := rand.New(rand.NewSource(9))
	rng.Read(blob[3*ChunkSize : 4*ChunkSize])
	p := ProfileBytes(blob)
	if p.PeakChunk != 3 {
		t.Errorf("peak chunk = %d, want 3", p.PeakChunk)
	}
	if p.PeakChunkEntropy < 7 {
		t.Errorf("peak chunk entropy = %v, want ~8", p.PeakChunkEntropy)
	}
	if p.StructuredChunkRatio != 0.8 {
		t.Errorf("structured ratio = %v, want 0.8 (4 of 5 chunks)", p.StructuredChunkRatio)
	}
	if len(p.ChunkEntropy) != 5 {
		t.Errorf("got %d chunk entropies, want 5", len(p.ChunkEntropy))
	}
}

func TestProfileDeltaHelpers(t *testing.T) {
	a := ProfileBytes(make([]byte, 10))
	b := ProfileBytes(bytes.Repeat([]byte{0xAA}, 25))
	if got := a.SizeDelta(b); got != 15 {
		t.Errorf("SizeDelta = %d, want 15", got)
	}
	if got := a.Growth(b); got != 2.5 {
		t.Errorf("Growth = %v, want 2.5", got)
	}
	if got := a.EntropyDelta(b); got != 0 {
		t.Errorf("EntropyDelta = %v, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// diff visualisation
// ---------------------------------------------------------------------------

func TestDiffMarksOnlyChangedLanes(t *testing.T) {
	before := bytes.Repeat([]byte{0x00}, 32)
	after := append([]byte(nil), before...)
	after[0] = 0xFF
	after[17] = 0x01

	out := Diff(before, after, 32)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected a header plus two rows and two marker lines, got %d lines:\n%s", len(lines), out)
	}
	// Marker rows carry the same ten-column indent as the hex rows; subtract it
	// so a caret's column is directly the lane's byte offset.
	const indent = 10
	markers := lines[2]
	if got := strings.Index(markers, "^") - indent; got != 0 {
		t.Errorf("first row should mark lane 0, got caret at %d in %q", got, markers)
	}
	if got := strings.Count(markers, "^"); got != 1 {
		t.Errorf("first row should mark exactly one lane, got %q", markers)
	}
	markers = lines[4]
	// The second row covers offsets 16..31, so offset 17 is row-local lane 1,
	// which starts three columns in (the caret plus two characters per lane).
	if got := strings.Index(markers, "^") - indent; got != 3 {
		t.Errorf("second row should mark offset 17 at column 3, got caret at %d in %q", got, markers)
	}
	if !strings.Contains(out, "32 bytes before, 32 bytes after") {
		t.Errorf("expected a size footer, got:\n%s", out)
	}
}

func TestDiffHandlesTruncation(t *testing.T) {
	out := Diff(bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{1}, 400), 16)
	if !strings.Contains(out, "8 bytes before, 400 bytes after") {
		t.Errorf("truncation footer missing:\n%s", out)
	}
	// Only one 16-byte row may be printed even though the "after" blob is much
	// longer, and the missing lanes must not be marked as changed.
	if got := strings.Count(out, "000000"); got != 1 {
		t.Errorf("expected exactly one row, got %d:\n%s", got, out)
	}
	if strings.Contains(out, "^") {
		t.Errorf("identical prefixes must not be marked changed:\n%s", out)
	}
}

func TestStructuralDiffReportsPeaks(t *testing.T) {
	before := ProfileBytes(make([]byte, 1024))
	after := ProfileBytes(bytes.Repeat([]byte{0x5A}, 1024))
	out := StructuralDiff(before, after)
	if !strings.Contains(out, "peak chunk") {
		t.Errorf("structural diff should report peak chunks:\n%s", out)
	}
	if !strings.Contains(out, "low-entropy chunks") {
		t.Errorf("structural diff should report the structure ratio:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// stage measurement
// ---------------------------------------------------------------------------

func TestAnalyzeRecordsEncodingStages(t *testing.T) {
	rep := analyze(t, "pe", pePayload(), "strings")

	if len(rep.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(rep.Steps))
	}
	s := rep.Steps[0]
	if s.Skipped {
		t.Fatalf("the strings stage should run on a PE full of API names: %s", s.SkipReason)
	}
	if s.StubKind != "machine-code" {
		t.Errorf("strings stub_kind = %q, want machine-code", s.StubKind)
	}
	if s.Delta <= 0 {
		t.Errorf("the strings stage adds a container and a stub, so delta should be positive, got %d", s.Delta)
	}
	if len(s.Cleared) == 0 {
		t.Error("the strings stage must clear the API-name rules it rewrote")
	}
	for _, want := range []string{"suspicious_api_names", "wide_suspicious_api_names", "pe_injection_imports"} {
		if !contains(s.Cleared, want) {
			t.Errorf("expected %s to be cleared, cleared = %v", want, s.Cleared)
		}
	}
	if !contains(s.Added, "decoder_literal_rebuild_loop") {
		t.Errorf("the shipped rebuild stub should be detected, added = %v", s.Added)
	}
	if rep.DetectionAfter >= rep.DetectionBefore {
		t.Errorf("detection rate did not drop: %v -> %v", rep.DetectionBefore, rep.DetectionAfter)
	}
	if !rep.Verified {
		t.Errorf("strings is reversible, so self-extraction should verify; notes = %v", rep.Notes)
	}
}

func TestAnalyzeRecordsInstructionLevelStages(t *testing.T) {
	payload := codePayload(t)

	poly := analyze(t, "code", payload, "polymorph")
	if poly.Steps[0].Skipped {
		t.Fatalf("polymorph should run on pure code: %s", poly.Steps[0].SkipReason)
	}
	subs, _ := poly.Steps[0].Details["substitutions"].(int)
	if subs < 15 {
		t.Errorf("got %d substitutions on a 416-byte code image, want at least 15", subs)
	}
	byRule, _ := poly.Steps[0].Details["by_rule"].(map[string]int)
	if len(byRule) < 4 {
		t.Errorf("expected at least 4 distinct substitution rules to fire, got %v", byRule)
	}
	if poly.Steps[0].Delta <= 0 {
		t.Errorf("polymorphic rewriting conserves length only when no morph grows; this fixture grows, delta = %d", poly.Steps[0].Delta)
	}

	dc := analyze(t, "code", payload, "deadcode")
	if dc.Steps[0].Skipped {
		t.Fatalf("deadcode should run on pure code: %s", dc.Steps[0].SkipReason)
	}
	ins, _ := dc.Steps[0].Details["insertions"].(int)
	if ins == 0 {
		t.Error("deadcode reported zero insertions")
	}
	kinds, _ := dc.Steps[0].Details["by_kind"].(map[string]int)
	if len(kinds) != 4 {
		t.Errorf("expected four kinds of inert sequence, got %v", kinds)
	}

	cff := analyze(t, "code", payload, "cff")
	if cff.Steps[0].Skipped {
		t.Fatalf("cff should run on pure code: %s", cff.Steps[0].SkipReason)
	}
	blocks, _ := cff.Steps[0].Details["blocks"].(int)
	states, _ := cff.Steps[0].Details["states"].(int)
	if blocks < 10 || states != blocks {
		t.Errorf("blocks = %d, states = %d; want at least 10 blocks and one state each", blocks, states)
	}
	order, _ := cff.Steps[0].Details["block_order"].([]int)
	if !isPermutation(order, blocks) {
		t.Errorf("block order is not a permutation of 0..%d: %v", blocks-1, order)
	}
	// The point of flattening is that the emitted order is not the original one.
	if isSorted(order) {
		t.Errorf("block order came out sorted, which means no shuffling happened: %v", order)
	}
	if cff.Steps[0].Delta <= blocks {
		t.Errorf("flattening should add a dispatcher and a jump table; delta = %d for %d blocks", cff.Steps[0].Delta, blocks)
	}
}

func TestAnalyzeRecordsRefusalAsSkip(t *testing.T) {
	// A PE is not a decodable instruction stream, so the instruction-level
	// stages must refuse rather than corrupt it.
	for _, name := range []string{"polymorph", "cff"} {
		rep := analyze(t, "pe", pePayload(), name)
		s := rep.Steps[0]
		if !s.Skipped {
			t.Fatalf("%s should refuse a PE payload", name)
		}
		if s.SkipReason == "" {
			t.Errorf("%s skipped without a reason", name)
		}
		if s.OutSize != s.InSize {
			t.Errorf("%s changed the payload size while skipping: %d -> %d", name, s.InSize, s.OutSize)
		}
		if s.DetectionsAfter != s.DetectionsBefore {
			t.Errorf("%s changed the detection count while skipping", name)
		}
		var noted bool
		for _, n := range rep.Notes {
			if strings.Contains(n, name) && strings.Contains(n, "skipped") {
				noted = true
			}
		}
		if !noted {
			t.Errorf("a skip must be recorded in the notes, got %v", rep.Notes)
		}
	}
}

// TestEndToEndOnTheShippedFixtures is the whole-pipeline assertion: the two
// committed payload shapes are pushed through the recommended pipeline and the
// measured detection rate has to fall, with the artifact rescanned independently
// rather than trusted from the report.
//
// The two fixtures exercise the two regimes the engine has to handle, and the
// test states both outcomes explicitly:
//
//	shellcode.bin    pure, relocatable code: every instruction-level stage runs,
//	                 so the results must show a real metamorphic effect
//	loader_table.bin data with the literals a loader leaves behind: the code
//	                 stages must refuse it, and the literal masking has to clear
//	                 the string rules it was built to trip
func TestEndToEndOnTheShippedFixtures(t *testing.T) {
	const threshold = 0.10

	t.Run("relocatable code", func(t *testing.T) {
		rep := analyze(t, "shellcode", loadFixture(t, "shellcode.bin"),
			"polymorph", "deadcode", "cff", "strings", "xor", "base64")

		if rep.Before.Size != len(loadFixture(t, "shellcode.bin")) {
			t.Errorf("report input size %d does not match the fixture", rep.Before.Size)
		}
		if before := ruleCount(rep.DetectionBefore, rep.TotalRules); before < 3 {
			t.Fatalf("the fixture is supposed to look like shellcode; the ruleset fired %d of %d rules\n%s",
				before, rep.TotalRules, rep.Notes)
		}
		if rep.DetectionAfter > threshold {
			t.Errorf("detection after = %.2f, want at most %.2f", rep.DetectionAfter, threshold)
		}
		// The three instruction-level stages must actually run: this fixture is
		// pure code, so a refusal here is a bug rather than a property of the
		// input.
		for _, name := range []string{"polymorph", "deadcode", "cff"} {
			step := stepByName(t, rep, name)
			if step.Skipped {
				t.Errorf("%s refused a relocatable code fixture: %s", name, step.SkipReason)
			}
		}
		if subs, _ := stepByName(t, rep, "polymorph").Details["substitutions"].(int); subs < 10 {
			t.Errorf("only %d substitutions on a payload full of NOPs and arithmetic", subs)
		}
		if blocks, _ := stepByName(t, rep, "cff").Details["blocks"].(int); blocks < 5 {
			t.Errorf("only %d basic blocks were flattened", blocks)
		}

		// Independent verification of the verdict.
		fired := scanCount(t, rep.AfterBlob)
		if fired != int(rep.DetectionAfter*float64(rep.TotalRules)+0.5) {
			t.Errorf("rescanning the artifact fires %d rules; the report says %.2f of %d",
				fired, rep.DetectionAfter, rep.TotalRules)
		}
		if rate := Rate(fired, rep.TotalRules); rate > threshold {
			t.Errorf("independently measured detection rate = %.2f, want at most %.2f", rate, threshold)
		}
		if rep.After.Size <= rep.Before.Size {
			t.Error("the pipeline reported no growth, which cannot be right with a dispatcher and two decoder stubs")
		}
	})

	t.Run("literal table", func(t *testing.T) {
		rep := analyze(t, "loader_table", loadFixture(t, "loader_table.bin"),
			"strings", "xor", "base64")

		if before := ruleCount(rep.DetectionBefore, rep.TotalRules); before < 5 {
			t.Fatalf("the fixture is supposed to trip the string rules; only %d of %d fired\n%s",
				before, rep.TotalRules, rep.Notes)
		}
		if rep.DetectionAfter > threshold {
			t.Errorf("detection after = %.2f, want at most %.2f", rep.DetectionAfter, threshold)
		}
		// The code stages have nothing to work with here and must say so.
		if skipped := analyze(t, "loader_table", loadFixture(t, "loader_table.bin"), "polymorph").SkippedStages(); len(skipped) != 1 {
			t.Errorf("a data blob should be refused by the instruction-level stages, got %v", skipped)
		}

		steps := stepByName(t, rep, "strings")
		if steps.Skipped {
			t.Fatalf("the strings stage refused a payload made of printable literals: %s", steps.SkipReason)
		}
		cleared := len(steps.Cleared)
		if cleared < 4 {
			t.Errorf("masking the literals cleared only %d rules, want at least 4: %v", cleared, steps.Cleared)
		}
		if len(steps.Added) != 1 {
			t.Errorf("the rebuild stub should add exactly one rule, got %v", steps.Added)
		}

		fired := scanCount(t, rep.AfterBlob)
		if rate := Rate(fired, rep.TotalRules); rate > threshold {
			t.Errorf("independently measured detection rate = %.2f, want at most %.2f (fired: %v)",
				rate, threshold, scanNames(t, rep.AfterBlob))
		}
	})

	// The syscall fixture exists because classifying SYSCALL as a trap made all
	// three instruction-level stages refuse any payload containing one, which is
	// to say every real payload. The stages have to run here, and the instruction
	// has to survive them untouched.
	t.Run("syscall-bearing code", func(t *testing.T) {
		rep := analyze(t, "syscall_stub", loadFixture(t, "syscall_stub.bin"),
			"polymorph", "deadcode", "cff")

		if len(rep.SkippedStages()) != 0 {
			t.Errorf("no stage should decline a payload containing a syscall, got %v", rep.SkippedStages())
		}
		for _, name := range []string{"polymorph", "deadcode", "cff"} {
			if step := stepByName(t, rep, name); step.Skipped {
				t.Errorf("%s refused a payload containing a syscall: %s", name, step.SkipReason)
			}
		}
		if before := scanNames(t, loadFixture(t, "syscall_stub.bin")); len(before) == 0 {
			t.Fatal("the fixture is supposed to trip the direct-syscall rule")
		}
		// Rewriting around a system call is fine; rewriting the call is not.
		if !bytes.Contains(rep.AfterBlob, []byte{0x0F, 0x05}) {
			t.Error("the syscall opcode did not survive the pipeline")
		}
		if rep.DetectionAfter > threshold {
			t.Errorf("detection after = %.2f, want at most %.2f (fired: %v)",
				rep.DetectionAfter, threshold, scanNames(t, rep.AfterBlob))
		}
		// Note deliberately not asserted: whether the direct-syscall rule is
		// cleared. That depends on whether a stage happens to insert between the
		// syscall and the return, which is seed-dependent, and the semantics
		// -preserving stages make no promise about it. Claiming it here would be
		// asserting luck.
	})
}

// ruleCount converts a detection rate back into a rule count. Rates are used
// everywhere else because they survive the ruleset growing; a test that wants to
// say "the fixture trips at least four rules" needs the count.
func ruleCount(rate float64, total int) int { return int(rate*float64(total) + 0.5) }

func stepByName(t *testing.T, rep *Report, name string) Step {
	t.Helper()
	for _, s := range rep.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no step named %q in %v", name, rep.Pipeline)
	return Step{}
}

func scanCount(t *testing.T, b []byte) int {
	t.Helper()
	return len(scanNames(t, b))
}

func scanNames(t *testing.T, b []byte) []string {
	t.Helper()
	f, err := rules(t).Scan(b)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.Rule)
	}
	return out
}

func TestAnalyzeDoesNotClaimVacuousVerification(t *testing.T) { // A pipeline of semantics-preserving stages emits no decoder, so a "round
	// trip" would only echo the bytes back. The report must say that rather than
	// reporting a verified self-extraction.
	rep := analyze(t, "code", codePayload(t), "polymorph", "deadcode")
	if rep.Verified {
		t.Errorf("no decoder was emitted, so Verified must be false; notes = %v", rep.Notes)
	}
	var noted bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "self-extraction is not applicable") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("expected an explanatory note, got %v", rep.Notes)
	}

	// The same holds when every stage declined to run: the payload is byte-for
	// -byte identical, which trivially round-trips.
	skipped := analyze(t, "pe", pePayload(), "polymorph")
	if len(skipped.SkippedStages()) != 1 || !skipped.Steps[0].Skipped {
		t.Fatalf("expected the payload to be refused, steps = %+v", skipped.Steps)
	}
	if skipped.Verified {
		t.Error("a fully skipped pipeline must not report a verified self-extraction")
	}

	// And it holds for a *reversible* stage that declined, which is the case
	// that used to get this wrong: the stage type was reversible, so the report
	// announced "self-extraction failed" for a transform that had never been
	// applied. Nothing was decoded and nothing should be claimed.
	var unprintable []byte
	for i := 0; i < 64; i++ {
		unprintable = append(unprintable, 0x01, 0x02, 0x0B, 0x00)
	}
	declined := analyze(t, "raw", unprintable, "strings")
	if !declined.Steps[0].Skipped {
		t.Skipf("the strings stage chose to mask something here; pick a plainer payload: %+v", declined.Steps[0])
	}
	if declined.Verified {
		t.Error("a declined reversible stage must not produce a verified self-extraction")
	}
	for _, n := range declined.Notes {
		if strings.Contains(n, "self-extraction failed") {
			t.Errorf("a declined stage is not a decode failure; notes = %v", declined.Notes)
		}
	}
}

func TestAnalyzeIsDeterministicForASeed(t *testing.T) {
	first := analyze(t, "pe", pePayload(), "polymorph", "strings", "xor")
	second := analyze(t, "pe", pePayload(), "polymorph", "strings", "xor")
	if !bytes.Equal(first.AfterBlob, second.AfterBlob) {
		t.Fatal("two runs with the same seed produced different bytes")
	}
	if first.DetectionAfter != second.DetectionAfter {
		t.Fatalf("detection drifted between runs: %v vs %v", first.DetectionAfter, second.DetectionAfter)
	}
	if len(first.Steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(first.Steps))
	}
	// A different seed must change the sample, otherwise the "random per run"
	// stages are not actually random.
	a := New(rules(t))
	other, err := a.Analyze("pe", pePayload(), stagesFor(t, 2, "polymorph", "strings", "xor"), Options{Rounds: 1, Seed: 2, Scan: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.AfterBlob, other.AfterBlob) {
		t.Error("a different seed produced identical output")
	}
}

func TestAnalyzeRepeatsWholePipelinePerRound(t *testing.T) {
	a := New(rules(t))
	rep, err := a.Analyze("pe", pePayload(), stagesFor(t, 1, "strings", "xor"), Options{
		Rounds: 3, Seed: 1, Scan: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Steps) != 6 {
		t.Fatalf("got %d steps for 2 stages x 3 rounds, want 6", len(rep.Steps))
	}
	for i, s := range rep.Steps {
		want := i%2 + 1
		if s.Round != i/2+1 {
			t.Errorf("step %d: round = %d, want %d", i, s.Round, i/2+1)
		}
		if s.Index != want {
			t.Errorf("step %d: index = %d, want %d", i, s.Index, want)
		}
	}
	// Verification is only meaningful for a single round: a second round
	// encrypts an already-encrypted container, and the reverse walk would have
	// to know that.
	if rep.Verified {
		t.Error("self-extraction should not claim to verify a multi-round pipeline")
	}
}

func TestEvasionGainEdgeCases(t *testing.T) {
	clean := &Report{DetectionBefore: 0, DetectionAfter: 0}
	if got := clean.EvasionGain(); got != 0 {
		t.Errorf("EvasionGain with nothing detected = %v, want 0", got)
	}
	half := &Report{DetectionBefore: 0.2, DetectionAfter: 0.05}
	if got := half.EvasionGain(); got != 0.75 {
		t.Errorf("EvasionGain = %v, want 0.75", got)
	}
}

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

func TestPermutationEnumeration(t *testing.T) {
	names := []string{"a", "b", "c"}
	if got := len(Permutations(names, 1)); got != 3 {
		t.Errorf("P(3,1) = %d, want 3", got)
	}
	if got := len(Permutations(names, 2)); got != 6 {
		t.Errorf("P(3,2) = %d, want 6", got)
	}
	if got := len(Permutations(names, 3)); got != 6 {
		t.Errorf("P(3,3) = %d, want 6", got)
	}
	if got := len(AllPermutationsUpTo(names, 3)); got != 15 {
		t.Errorf("sum of P(3,k) for k=1..3 = %d, want 15", got)
	}
	if got := Permutations(names, 4); got != nil {
		t.Errorf("asking for more stages than exist should yield nothing, got %d", len(got))
	}
	// Every candidate must be a permutation without repetition.
	for _, c := range Permutations(names, 3) {
		seen := map[string]bool{}
		for _, s := range c {
			if seen[s] {
				t.Errorf("candidate %v repeats %s", c, s)
			}
			seen[s] = true
		}
	}
}

func TestBenchmarkRanksCandidates(t *testing.T) {
	payload := pePayload()
	a := New(rules(t))
	all := pipeline.Names()
	candidates := AllPermutationsUpTo(all, 2)
	if want := len(all) + len(all)*(len(all)-1); len(candidates) != want {
		t.Fatalf("got %d candidates, want %d", len(candidates), want)
	}
	res, err := a.Benchmark("pe", payload, candidates, func(names []string) ([]pipeline.Stage, error) {
		return stagesFor(t, 1, names...), nil
	}, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ranked) != len(candidates) {
		t.Fatalf("ranked %d of %d candidates", len(res.Ranked), len(candidates))
	}
	for _, c := range res.Ranked {
		if c.Error != "" {
			t.Errorf("candidate %v failed: %s", c.Stages, c.Error)
		}
	}
	// The ranking is ascending by the weighted score, so detection rates are
	// non-decreasing.
	for i := 1; i < len(res.Ranked); i++ {
		if res.Ranked[i-1].Score.Weighted() > res.Ranked[i].Score.Weighted() {
			t.Fatalf("ranking is not sorted at %d: %v > %v", i,
				res.Ranked[i-1].Score.Weighted(), res.Ranked[i].Score.Weighted())
		}
	}
	presence := res.StagePresence()
	for _, n := range all {
		if presence[n] == 0 {
			t.Errorf("stage %s never appeared in the candidate set", n)
		}
	}
	// The best candidate must actually be good: this ruleset is beaten by
	// encodings that leave the payload low-entropy and bright.
	best := res.Ranked[0]
	if best.Score.Detection > 0.2 {
		t.Errorf("best candidate %v still detects at %v; expected better", best.Stages, best.Score.Detection)
	}
	var buf bytes.Buffer
	RenderBenchmark(&buf, res)
	for _, want := range []string{"benchmark:", "rank", "average outcome by inclusion"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("benchmark table is missing %q", want)
		}
	}
}

func TestDeadCodeKeepsThePayloadRelocatable(t *testing.T) {
	// Regression: dead code used to append a snippet after the final terminator
	// even when it had already inserted at real sites. That left the payload not
	// ending at a terminator, so a following flattening pass had to refuse it and
	// the recommended stage order silently degraded into a shorter pipeline.
	payload := codePayload(t)
	dc := analyze(t, "code", payload, "deadcode")
	if dc.Steps[0].Skipped {
		t.Fatalf("deadcode refused the fixture: %s", dc.Steps[0].SkipReason)
	}
	instrs := x86.Disassemble(dc.AfterBlob)
	if ok, reason := x86.Relocatable(instrs); !ok {
		t.Fatalf("dead-code output is no longer relocatable: %s", reason)
	}
	if last := &instrs[len(instrs)-1]; !last.Terminates() {
		t.Fatalf("dead-code output ends with %q, not a terminator", last.String())
	}
	// The property that actually matters: a following flattening pass accepts it.
	cff := analyze(t, "code", dc.AfterBlob, "cff")
	if cff.Steps[0].Skipped {
		t.Fatalf("cff refused dead-code output: %s", cff.Steps[0].SkipReason)
	}
}

func TestBenchmarkSurfacesSkips(t *testing.T) {
	// Stage order changes what is possible, and the benchmark has to report that
	// rather than quietly scoring a two-stage pipeline as if both stages ran.
	// On a PE, the instruction-level stages refuse and the literals stage runs:
	//
	//   strings -> cff     cff refuses: strings has wrapped the image in a
	//                      container, so it is no longer a decodable stream
	//   cff -> deadcode    cff refuses outright, deadcode still appends
	//   deadcode -> strings both run
	a := New(rules(t))
	res, err := a.Benchmark("pe", pePayload(),
		[][]string{{"strings", "cff"}, {"cff", "deadcode"}, {"deadcode", "strings"}},
		func(names []string) ([]pipeline.Stage, error) { return stagesFor(t, 1, names...), nil }, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Combination{}
	for _, c := range res.Ranked {
		byName[strings.Join(c.Stages, "->")] = c
	}
	if got := byName["strings->cff"].Skipped; len(got) != 1 || got[0] != "cff" {
		t.Errorf("strings->cff should report cff as skipped, got %v", got)
	}
	if got := byName["cff->deadcode"].Skipped; len(got) != 1 || got[0] != "cff" {
		t.Errorf("cff->deadcode should report cff as skipped, got %v", got)
	}
	if got := byName["deadcode->strings"].Skipped; len(got) != 0 {
		t.Errorf("deadcode->strings should run both stages, got skipped=%v", got)
	}
	// A degraded pipeline must not silently outrank one where every stage ran.
	if byName["strings->cff"].Score.Detection > byName["deadcode->strings"].Score.Detection {
		t.Errorf("the pipeline that degraded (%.2f) scores better than the one that ran fully (%.2f)",
			byName["strings->cff"].Score.Detection, byName["deadcode->strings"].Score.Detection)
	}
}

// TestReportsThatAPEInputProducesAContainer covers the one claim about a PE that
// is easy to get wrong: what comes out is a container, not a PE.
//
// Every stage accepts a PE and every encoding stage hands the original image
// back byte for byte, so the round trip really is "verified". But a PE loader
// reads the import table and the data directories before any decoder of ours
// runs, so the artefact cannot be loaded or jumped into -- and a report that
// says "verified" without saying that is telling the operator something false.
func TestReportsThatAPEInputProducesAContainer(t *testing.T) {
	rep := analyze(t, "pe", pePayload(), "strings", "base64")

	if got := rep.Steps[0].PayloadKind; got != "pe" {
		t.Errorf("first stage payload_kind = %q, want %q", got, "pe")
	}
	// The second stage's input is the first stage's container, not the PE.
	if got := rep.Steps[1].PayloadKind; got != "raw" {
		t.Errorf("second stage payload_kind = %q, want %q (its input is a container)", got, "raw")
	}

	var noted bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "not a loadable file") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("the report must state that the artefact is a container; notes = %v", rep.Notes)
	}

	// And it must remain true that the original image comes back exactly, so
	// the warning is a caveat rather than a confession of data loss. Decode the
	// artefact independently, using only the public encode API.
	if !rep.Verified {
		t.Errorf("a reversible pipeline over a PE must verify its self-extraction; notes = %v", rep.Notes)
	}
	inner, err := encode.DecodeBase64Image(rep.AfterBlob)
	if err != nil {
		t.Fatalf("DecodeBase64Image: %v", err)
	}
	got, err := encode.DecodeStringImage(inner)
	if err != nil {
		t.Fatalf("DecodeStringImage: %v", err)
	}
	if !bytes.Equal(got, pePayload()) {
		t.Errorf("the artefact does not decode back to the original PE: %d bytes back, %d in",
			len(got), len(pePayload()))
	}
}

// ---------------------------------------------------------------------------
// rendering and serialisation
// ---------------------------------------------------------------------------

func TestRenderAndJSONAgreeOnTheHeadlineNumbers(t *testing.T) {
	rep := analyze(t, "pe", pePayload(), "strings", "base64")

	var text bytes.Buffer
	Render(&text, rep)
	out := text.String()
	for _, want := range []string{
		"summary", "size", "entropy", "detections", "evasion",
		"stages", "structural diff", "byte diff", "detections before", "detections after",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report is missing the %q section", want)
		}
	}
	if !strings.Contains(out, "->") {
		t.Error("the rendered pipeline should show the stage order")
	}

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.DetectionBefore != rep.DetectionBefore || back.DetectionAfter != rep.DetectionAfter {
		t.Errorf("detection rates did not survive a JSON round trip: %v/%v vs %v/%v",
			back.DetectionBefore, back.DetectionAfter, rep.DetectionBefore, rep.DetectionAfter)
	}
	if back.After.Size != rep.After.Size || back.Before.Size != rep.Before.Size {
		t.Error("sizes did not survive a JSON round trip")
	}
	if back.BeforeBlob != nil || back.AfterBlob != nil {
		t.Error("the raw payloads must not be serialised into the report")
	}
	if len(back.Steps) != len(rep.Steps) {
		t.Fatalf("steps did not survive the round trip: %d vs %d", len(back.Steps), len(rep.Steps))
	}
	if len(back.Steps[0].Cleared) != len(rep.Steps[0].Cleared) {
		t.Error("cleared-rule lists did not survive the round trip")
	}
}

func TestWriteReportToFile(t *testing.T) {
	rep := analyze(t, "pe", pePayload(), "xor")
	dir := t.TempDir()
	textPath := filepath.Join(dir, "report.txt")
	if err := WriteText(textPath, rep); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("summary")) {
		t.Error("report file is missing the summary")
	}

	jsonPath := filepath.Join(dir, "report.json")
	f, err := os.Create(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(f, rep); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, err = os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("report JSON is not valid: %v", err)
	}
	if probe["label"] != "pe" {
		t.Errorf("label = %v, want pe", probe["label"])
	}
}

func TestAnalyzerWithoutScannerReportsShapeOnly(t *testing.T) {
	a := New(nil)
	rep, err := a.Analyze("pe", pePayload(), stagesFor(t, 1, "base64"), Options{Rounds: 1, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalRules != 0 || len(rep.FindingsAfter) != 0 {
		t.Error("a scanner-less analyzer must not report detections")
	}
	if rep.After.Size <= rep.Before.Size {
		t.Error("static shape should still be measured")
	}
	if rep.EvasionGain() != 0 {
		t.Error("EvasionGain is meaningless without detection and must be zero")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func isPermutation(order []int, n int) bool {
	if len(order) != n {
		return false
	}
	seen := make([]bool, n)
	for _, v := range order {
		if v < 0 || v >= n || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func isSorted(order []int) bool {
	for i := 1; i < len(order); i++ {
		if order[i-1] > order[i] {
			return false
		}
	}
	return true
}
