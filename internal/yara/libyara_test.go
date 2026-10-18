package yara

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"pobf/internal/testpe"
	"pobf/internal/x86"
)

// blobs returns the corpus every engine-level assertion runs against. It is
// deliberately small and hand-chosen: one naive "malicious" payload, ordinary
// source text, an incompressible blob, a zero blob, two PE images and the
// decoder stubs this project actually ships.
func blobs() map[string][]byte {
	rng := rand.New(rand.NewSource(7))
	random := make([]byte, 4096)
	rng.Read(random)
	return map[string][]byte{
		"suspect":      suspectBlob(),
		"benign":       []byte("package main\n\nfunc main() { println(\"hi\") }\n"),
		"random":       random,
		"zeros":        make([]byte, 4096),
		"pe_dense":     peDense(),
		"pe_sparse":    peSparse(),
		"decoder_stub": decoderStubBlob(),
	}
}

func peDense() []byte  { return testpe.Build(true) }
func peSparse() []byte { return testpe.Build(false) }

// moduleCorpus is the blob set used by the pe.* and math.* tests: a dense PE, a
// sparse PE, and a couple of non-PE inputs so the `pe.is_pe` guard is exercised
// in both directions.
func moduleCorpus() map[string][]byte {
	return map[string][]byte{
		"pe_dense":  peDense(),
		"pe_sparse": peSparse(),
		"plain":     []byte("not a portable executable at all"),
		"random":    blobs()["random"],
	}
}

// decoderStubBlob concatenates the decoder stubs the encoding stages really use.
//
// Detecting these is the point of the three decoder_* rules: a payload can be
// perfectly opaque and still be caught by the shape of the loop that has to
// unwrap it. Using the real constructors keeps the corpus honest - if a stub
// changes shape and stops being detected, this blob and the rules' verdicts
// change with it.
func decoderStubBlob() []byte {
	var b []byte
	b = append(b, x86.XORSelfDecodeMultiKeyStub(4, 64, false, false)...)
	var inv [256]byte
	for i := range inv {
		inv[i] = 0xFF
	}
	b = append(b, x86.Base64DecodeStub(&inv, 4, false).Code...)
	b = append(b, x86.StringRedecodeStub(9, 2)...)
	return b
}

// libyaraPython returns an interpreter that can `import yara`, or "".
//
// Cross-validation is a hard requirement of this project, but it must not make
// the test suite unbuildable on a machine without libyara: the checks skip
// instead. Set POE_LIBYARA_PYTHON to pin the interpreter.
func libyaraPython() string {
	candidates := []string{os.Getenv("POE_LIBYARA_PYTHON"), "/tmp/opencode/yv/bin/python", "python3", "python"}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		path, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		if err := exec.Command(path, "-c", "import yara").Run(); err == nil {
			return path
		}
	}
	return ""
}

// libyaraRunner is the reference-side half of the cross-validation. It compiles
// the same rule files libyara would be given and prints one JSON object per
// input file.
const libyaraRunner = `
import json, sys, os
import yara

ruledir, manifest = sys.argv[1], sys.argv[2]
paths = {os.path.basename(p): p for p in sorted(
    os.path.join(ruledir, f) for f in os.listdir(ruledir) if f.endswith(".yar"))}
rules = yara.compile(filepaths=paths)
cases = json.load(open(manifest))
out = {}
for name, path in cases.items():
    try:
        out[name] = sorted(m.rule for m in rules.match(path))
    except Exception as exc:
        out[name] = {"error": str(exc)}
json.dump(out, open(os.path.join(os.path.dirname(manifest), "libyara.json"), "w"))
`

// TestRulesAgreeWithLibyara is the load-bearing correctness test for the
// hand-written rules: every rule must parse in libyara, and both engines must
// reach the same verdict on every blob.
//
// A disagreement is nearly always a bug in this package rather than in the
// rules, because the rules are written to the subset libyara already defines.
func TestRulesAgreeWithLibyara(t *testing.T) {
	py := libyaraPython()
	if py == "" {
		t.Skip("no interpreter with libyara found; set POE_LIBYARA_PYTHON to enable cross-validation")
	}

	dir := t.TempDir()
	cases := map[string]string{}
	for name, blob := range blobs() {
		p := filepath.Join(dir, name+".bin")
		if err := os.WriteFile(p, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		cases[name] = p
	}
	manifest := filepath.Join(dir, "manifest.json")
	data, _ := json.Marshal(cases)
	if err := os.WriteFile(manifest, data, 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "runner.py")
	if err := os.WriteFile(script, []byte(libyaraRunner), 0o644); err != nil {
		t.Fatal(err)
	}

	// The rule files have to be readable from the rule directory the runner
	// compiles, so copy them out of the embed FS.
	const rulesSrc = "rules"
	entries, err := os.ReadDir("rules")
	if err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(dir, rulesSrc)
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("rules", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rulesDir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out, err := exec.Command(py, script, rulesDir, manifest).CombinedOutput()
	if err != nil {
		t.Fatalf("libyara runner failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "libyara.json"))
	if err != nil {
		t.Fatalf("libyara produced no output: %v\n%s", err, out)
	}
	var ref map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ref); err != nil {
		t.Fatalf("decoding libyara output: %v", err)
	}

	ours := MustBuiltin()
	for name, blob := range blobs() {
		var libyara []string
		if err := json.Unmarshal(ref[name], &libyara); err != nil {
			t.Fatalf("libyara reported an error for %s: %s", name, ref[name])
		}
		findings, err := ours.Scan(blob)
		if err != nil {
			t.Fatalf("our scan of %s: %v", name, err)
		}
		var mine []string
		for _, f := range findings {
			mine = append(mine, f.Rule)
		}
		sort.Strings(mine)
		sort.Strings(libyara)
		if strings.Join(mine, ",") != strings.Join(libyara, ",") {
			t.Errorf("verdicts disagree on %s:\n  ours:    %v\n  libyara: %v", name, mine, libyara)
		}
	}
}

// TestEveryBuiltinRuleFiresSomewhere keeps the ruleset from containing rules
// that no input can ever trip. Each rule is a detector; a detector that never
// detects anything in the corpus is either wrong or useless.
func TestEveryBuiltinRuleFiresSomewhere(t *testing.T) {
	rs := MustBuiltin()
	fired := map[string]int{}
	corpus := blobs()
	corpus["suspect_repeated"] = append(append([]byte{}, suspectBlob()...), suspectBlob()...)
	for _, blob := range corpus {
		findings, err := rs.Scan(blob)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			fired[f.Rule]++
		}
	}
	var never []string
	for _, name := range rs.Names() {
		if fired[name] == 0 {
			never = append(never, name)
		}
	}
	if len(never) > 0 {
		t.Errorf("these rules never fired on the test corpus: %s", strings.Join(never, ", "))
	}
	t.Logf("rule coverage over %d blobs: %s", len(corpus), fireCounts(rs, fired))
}

func fireCounts(rs *Ruleset, fired map[string]int) string {
	var b strings.Builder
	for _, name := range rs.Names() {
		fmt.Fprintf(&b, "%s=%d ", name, fired[name])
	}
	return b.String()
}
