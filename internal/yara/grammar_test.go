package yara

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// crossCheckRules compiles the given rule sources with this engine and, when an
// interpreter with libyara is available, with the reference implementation too,
// then asserts that the two agree on every blob.
//
// It is the single most valuable test in the package: the parser, the matchers.
// the PE reader and `math.*` are all hand-written, and hand-written
// reimplementations of a specified language drift. Agreement on a diverse corpus
// is the only cheap evidence that the drift is absent.
//
// Callers pass one source per rule file, and each source must carry its own
// imports, because libyara resolves imports per file.
func crossCheckRules(t *testing.T, sources []string, corpus map[string][]byte) *Ruleset {
	t.Helper()

	rs := &Ruleset{Imports: map[string]bool{}}
	for i, src := range sources {
		part, err := Parse(src, fmt.Sprintf("case%02d.yar", i))
		if err != nil {
			t.Fatalf("parsing case %d: %v", i, err)
		}
		rs.Rules = append(rs.Rules, part.Rules...)
		for k := range part.Imports {
			rs.Imports[k] = true
		}
	}

	py := libyaraPython()
	if py == "" {
		t.Log("libyara unavailable; cross-check degraded to our engine only")
		return rs
	}

	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, src := range sources {
		p := filepath.Join(rulesDir, fmt.Sprintf("case%02d.yar", i))
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names := make([]string, 0, len(corpus))
	for name := range corpus {
		names = append(names, name)
	}
	sort.Strings(names)
	cases := map[string]string{}
	for _, name := range names {
		p := filepath.Join(dir, name+".bin")
		if err := os.WriteFile(p, corpus[name], 0o644); err != nil {
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
		t.Fatal(err)
	}
	for _, name := range names {
		var want []string
		if err := json.Unmarshal(ref[name], &want); err != nil {
			t.Fatalf("libyara errored on %s: %s", name, ref[name])
		}
		findings, err := rs.Scan(corpus[name])
		if err != nil {
			t.Fatalf("our scan of %s: %v", name, err)
		}
		got := make([]string, 0, len(findings))
		for _, f := range findings {
			got = append(got, f.Rule)
		}
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("blob %s:\n  ours:    %v\n  libyara: %v", name, got, want)
		}
	}
	return rs
}

// fires runs the ruleset and returns the set of rules that matched.
func fires(t *testing.T, rs *Ruleset, blob []byte) map[string]bool {
	t.Helper()
	findings, err := rs.Scan(blob)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	out := map[string]bool{}
	for _, f := range findings {
		out[f.Rule] = true
	}
	return out
}

func TestGrammarTextStrings(t *testing.T) {
	rs := crossCheckRules(t, []string{`
rule t_text {
    strings:
        $a = "Hello"
    condition:
        $a
}
rule t_nocase {
    strings:
        $a = "Hello" nocase
    condition:
        $a
}
rule t_hexesc {
    strings:
        $a = "\x90\x90\x90\x90"
    condition:
        $a
}
rule t_fullword {
    strings:
        $a = "cat" fullword
        $b = "dog" fullword nocase
    condition:
        $a or $b
}
rule t_wide_only {
    strings:
        $a = "zebra" wide
    condition:
        $a
}
rule t_wide_ascii {
    strings:
        $a = "zebra" wide ascii
    condition:
        $a
}
`}, map[string][]byte{
		"exact":       []byte("Hello there"),
		"lower":       []byte("hello there"),
		"upper":       []byte("HELLO"),
		"partial":     []byte("hell"),
		"nops":        []byte{0x90, 0x90, 0x90, 0x90, 0x90},
		"twonops":     []byte{0x90, 0x90},
		"word":        []byte("a cat sat"),
		"embedded":    []byte("concatenate"),
		"dawg":        []byte("DOG!"),
		"wide":        []byte("z\x00e\x00b\x00r\x00a\x00"),
		"wide_split":  []byte("z\x00e\x00b\x00"),
		"ascii_zebra": []byte("a zebra here"),
	})

	// Documented expectations, in addition to the cross-check.
	if got := fires(t, rs, []byte("Hello there")); !got["t_text"] || !got["t_nocase"] {
		t.Error("exact ascii text should fire both t_text and t_nocase")
	}
	if got := fires(t, rs, []byte("hello there")); got["t_text"] || !got["t_nocase"] {
		t.Error("lowercase input should fire only t_nocase")
	}
	if got := fires(t, rs, []byte("a cat sat")); !got["t_fullword"] {
		t.Error("fullword text should match between spaces")
	}
	if got := fires(t, rs, []byte("concatenate")); got["t_fullword"] {
		t.Error("fullword must not match inside a larger word")
	}
	// `wide` on its own searches only the UTF-16LE form; `wide ascii` searches
	// both. This is the reference behaviour and the reason the rules in
	// api_strings.yar ask for `wide ascii` rather than `wide`.
	if got := fires(t, rs, []byte("a zebra here")); got["t_wide_only"] || !got["t_wide_ascii"] {
		t.Error("`wide` alone must not match ascii; `wide ascii` must")
	}
	if got := fires(t, rs, []byte("z\x00e\x00b\x00r\x00a\x00")); !got["t_wide_only"] || !got["t_wide_ascii"] {
		t.Error("both wide rules must match the UTF-16LE form")
	}
}

func TestGrammarHexStrings(t *testing.T) {
	rs := crossCheckRules(t, []string{`
rule t_hex_exact {
    strings:
        $a = { 4D 5A 90 00 }
    condition:
        $a
}
rule t_hex_wildcard {
    strings:
        $a = { 4D 5A ?? 00 }
    condition:
        $a
}
rule t_hex_nibble {
    strings:
        $a = { 4D 5? 90 0? }
    condition:
        $a
}
rule t_hex_alternation {
    strings:
        $a = { 4D ( 5A | 5B 5C ) 90 }
    condition:
        $a
}
rule t_hex_jump {
    strings:
        $a = { 4D [2-4] 90 }
    condition:
        $a
}
rule t_hex_jump_exact {
    strings:
        $a = { 4D [3] 90 }
    condition:
        $a
}
rule t_hex_not {
    strings:
        $a = { 4D ~5A 90 }
    condition:
        $a
}
`}, map[string][]byte{
		"exact":  {0x4D, 0x5A, 0x90, 0x00},
		"wild":   {0x4D, 0x5A, 0x11, 0x00},
		"nib":    {0x4D, 0x5F, 0x90, 0x0A},
		"alt_a":  {0x4D, 0x5A, 0x90},
		"alt_b":  {0x4D, 0x5B, 0x5C, 0x90},
		"alt_c":  {0x4D, 0x5B, 0x90},
		"jump2":  {0x4D, 0x01, 0x02, 0x90},
		"jump5":  {0x4D, 1, 2, 3, 4, 5, 0x90},
		"not5a":  {0x4D, 0x5B, 0x90},
		"not5a2": {0x4D, 0x00, 0x90},
	})

	if got := fires(t, rs, []byte{0x4D, 0x5B, 0x90}); !got["t_hex_not"] {
		t.Error("~5A should match 0x5B")
	}
	if got := fires(t, rs, []byte{0x4D, 0x5A, 0x90}); got["t_hex_not"] {
		t.Error("~5A must not match 0x5A")
	}
	if got := fires(t, rs, []byte{0x4D, 1, 2, 3, 4, 5, 0x90}); got["t_hex_jump"] {
		t.Error("a five-byte gap is outside [2-4]")
	}
	if got := fires(t, rs, []byte{0x4D, 1, 2, 3, 0x90}); !got["t_hex_jump_exact"] {
		t.Error("[3] should match a three-byte gap")
	}
	if got := fires(t, rs, []byte{0x4D, 1, 2, 0x90}); got["t_hex_jump_exact"] {
		t.Error("[3] must not match a two-byte gap")
	}
}

func TestGrammarCountsAndOffsets(t *testing.T) {
	rs := crossCheckRules(t, []string{`
rule t_count {
    strings:
        $a = "ab"
    condition:
        #a == 3
}
rule t_count_ge {
    strings:
        $a = "ab"
    condition:
        #a >= 2
}
rule t_offset {
    strings:
        $a = "wxyz"
    condition:
        @a == 4
}
rule t_offset_indexed {
    strings:
        $a = "ab"
    condition:
        @a[2] == 6
}
rule t_length {
    strings:
        $a = "wxyz"
    condition:
        !a == 4
}
rule t_at {
    strings:
        $a = "wxyz"
    condition:
        $a at 4
}
`}, map[string][]byte{
		"three":       []byte("abxxabxxab"),
		"two":         []byte("abab"),
		"one":         []byte("xxab"),
		"offset4":     []byte("xxxxwxyz"),
		"offset0":     []byte("wxyz"),
		"second_at_6": []byte("abxxxxab"),
		"second_at_5": []byte("abxxxab"),
		"count_mixed": []byte("ab ab ab ab"),
		"overlapping": []byte("ababab"),
	})

	if got := fires(t, rs, []byte("abxxabxxab")); !got["t_count"] || !got["t_count_ge"] {
		t.Error("#a == 3 should hold for three non-overlapping occurrences")
	}
	if got := fires(t, rs, []byte("xxab")); got["t_count"] || got["t_count_ge"] {
		t.Error("#a == 3 must not hold for a single occurrence")
	}
	if got := fires(t, rs, []byte("xxxxwxyz")); !got["t_offset"] || !got["t_at"] || !got["t_length"] {
		t.Error("offset, at and length should all match a four-byte string at offset 4")
	}
	if got := fires(t, rs, []byte("abxxxxab")); !got["t_offset_indexed"] {
		t.Error("@a[2] should be the offset of the second occurrence")
	}
	if got := fires(t, rs, []byte("abxxxab")); got["t_offset_indexed"] {
		t.Error("@a[2] must not be satisfied by an occurrence at offset 5")
	}
}

func TestGrammarQuantifiers(t *testing.T) {
	rs := crossCheckRules(t, []string{`
rule t_of_2 {
    strings:
        $a = "aa"
        $b = "bb"
        $c = "cc"
    condition:
        2 of them
}
rule t_of_any {
    strings:
        $a = "aa"
        $b = "bb"
        $c = "cc"
    condition:
        any of them
}
rule t_of_all {
    strings:
        $a = "aa"
        $b = "bb"
        $c = "cc"
    condition:
        all of them
}
rule t_of_ids {
    strings:
        $a = "aa"
        $c = "cc"
    condition:
        1 of ($a, $c)
}
rule t_of_ids_both {
    strings:
        $a = "aa"
        $c = "cc"
    condition:
        2 of ($a, $c)
}
`}, map[string][]byte{
		"none":  []byte("nothing here"),
		"one":   []byte("only aa"),
		"two":   []byte("aa and bb"),
		"three": []byte("aa bb cc"),
		"pair":  []byte("bb only and nothing else"),
		"ac":    []byte("aa and cc"),
	})

	f := map[string]map[string]bool{}
	for name, blob := range map[string][]byte{
		"none":  []byte("nothing here"),
		"one":   []byte("only aa"),
		"two":   []byte("aa and bb"),
		"three": []byte("aa bb cc"),
		"ac":    []byte("aa and cc"),
	} {
		f[name] = fires(t, rs, blob)
	}
	if f["none"]["t_of_any"] || f["none"]["t_of_2"] {
		t.Error("`any of them` and `2 of them` must be false when nothing matches")
	}
	if !f["one"]["t_of_any"] || f["one"]["t_of_2"] {
		t.Error("one match satisfies `any of them` but not `2 of them`")
	}
	if !f["two"]["t_of_2"] || f["two"]["t_of_all"] {
		t.Error("two of three matches must satisfy `2 of them` but not `all of them`")
	}
	if !f["three"]["t_of_all"] {
		t.Error("`all of them` must hold when every string matches")
	}
	if !f["ac"]["t_of_ids"] || !f["ac"]["t_of_ids_both"] {
		t.Error("`2 of ($a,$c)` must hold when both listed strings match")
	}
	if !f["one"]["t_of_ids"] || f["one"]["t_of_ids_both"] {
		t.Error("`1 of ($a,$c)` holds with one match; `2 of ($a,$c)` does not")
	}
}

func TestGrammarArithmeticAndBuiltins(t *testing.T) {
	crossCheckRules(t, []string{`
rule t_arith {
    strings:
        $a = "aaaa"
    condition:
        #a * 2 == 10
}
rule t_overlap_count {
    strings:
        $a = "aa"
    condition:
        #a == 7
}
rule t_overlap_hex {
    strings:
        $a = { 4D 4D 5A }
    condition:
        #a == 1
}
rule t_jump_shortest {
    strings:
        $a = { 4D [1-3] 90 }
    condition:
        !a == 3
}
rule t_jump_longest {
    strings:
        $a = { 4D [1-3] 90 }
    condition:
        !a == 4
}
rule t_alt_grammar_order {
    strings:
        $a = { 4D ( 5B 5C | 5A ) 90 }
    condition:
        !a == 4
}
rule t_regex_overlap {
    strings:
        $a = /abab/
    condition:
        #a == 3
}
rule t_parens {
    strings:
        $a = "aaaa"
    condition:
        (#a + 1) * 2 == 12
}
rule t_filesize {
    condition:
        filesize == 16
}
rule t_uint {
    condition:
        uint16(0) == 0x5A4D
}
rule t_uint32 {
    condition:
        uint32(0) == 0x02015A4D
}
rule t_uint8 {
    condition:
        uint8(1) == 0x4D
}
rule t_div {
    condition:
        filesize \ 4 == 4
}
rule t_mod {
    condition:
        filesize % 5 == 1
}
`}, map[string][]byte{
		"mz16":     append([]byte{0x4D, 0x5A, 0x01, 0x02}, make([]byte, 12)...),
		"mz15":     append([]byte{0x4D, 0x5A, 0x01, 0x02}, make([]byte, 11)...),
		"aaaa4":    append([]byte("aaaaaaaa"), make([]byte, 8)...),
		"jump1":    {0x4D, 0x01, 0x90, 0x90},
		"ovl_hex":  {0x4D, 0x4D, 0x5A},
		"alt_gram": {0x4D, 0x5B, 0x5C, 0x90},
		"abab4":    []byte("abababab"),
	})

	rs := &Ruleset{Imports: map[string]bool{}}
	src := `rule t_filesize { condition: filesize == 16 }
rule t_uint { condition: uint16(0) == 0x5A4D }
rule t_arith { strings: $a = "aaaa" condition: #a > 0 }
`
	part, err := Parse(src, "inline.yar")
	if err != nil {
		t.Fatal(err)
	}
	rs.Rules = part.Rules
	blob := append([]byte{0x4D, 0x5A}, []byte("aaaaaaaaaaaaaa")...)
	got := fires(t, rs, blob)
	if !got["t_filesize"] || !got["t_uint"] || !got["t_arith"] {
		t.Errorf("expected all three inline rules to fire, got %v", got)
	}
}

func TestGrammarRegex(t *testing.T) {
	rs := crossCheckRules(t, []string{`
rule t_re {
    strings:
        $a = /ab+c/
    condition:
        $a
}
rule t_re_nocase {
    strings:
        $a = /ab+c/ nocase
    condition:
        $a
}
rule t_re_class {
    strings:
        $a = /[0-9]{3}-[0-9]{4}/
    condition:
        $a
}
rule t_re_anchorless_dot {
    strings:
        $a = /MZ./
    condition:
        $a
}
rule t_re_fullword {
    strings:
        $a = /cat/ fullword
    condition:
        $a
}
rule t_re_slashes {
    strings:
        $a = /cmd\/exe/
    condition:
        $a
}
`}, map[string][]byte{
		"abc":     []byte("xxabcyy"),
		"ac":      []byte("xxacyy"),
		"abbbbc":  []byte("abbbbc"),
		"ABC":     []byte("ABC"),
		"phone":   []byte("555-1234"),
		"nonum":   []byte("55-123"),
		"mz":      []byte("MZP"),
		"mz_only": []byte("MZ"),
		"cats":    []byte("concatenate"),
		"cat":     []byte("a cat here"),
		"slashes": []byte("cmd/exe"),
		"noslash": []byte("cmdexe"),
	})

	if got := fires(t, rs, []byte("xxabcyy")); !got["t_re"] {
		t.Error("/ab+c/ should match abc")
	}
	if got := fires(t, rs, []byte("xxacyy")); got["t_re"] {
		t.Error("/ab+c/ requires at least one b")
	}
	if got := fires(t, rs, []byte("ABC")); !got["t_re_nocase"] {
		t.Error("nocase regex should match uppercase")
	}
	if got := fires(t, rs, []byte("MZ")); got["t_re_anchorless_dot"] {
		t.Error("/MZ./ needs a third byte")
	}
	if got := fires(t, rs, []byte("concatenate")); got["t_re_fullword"] {
		t.Error("fullword regex must not match inside a longer word")
	}
	if got := fires(t, rs, []byte("cmd/exe")); !got["t_re_slashes"] {
		t.Error("an escaped slash inside a regex should match a literal slash")
	}
}

func TestGrammarModules(t *testing.T) {
	rs := crossCheckRules(t, []string{`
import "pe"
import "math"

rule t_pe {
    condition:
        pe.is_pe
}
rule t_pe_sections {
    condition:
        pe.number_of_sections == 2
}
rule t_pe_import {
    condition:
        pe.imports("kernel32.dll", "VirtualAlloc")
}
rule t_pe_import_missing {
    condition:
        pe.imports("kernel32.dll", "NoSuchFunction")
}
rule t_pe_machine {
    condition:
        pe.machine == 0x8664
}
rule t_pe_64bit {
    condition:
        pe.is_64bit() and pe.entry_point == 0x200
}
rule t_pe_section_name {
    condition:
        pe.sections[0].name == ".text"
}
rule t_pe_section_props {
    condition:
        pe.sections[1].raw_data_size == 1024 and pe.sections[1].virtual_address == 0x2000
}
rule t_math_entropy {
    condition:
        math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.5
}
rule t_math_mean {
    condition:
        math.mean(0, filesize) > 100
}
`}, moduleCorpus())

	f := fires(t, rs, peDense())
	if !f["t_pe"] || !f["t_pe_sections"] || !f["t_pe_import"] || !f["t_pe_machine"] || !f["t_pe_64bit"] {
		t.Errorf("PE header rules did not all fire on the dense fixture: %v", keys(f))
	}
	if f["t_pe_import_missing"] {
		t.Error("pe.imports must not match a function the image does not import")
	}
	if !f["t_pe_section_name"] {
		t.Error(`pe.sections[0].name should be ".text"`)
	}
	if !f["t_pe_section_props"] {
		t.Error("pe.sections[1] raw size / virtual address mismatch")
	}
	if !f["t_math_entropy"] {
		t.Error("the dense fixture's .text section should have entropy above 7.5")
	}
	f = fires(t, rs, peSparse())
	if f["t_math_entropy"] {
		t.Error("the sparse fixture should not have entropy above 7.5")
	}
	if f["t_pe"] != true {
		t.Error("the sparse fixture is still a PE")
	}
}

func TestGrammarNotPrecedence(t *testing.T) {
	rs := crossCheckRules(t, []string{`
rule t_prec_and_or {
    strings:
        $a = "aa"
        $b = "bb"
    condition:
        not $a and $b
}
rule t_prec_parens {
    strings:
        $a = "aa"
        $b = "bb"
    condition:
        not ($a or $b)
}
rule t_prec_not_not {
    strings:
        $a = "aa"
    condition:
        not not $a
}
`}, map[string][]byte{
		"ab": []byte("aa bb"),
		"a":  []byte("aa only"),
		"b":  []byte("bb only"),
		"ne": []byte("neither"),
	})

	if got := fires(t, rs, []byte("bb only")); !got["t_prec_and_or"] {
		t.Error("`not $a and $b` must hold when only $b matches")
	}
	if got := fires(t, rs, []byte("bb only")); got["t_prec_parens"] {
		t.Error("`not ($a or $b)` must be false when $b matches")
	}
	if got := fires(t, rs, []byte("aa only")); got["t_prec_and_or"] || !got["t_prec_not_not"] {
		t.Error("precedence: `not $a and $b` is false when $a matches; `not not $a` is true")
	}
	if got := fires(t, rs, []byte("aa bb")); got["t_prec_parens"] {
		t.Error("`not ($a or $b)` must be false when both match")
	}
}

func TestParserRejectsBadRules(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"missing condition", `rule r { strings: $a = "x" }`, "no condition"},
		{"undefined string", `rule r { strings: $a = "x" condition: $b }`, "not defined"},
		{"unreferenced string", `rule r { strings: $a = "x" $b = "y" condition: $a }`, "unreferenced"},
		{"duplicate string", `rule r { strings: $a = "x" $a = "y" condition: $a }`, "defined twice"},
		{"empty hex", `rule r { strings: $a = {} condition: $a }`, "empty hex"},
		{"inverted jump", `rule r { strings: $a = { 4D [4-2] } condition: $a }`, "inverted"},
		{"unterminated string", `rule r { strings: $a = "x condition: $a }`, "unterminated"},
		{"for loop", `rule r { condition: for any i in (1..2) : ( true ) }`, "not supported"},
		{"include", `include "other.yar"`, "not supported"},
		{"bad module use", `rule r { condition: pe.is_pe }`, "without importing"},
		{"them without of", `rule r { strings: $a = "x" condition: them }`, "only valid after"},
		{"unknown function", `rule r { condition: nonsense(1) }`, "unknown identifier"},
		{"bad field", `import "pe"
rule r { condition: pe.sections[0].entropy > 1 }`, "unsupported pe.sections property"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.src, "bad.yar")
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParserAcceptsCommentsAndTags(t *testing.T) {
	src := `// a leading comment
/* a block
   comment */
import "pe" // trailing

rule tagged : one two /* inline */ {
    meta:
        author = "someone"
        score  = 5
        draft  = false
    strings:
        $a = "MZ" // not the real thing
    condition:
        $a and not pe.is_pe
}
`
	rs, err := Parse(src, "comments.yar")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs.Rules))
	}
	r := rs.Rules[0]
	if r.Name != "tagged" || len(r.Tags) != 2 {
		t.Fatalf("name/tags = %q/%v", r.Name, r.Tags)
	}
	if r.Meta["score"] != float64(5) || r.Meta["draft"] != false || r.Meta["author"] != "someone" {
		t.Fatalf("meta = %v", r.Meta)
	}
	if !rs.Imports["pe"] {
		t.Fatal("import not recorded")
	}
	got := fires(t, rs, []byte("MZ\x00"))
	if !got["tagged"] {
		t.Error("the rule should fire on a two-byte prefix outside a PE")
	}
	if got := fires(t, rs, peDense()); got["tagged"] {
		t.Error("the rule must not fire on a real PE")
	}
}

func TestScanReportsMatchOffsets(t *testing.T) {
	rs := &Ruleset{Imports: map[string]bool{}}
	part, err := Parse(`
rule offsets {
    strings:
        $a = "abcd"
        $b = { DE AD }
    condition:
        $a and $b
}
`, "offsets.yar")
	if err != nil {
		t.Fatal(err)
	}
	rs.Rules = part.Rules
	findings, err := rs.Scan([]byte("xxabcdxx" + "\xDE\xAD"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if got := f.Matches["$a"]; len(got) != 1 || got[0] != (Match{Offset: 2, Length: 4}) {
		t.Errorf("$a matches = %v", got)
	}
	if got := f.Matches["$b"]; len(got) != 1 || got[0] != (Match{Offset: 8, Length: 2}) {
		t.Errorf("$b matches = %v", got)
	}
	if f.Severity() != "unknown" {
		t.Errorf("severity without meta = %q", f.Severity())
	}
}

func TestGlobalAndPrivateRules(t *testing.T) {
	rs := &Ruleset{Imports: map[string]bool{}}
	part, err := Parse(`
global rule gate {
    condition:
        filesize > 8
}
private rule hidden {
    condition:
        true
}
rule visible {
    condition:
        true
}
`, "global.yar")
	if err != nil {
		t.Fatal(err)
	}
	rs.Rules = part.Rules
	small, err := rs.Scan([]byte("tiny"))
	if err != nil {
		t.Fatal(err)
	}
	if len(small) != 0 {
		t.Errorf("a false global rule must suppress every other rule, got %v", small)
	}
	big, err := rs.Scan([]byte("long enough to pass the gate"))
	if err != nil {
		t.Fatal(err)
	}
	if len(big) != 1 || big[0].Rule != "visible" {
		t.Errorf("got %v, want only `visible`", big)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
