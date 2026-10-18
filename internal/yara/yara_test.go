package yara

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestBuiltinRulesetCompiles(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if n := len(rs.Rules); n < 15 || n > 20 {
		t.Fatalf("ruleset has %d rules, want between 15 and 20", n)
	}
	for _, r := range rs.Rules {
		if r.Condition == nil {
			t.Errorf("rule %s has no condition", r.Name)
		}
		if d, _ := r.Meta["description"].(string); d == "" {
			t.Errorf("rule %s has no description meta", r.Name)
		}
		if s, _ := r.Meta["severity"].(string); s == "" {
			t.Errorf("rule %s has no severity meta", r.Name)
		}
	}
}

// suspectBlob is a deliberately naive "malicious-looking" payload: shellcode
// prologue, NOP padding, API names in ascii and UTF-16, a shell path, a standard
// Base64 alphabet and a canonical Base64 run. It is not malware; it exists so
// the scanner has something to detect before any obfuscation runs.
func suspectBlob() []byte {
	var b bytes.Buffer
	b.Write([]byte{0xFC, 0x48, 0x83, 0xE4, 0xF0})                         // cld; and rsp, -16
	b.Write([]byte{0xE8, 0x00, 0x00, 0x00, 0x00, 0x58})                   // call $+5; pop rax
	b.Write([]byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}) // mov rax, gs:[0x60]
	b.Write([]byte{0x0F, 0x05, 0xC3})                                     // syscall; ret
	b.Write(bytes.Repeat([]byte{0x90}, 24))                               // NOP sled
	for _, s := range []string{
		"VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory",
		"GetProcAddress", "LoadLibraryA", "CreateRemoteThread",
		"AmsiScanBuffer", "EtwEventWrite", "ntdll.dll",
		"VirtualAllocEx", "NtUnmapViewOfSection", "QueueUserAPC",
		"/bin/sh", "cmd.exe /c", "-EncodedCommand", "FromBase64String",
		"PAGE_EXECUTE_READWRITE", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	} {
		b.WriteString(s)
		b.WriteByte(0)
	}
	b.WriteString("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLw==")
	return b.Bytes()
}

func TestSuspectBlobFiresManyRules(t *testing.T) {
	rs := MustBuiltin()
	findings, err := rs.Scan(suspectBlob())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Rule] = true
	}
	want := []string{
		"shellcode_x64_common_prologue",
		"shellcode_nop_sled",
		"suspicious_api_names",
		"antimalware_interference",
		"process_injection_api_set",
		"shell_command_strings",
		"powershell_encoded_command",
		"base64_canonical_alphabet_literal",
		"base64_canonical_blob",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("rule %s did not fire on the suspect blob", w)
		}
	}
	if len(findings) < len(want) {
		t.Errorf("got %d findings, want at least %d", len(findings), len(want))
	}
	t.Logf("suspect blob fires %d/%d rules", len(findings), len(rs.Rules))
}

func TestDenseBlobFiresEntropyRules(t *testing.T) {
	rs := MustBuiltin()
	rng := rand.New(rand.NewSource(1))
	blob := make([]byte, 4096)
	rng.Read(blob)
	findings, err := rs.Scan(blob)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Rule] = true
	}
	if !got["pe_high_entropy_body"] {
		t.Error("pe_high_entropy_body did not fire on 4 KiB of random data")
	}
	if !got["high_entropy_blob_without_pe_header"] {
		t.Error("high_entropy_blob_without_pe_header did not fire on 4 KiB of random data")
	}
}

func TestBenignSourceDoesNotFire(t *testing.T) {
	// Ordinary ASCII text (this file's own source, in fact) must not trip the
	// shellcode or API rules. This is the false-positive guard: a ruleset that
	// fires on prose is useless for measuring anything.
	src := []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello, world\")\n}\n" +
		"func add(a, b int) int { return a + b }\n")
	rs := MustBuiltin()
	findings, err := rs.Scan(src)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range findings {
		if f.Rule == "base64_canonical_blob" || f.Rule == "base64_canonical_alphabet_literal" {
			continue
		}
		t.Errorf("benign source fired rule %s", f.Rule)
	}
}
