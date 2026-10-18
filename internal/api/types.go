package api

import "pobf/internal/analysis"

// Report is the analysis layer's per-run report, re-exported so that callers of
// this package can decode a response without importing the analysis package
// directly. The JSON encoding is identical.
type Report = analysis.Report

// Request is the per-run configuration accepted by /v1/obfuscate, /v1/analyze
// and /v1/benchmark.
//
// The zero value is not valid: a run must name its stages. Everything else has a
// documented default, so a caller only sends what it wants to change.
type Request struct {
	// Label names the run in the report. It defaults to the uploaded filename.
	Label string `json:"label"`

	// Stages is the ordered pipeline. Required, and the order matters: a
	// polymorphic rewriter placed after an encoding stage finds nothing to
	// rewrite, because the bytes are no longer a decodable instruction stream.
	Stages []string `json:"stages"`

	// Rounds repeats the whole pipeline. Default 1, capped at MaxRounds.
	//
	// More than one round disables self-extraction verification: the reverse
	// walk cannot know that a container was built on top of another container.
	Rounds int `json:"rounds"`

	// Seed makes the run reproducible. 0 (the default) means "choose a random
	// seed", and the effective seed is echoed in the response.
	Seed int64 `json:"seed"`

	// Verify walks the emitted decoder stubs backwards and reports whether the
	// original bytes come back. Default true.
	Verify *bool `json:"verify,omitempty"`

	// Scan measures YARA detection before and after each stage. Default true.
	Scan *bool `json:"scan,omitempty"`

	// EmitPayload includes the obfuscated artifact in the response, base64
	// encoded. Default true for /v1/obfuscate and false for /v1/analyze.
	EmitPayload *bool `json:"emit_payload,omitempty"`

	// Render includes a human-readable report in the response as "rendered".
	// Default true.
	Render *bool `json:"render,omitempty"`

	// DiffBytes is the byte-diff window in the rendered report. 0 uses the
	// analysis package's default of 128; negative disables the diff.
	DiffBytes int `json:"diff_bytes,omitempty"`

	// Passphrase seeds the AES stage's PBKDF2 derivation. Empty means "derive a
	// random one and record it in the stub descriptor". Supplying the same
	// passphrase and seed reproduces the same key.
	Passphrase string `json:"passphrase,omitempty"`

	// MinStringLen is the shortest printable run the string stage treats as a
	// literal worth masking. Default 6; lower values catch more strings and
	// mangle more of the payload.
	MinStringLen int `json:"min_string_len,omitempty"`

	// MaxInsertions caps how many dead-code snippets a single deadcode pass may
	// inject. Default 64.
	MaxInsertions int `json:"max_insertions,omitempty"`

	// AllowFlagClobber permits instruction substitutions that change EFLAGS.
	// Off by default, because a substitution is only applied when the following
	// instruction does not read the flags.
	AllowFlagClobber bool `json:"allow_flag_clobber,omitempty"`

	// CFPMaxBlocks caps how many basic blocks control-flow flattening rewrites.
	// 0 means unlimited.
	CFPMaxBlocks int `json:"cfp_max_blocks,omitempty"`

	// MaxStagesPerPipeline is the benchmark's candidate depth. Default 2, which
	// over the seven built-in stages means 49 candidates.
	MaxStagesPerPipeline int `json:"max_stages_per_pipeline,omitempty"`
}

// StageInfo describes one registered stage.
type StageInfo struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	// Reversible reports whether the stage embeds a decoder stub, i.e. whether
	// the engine can walk it backwards. Semantics-preserving stages are not
	// reversible, and pretending otherwise would misreport self-extraction.
	Reversible bool `json:"reversible"`
	// Detailable reports whether the stage publishes structured metadata.
	Detailable bool `json:"detailable"`
}

// RuleInfo describes one rule in the detection oracle.
type RuleInfo struct {
	Name     string   `json:"name"`
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Source   string   `json:"source,omitempty"`
}

// ObfuscateResponse is the payload of /v1/obfuscate and /v1/analyze.
type ObfuscateResponse struct {
	Label  string   `json:"label"`
	Stages []string `json:"pipeline"`

	// Seed is always the effective seed, never 0, so a caller can reproduce the
	// run by sending it back.
	Seed   int64 `json:"seed"`
	Rounds int   `json:"rounds"`

	InputSize    int    `json:"input_size"`
	InputSHA256  string `json:"input_sha256"`
	OutputSize   int    `json:"output_size"`
	OutputSHA256 string `json:"output_sha256"`

	// PayloadBase64 carries the obfuscated artifact when emit_payload is set.
	PayloadBase64 string `json:"payload_base64,omitempty"`

	Report   *Report  `json:"report"`
	Warnings []string `json:"warnings,omitempty"`
	Rendered string   `json:"rendered,omitempty"`
}

// BenchmarkResponse is the payload of /v1/benchmark.
type BenchmarkResponse struct {
	// Pool is the stage pool the candidates were drawn from.
	Pool       []string `json:"pool"`
	Depth      int      `json:"depth"`
	Candidates int      `json:"candidates"`
	Ranked     []Ranked `json:"ranked"`
	Rendered   string   `json:"rendered,omitempty"`
}

// Ranked is one measured pipeline in a benchmark, flattened for JSON so the
// response does not depend on internal package types.
type Ranked struct {
	Stages    []string `json:"stages"`
	Detection float64  `json:"detection_rate"`
	SizeBytes int      `json:"size_bytes"`
	Growth    float64  `json:"growth"`
	Millis    float64  `json:"ms"`
	Skipped   []string `json:"skipped,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// ErrorResponse is the payload of every 4xx/5xx response.
type ErrorResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
	// Hint is set when the caller can fix the request, such as a list of valid
	// stage names after an unknown one.
	Hint string `json:"hint,omitempty"`
}
