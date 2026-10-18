package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"pobf/internal/analysis"
	"pobf/internal/pipeline"
	_ "pobf/internal/stages"
	"pobf/internal/testpe"
	"pobf/internal/yara"
)

// evasionThreshold is the detection rate a configured pipeline must reach for
// the integration test to pass. It is a rate rather than a rule count, so adding
// tuning rules to the ruleset does not silently weaken the assertion.
const evasionThreshold = 0.10

// pePayload is a structurally valid PE32+ image with a high-entropy section and
// four kernel32 imports, which the ruleset detects on import names, on section
// entropy and on the injection import pair.
func pePayload() []byte { return testpe.Build(true) }

func newTestServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// multipartRequest builds a multipart/form-data request the way the documented
// curl invocation does: a file part plus an optional "config" JSON field.
func multipartRequest(t *testing.T, url string, payload []byte, filename string, cfg any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("payload", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		b, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := mw.WriteField("config", string(b)); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// post performs a request and returns the status and body. It never fails the
// test, so it is safe to call from a goroutine.
func post(req *http.Request) (int, []byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func do(t *testing.T, req *http.Request) (int, []byte) {
	t.Helper()
	status, body, err := post(req)
	if err != nil {
		t.Fatal(err)
	}
	return status, body
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do(t, req)
}

func decode[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decoding %T from %s: %v", v, body, err)
	}
	return v
}

func mustPost(t *testing.T, ts *httptest.Server, path string, payload []byte, cfg *Request) []byte {
	t.Helper()
	status, body := do(t, multipartRequest(t, ts.URL+path, payload, "p.bin", cfg))
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	return body
}

// countDetections runs the ruleset directly, so no assertion has to trust a
// number the server reported.
func countDetections(t *testing.T, b []byte) int {
	t.Helper()
	rs, err := yara.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	f, err := rs.Scan(b)
	if err != nil {
		t.Fatal(err)
	}
	return len(f)
}

func hasSubstring(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GET endpoints
// ---------------------------------------------------------------------------

func TestHealthReportsTheLoadedCatalog(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := get(t, ts.URL+"/healthz")
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	health := decode[map[string]any](t, body)
	rs, err := yara.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if got := int(health["rules"].(float64)); got != len(rs.Names()) {
		t.Errorf("health reports %d rules, the ruleset has %d", got, len(rs.Names()))
	}
	if got := int(health["stages"].(float64)); got != len(pipeline.Names()) {
		t.Errorf("health reports %d stages, the registry has %d", got, len(pipeline.Names()))
	}
	if health["status"] != "ok" {
		t.Errorf("status = %v", health["status"])
	}
}

func TestStageCatalogMarksCapabilities(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := get(t, ts.URL+"/v1/stages")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	got := decode[struct {
		Count  int         `json:"count"`
		Stages []StageInfo `json:"stages"`
	}](t, body)
	if got.Count != len(pipeline.Names()) {
		t.Fatalf("catalog has %d stages, want %d", got.Count, len(pipeline.Names()))
	}
	byName := map[string]StageInfo{}
	for _, s := range got.Stages {
		byName[s.Name] = s
		if s.Description == "" {
			t.Errorf("stage %s has no description", s.Name)
		}
		if s.Kind == "" {
			t.Errorf("stage %s has no kind", s.Name)
		}
	}
	// The capability flags must match what the stages actually implement: a
	// client that reads "reversible" as "self-extraction is verifiable" has to
	// get the truth.
	for _, name := range []string{"base64", "xor", "aes", "strings"} {
		if !byName[name].Reversible {
			t.Errorf("%s embeds a decoder and should be reported reversible", name)
		}
	}
	for _, name := range []string{"polymorph", "deadcode", "cff"} {
		info, ok := byName[name]
		if !ok {
			t.Fatalf("stage %s missing from the catalog", name)
		}
		if info.Reversible {
			t.Errorf("%s is semantics-preserving, not invertible; it must not claim to be reversible", name)
		}
	}
}

func TestRuleCatalogMatchesTheRuleset(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := get(t, ts.URL+"/v1/rules")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	got := decode[struct {
		Count int        `json:"count"`
		Rules []RuleInfo `json:"rules"`
	}](t, body)
	rs, err := yara.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != len(rs.Rules) {
		t.Fatalf("catalog has %d rules, want %d", got.Count, len(rs.Rules))
	}
	for i, r := range got.Rules {
		if r.Name != rs.Rules[i].Name {
			t.Errorf("rule %d = %s, want %s", i, r.Name, rs.Rules[i].Name)
		}
		if r.Severity == "" {
			t.Errorf("rule %s publishes no severity", r.Name)
		}
	}
}

func TestUnknownRouteAndWrongMethod(t *testing.T) {
	ts := newTestServer(t, Options{})
	if status, body := get(t, ts.URL+"/nope"); status != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404; body = %s", status, body)
	}
	if status, _ := get(t, ts.URL+"/v1/obfuscate"); status != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/obfuscate = %d, want 405", status)
	}
}

// ---------------------------------------------------------------------------
// the headline integration test
// ---------------------------------------------------------------------------

// TestObfuscateDropsDetectionBelowThreshold is the end-to-end proof the project
// is built around: a payload the ruleset recognises is pushed through a
// configured pipeline over real HTTP, and the artifact that comes back is
// independently rescanned to confirm detection actually fell.
func TestObfuscateDropsDetectionBelowThreshold(t *testing.T) {
	ts := newTestServer(t, Options{})
	payload := pePayload()

	status, body := do(t, multipartRequest(t, ts.URL+"/v1/obfuscate", payload, "payload.bin", &Request{
		Stages: []string{"strings", "xor", "base64"},
		Rounds: 1,
		Seed:   7,
	}))
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	resp := decode[ObfuscateResponse](t, body)

	if resp.Seed != 7 {
		t.Errorf("seed = %d, want the requested 7", resp.Seed)
	}
	if resp.Label != "payload" {
		t.Errorf("label = %q, want payload (the filename without its extension)", resp.Label)
	}
	if len(resp.Stages) != 3 {
		t.Fatalf("pipeline = %v, want three stages", resp.Stages)
	}
	if resp.Report == nil {
		t.Fatal("no report in the response")
	}
	if resp.Report.DetectionBefore == 0 {
		t.Fatalf("the fixture is supposed to be detected; the report says %.3f", resp.Report.DetectionBefore)
	}
	if resp.Report.DetectionAfter > evasionThreshold {
		t.Errorf("detection after = %.2f, want at most %.2f\n%s",
			resp.Report.DetectionAfter, evasionThreshold, resp.Rendered)
	}
	if resp.Report.DetectionAfter >= resp.Report.DetectionBefore {
		t.Errorf("detection did not fall: %.2f -> %.2f", resp.Report.DetectionBefore, resp.Report.DetectionAfter)
	}
	if resp.Report.TotalRules != len(yara.MustBuiltin().Names()) {
		t.Errorf("report covers %d rules, the ruleset has %d", resp.Report.TotalRules, len(yara.MustBuiltin().Names()))
	}

	// The report must be honest about what it cost: this pipeline shrinks the
	// detected surface, but it does so by shipping decoder stubs.
	var cleared []string
	for _, s := range resp.Report.Steps {
		cleared = append(cleared, s.Cleared...)
		if s.Skipped {
			t.Errorf("stage %s skipped a payload it should handle: %s", s.Name, s.SkipReason)
		}
	}
	if len(cleared) == 0 {
		t.Error("no rule was reported as cleared, which cannot be right for this fixture")
	}
	if !resp.Report.Verified {
		t.Errorf("a pipeline of reversible stages must verify its own self-extraction; notes = %v", resp.Report.Notes)
	}

	// Independent verification: decode the artifact the server returned and
	// rescan it. This is the assertion that a bug in the reporting layer cannot
	// satisfy.
	artifact, err := base64.StdEncoding.DecodeString(resp.PayloadBase64)
	if err != nil {
		t.Fatalf("the returned payload is not valid base64: %v", err)
	}
	if len(artifact) != resp.OutputSize {
		t.Errorf("artifact is %d bytes, the response claims %d", len(artifact), resp.OutputSize)
	}
	fired := countDetections(t, artifact)
	if got := int(resp.Report.DetectionAfter*float64(resp.Report.TotalRules) + 0.5); fired != got {
		t.Errorf("rescanning the artifact fires %d rules, the report says %.2f of %d",
			fired, resp.Report.DetectionAfter, resp.Report.TotalRules)
	}
	if rate := analysis.Rate(fired, resp.Report.TotalRules); rate > evasionThreshold {
		t.Errorf("independently measured detection rate = %.2f, want at most %.2f", rate, evasionThreshold)
	}
	if resp.OutputSHA256 != digest(artifact) {
		t.Error("the response's hash does not describe the artifact it returned")
	}

	// The rendered report is part of the contract: a caller should not have to
	// reimplement the table.
	for _, want := range []string{"summary", "detections", "stages", "evasion"} {
		if !strings.Contains(resp.Rendered, want) {
			t.Errorf("rendered report is missing %q", want)
		}
	}
}

// TestObfuscateIsReproducibleFromTheReportedSeed states the guarantee the
// response's "seed" field exists to make: the same payload, the same stages and
// the same seed produce the same bytes.
func TestObfuscateIsReproducibleFromTheReportedSeed(t *testing.T) {
	ts := newTestServer(t, Options{})
	payload := pePayload()

	first := decode[ObfuscateResponse](t, mustPost(t, ts, "/v1/obfuscate", payload,
		&Request{Stages: []string{"xor", "base64"}, Seed: 11}))
	second := decode[ObfuscateResponse](t, mustPost(t, ts, "/v1/obfuscate", payload,
		&Request{Stages: []string{"xor", "base64"}, Seed: 11}))
	if first.PayloadBase64 != second.PayloadBase64 {
		t.Fatal("the same seed produced different artifacts")
	}
	if first.OutputSHA256 != second.OutputSHA256 {
		t.Fatalf("hashes differ: %s vs %s", first.OutputSHA256, second.OutputSHA256)
	}

	third := decode[ObfuscateResponse](t, mustPost(t, ts, "/v1/obfuscate", payload,
		&Request{Stages: []string{"xor", "base64"}, Seed: 12}))
	if third.PayloadBase64 == first.PayloadBase64 {
		t.Error("a different seed produced an identical artifact, so the per-run key is not random")
	}

	// An omitted seed is not an error: the server picks one and reports it.
	random := decode[ObfuscateResponse](t, mustPost(t, ts, "/v1/obfuscate", payload,
		&Request{Stages: []string{"base64"}}))
	if random.Seed == 0 {
		t.Error("the response reports seed 0, but 0 means \"choose one\" and the effective seed must be echoed")
	}
}

// ---------------------------------------------------------------------------
// request shapes
// ---------------------------------------------------------------------------

func TestRequestBodyShapesAgree(t *testing.T) {
	ts := newTestServer(t, Options{})
	payload := pePayload()

	multipartResp := decode[ObfuscateResponse](t, mustPost(t, ts, "/v1/obfuscate", payload,
		&Request{Stages: []string{"strings", "base64"}, Rounds: 1, Seed: 3, EmitPayload: ptr(true)}))

	jsonBody, err := json.Marshal(map[string]any{
		"payload_base64": base64.StdEncoding.EncodeToString(payload),
		"stages":         []string{"strings", "base64"},
		"seed":           3,
		"rounds":         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/obfuscate", bytes.NewReader(jsonBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	status, body := do(t, req)
	if status != http.StatusOK {
		t.Fatalf("JSON request: status = %d, body = %s", status, body)
	}
	jsonResp := decode[ObfuscateResponse](t, body)

	req, err = http.NewRequest(http.MethodPost,
		ts.URL+"/v1/obfuscate?stages=strings,base64&seed=3&rounds=1", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	status, body = do(t, req)
	if status != http.StatusOK {
		t.Fatalf("raw request: status = %d, body = %s", status, body)
	}
	rawResp := decode[ObfuscateResponse](t, body)

	if multipartResp.OutputSHA256 != jsonResp.OutputSHA256 || jsonResp.OutputSHA256 != rawResp.OutputSHA256 {
		t.Errorf("the three request shapes disagree: %s / %s / %s",
			multipartResp.OutputSHA256, jsonResp.OutputSHA256, rawResp.OutputSHA256)
	}
	if rawResp.PayloadBase64 == "" {
		t.Error("the raw-body form should still return the artifact by default")
	}
}

func TestAnalyzeReturnsTheReportWithoutTheArtifact(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/analyze", pePayload(), "p.bin",
		&Request{Stages: []string{"base64"}, Seed: 5}))
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	resp := decode[ObfuscateResponse](t, body)
	if resp.PayloadBase64 != "" {
		t.Error("/v1/analyze must not return an artifact")
	}
	if resp.OutputSize == 0 || resp.OutputSHA256 == "" {
		t.Error("the report should still describe the output it produced")
	}
	if resp.Report == nil || len(resp.Report.Steps) != 1 {
		t.Errorf("expected one recorded step, got %+v", resp.Report)
	}
}

func TestMultipartScalarFields(t *testing.T) {
	ts := newTestServer(t, Options{})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("payload", "shellcode.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(pePayload()); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"stages": "strings,base64",
		"seed":   "42",
		"rounds": "1",
		"verify": "true",
		"render": "false",
	} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/obfuscate", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	status, body := do(t, req)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	resp := decode[ObfuscateResponse](t, body)
	if resp.Seed != 42 || resp.Rounds != 1 {
		t.Errorf("scalar fields ignored: seed = %d, rounds = %d", resp.Seed, resp.Rounds)
	}
	if resp.Rendered != "" {
		t.Error("render=false should suppress the rendered report")
	}
	if resp.Label != "shellcode" {
		t.Errorf("label = %q, want shellcode", resp.Label)
	}
}

// ---------------------------------------------------------------------------
// error handling
// ---------------------------------------------------------------------------

func TestConfigurationErrors(t *testing.T) {
	ts := newTestServer(t, Options{})
	payload := pePayload()
	cases := []struct {
		name   string
		cfg    *Request
		status int
		substr string
	}{
		{"no stages", &Request{}, http.StatusBadRequest, "stages"},
		{"unknown stage", &Request{Stages: []string{"base64", "nope"}}, http.StatusBadRequest, "unknown stage"},
		{"too many rounds", &Request{Stages: []string{"base64"}, Rounds: MaxRounds + 1}, http.StatusBadRequest, "rounds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := do(t, multipartRequest(t, ts.URL+"/v1/obfuscate", payload, "p.bin", tc.cfg))
			if status != tc.status {
				t.Fatalf("status = %d, want %d; body = %s", status, tc.status, body)
			}
			if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(tc.substr)) {
				t.Errorf("error body %s does not mention %q", body, tc.substr)
			}
		})
	}

	// An unknown stage should tell the caller what the valid names are.
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/obfuscate", payload, "p.bin",
		&Request{Stages: []string{"nope"}}))
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
	hint := decode[ErrorResponse](t, body).Hint
	for _, want := range []string{"base64", "xor", "polymorph"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q does not list %s", hint, want)
		}
	}
}

func TestEmptyPayloadIsRejected(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/obfuscate", nil, "empty.bin",
		&Request{Stages: []string{"base64"}}))
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", status, body)
	}
	if !strings.Contains(string(body), "zero bytes") {
		t.Errorf("expected an explicit empty-payload message, got %s", body)
	}
}

func TestOversizedPayloadIsRejectedWith413(t *testing.T) {
	ts := newTestServer(t, Options{MaxPayload: 4096})
	big := bytes.Repeat([]byte{0xAB}, 8192)
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/obfuscate", big, "big.bin",
		&Request{Stages: []string{"base64"}}))
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body = %s", status, body)
	}
	if !strings.Contains(string(body), "limit") {
		t.Errorf("expected the limit to be reported, got %s", body)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/obfuscate?stages=base64", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if status, body := do(t, req); status != http.StatusRequestEntityTooLarge {
		t.Errorf("raw oversized body = %d, want 413; body = %s", status, body)
	}
}

func TestStageRefusalIsReportedNotHidden(t *testing.T) {
	ts := newTestServer(t, Options{})
	// A PE is not a decodable instruction stream, so the code-level stages
	// decline it. That is a correct outcome and must show up in the response.
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/obfuscate", pePayload(), "p.bin",
		&Request{Stages: []string{"polymorph"}, Seed: 1}))
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	resp := decode[ObfuscateResponse](t, body)
	if len(resp.Report.Steps) != 1 || !resp.Report.Steps[0].Skipped {
		t.Fatalf("expected the stage to be recorded as skipped, got %+v", resp.Report.Steps)
	}
	if resp.Report.Steps[0].SkipReason == "" {
		t.Error("a skip without a reason is not a useful report")
	}
	if !hasSubstring(resp.Warnings, "declined") {
		t.Errorf("warnings should mention the refusal, got %v", resp.Warnings)
	}
	if resp.OutputSHA256 != resp.InputSHA256 {
		t.Error("a skipped stage must leave the payload byte-for-byte unchanged")
	}
	if resp.Report.Verified {
		t.Error("nothing was encoded, so a verified self-extraction would be vacuous")
	}
}

func TestDetectionIncreaseIsReportedAsAWarning(t *testing.T) {
	// XOR alone turns the payload into high-entropy bytes, which is itself a
	// signature for this ruleset. The response has to say so rather than let the
	// caller assume every stage is an improvement.
	ts := newTestServer(t, Options{})
	resp := decode[ObfuscateResponse](t, mustPost(t, ts, "/v1/analyze", pePayload(),
		&Request{Stages: []string{"xor"}, Seed: 1}))
	if resp.Report.DetectionAfter < resp.Report.DetectionBefore {
		t.Skipf("xor now reduces detection for this fixture (%.2f -> %.2f); no warning expected",
			resp.Report.DetectionBefore, resp.Report.DetectionAfter)
	}
	if !hasSubstring(resp.Warnings, "detection rose") {
		t.Errorf("expected a raised-detection warning, got %v", resp.Warnings)
	}
	if !hasSubstring(resp.Warnings, "newly matching") {
		t.Errorf("expected the newly matching rules to be listed, got %v", resp.Warnings)
	}
}

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

func TestBenchmarkRanksEveryCandidate(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/benchmark", pePayload(), "p.bin", &Request{
		Seed:                 3,
		MaxStagesPerPipeline: 1,
	}))
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", status, body)
	}
	res := decode[BenchmarkResponse](t, body)
	if res.Depth != 1 || res.Candidates != len(pipeline.Names()) {
		t.Fatalf("depth = %d, candidates = %d, pool = %v", res.Depth, res.Candidates, res.Pool)
	}
	if len(res.Ranked) != len(pipeline.Names()) {
		t.Fatalf("ranked %d pipelines, want %d", len(res.Ranked), len(pipeline.Names()))
	}
	seen := map[string]bool{}
	for _, c := range res.Ranked {
		if c.Error != "" {
			t.Errorf("candidate %v failed: %s", c.Stages, c.Error)
		}
		seen[c.Stages[0]] = true
	}
	for _, n := range pipeline.Names() {
		if !seen[n] {
			t.Errorf("stage %s was never benchmarked", n)
		}
	}
	// Detection dominates the ranking metric, so walking the table must not show
	// detection rising.
	for i := 1; i < len(res.Ranked); i++ {
		if res.Ranked[i-1].Detection > res.Ranked[i].Detection+1e-9 {
			t.Fatalf("ranking is not sorted by detection: %v", res.Ranked)
		}
	}
	if res.Ranked[0].Detection > evasionThreshold {
		t.Errorf("best single stage still detects at %.2f; expected at most %.2f\n%s",
			res.Ranked[0].Detection, evasionThreshold, res.Rendered)
	}
	if !strings.Contains(res.Rendered, "average outcome by inclusion") {
		t.Error("the benchmark report should summarise which stages helped")
	}
}

func TestBenchmarkRejectsAnOversizedSearch(t *testing.T) {
	ts := newTestServer(t, Options{MaxCandidates: 8})
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/benchmark", pePayload(), "p.bin", &Request{
		MaxStagesPerPipeline: 2,
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", status, body)
	}
	if !strings.Contains(string(body), "narrow") {
		t.Errorf("the error should tell the caller how to narrow the search, got %s", body)
	}
}

func TestBenchmarkDepthLimit(t *testing.T) {
	ts := newTestServer(t, Options{})
	status, body := do(t, multipartRequest(t, ts.URL+"/v1/benchmark", pePayload(), "p.bin", &Request{
		MaxStagesPerPipeline: MaxStagesPerPipeline + 1,
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", status, body)
	}
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

// TestConcurrentRunsDoNotShareState runs many obfuscations at once and checks
// each response against a locally recomputed expectation. If two requests shared
// a random source or a stage's recorded details, some artifact would not match.
func TestConcurrentRunsDoNotShareState(t *testing.T) {
	ts := newTestServer(t, Options{MaxConcurrent: 32})
	payload := pePayload()
	names := []string{"strings", "xor", "base64"}
	const workers = 8

	type result struct {
		seed int64
		sha  string
	}
	results := make([]result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seed := int64(100 + i)
			status, body, err := post(multipartRequest(t, ts.URL+"/v1/obfuscate", payload, "p.bin",
				&Request{Stages: names, Seed: seed}))
			if err != nil || status != http.StatusOK {
				t.Errorf("worker %d: status %d, err %v, body %s", i, status, err, body)
				return
			}
			var resp ObfuscateResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Errorf("worker %d: %v", i, err)
				return
			}
			results[i] = result{seed: resp.Seed, sha: resp.OutputSHA256}
		}(i)
	}
	wg.Wait()

	// Recompute each expected artifact with the same seed. A shared stage object
	// or a leaked RNG would make at least one of these mismatch.
	for i, r := range results {
		if r.seed != int64(100+i) {
			t.Errorf("worker %d reported seed %d", i, r.seed)
			continue
		}
		ctx := pipeline.NewContext(r.seed, pipeline.DefaultOptions(), nil)
		var stages []pipeline.Stage
		for _, n := range names {
			st, err := pipeline.NewStage(n, ctx)
			if err != nil {
				t.Fatal(err)
			}
			stages = append(stages, st)
		}
		pl, err := pipeline.New(stages...).Run(payload)
		if err != nil {
			t.Fatal(err)
		}
		if got := digest(pl.Output); got != r.sha {
			t.Errorf("worker %d: concurrent result %s does not match a local run %s", i, r.sha, got)
		}
	}
}

// TestBusyServerRefusesRatherThanQueues pins the backpressure behaviour: with
// one run slot occupied, a second request is told to retry rather than silently
// waiting for an unbounded time.
func TestBusyServerRefusesRatherThanQueues(t *testing.T) {
	sc := &slowScanner{block: make(chan struct{}), entered: make(chan struct{})}
	srv, err := New(Options{MaxConcurrent: 1, Scanner: sc, Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = post(multipartRequest(t, ts.URL+"/v1/obfuscate", pePayload(), "p.bin",
			&Request{Stages: []string{"base64"}}))
	}()
	<-sc.entered // the first request now holds the only slot

	status, body, err := post(multipartRequest(t, ts.URL+"/v1/obfuscate", pePayload(), "p.bin",
		&Request{Stages: []string{"base64"}}))
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", status, body)
	}
	if !strings.Contains(string(body), "busy") {
		t.Errorf("expected a busy message, got %s", body)
	}
	close(sc.block)
	<-done
}

// slowScanner parks inside Scan until released, so a test can hold the server's
// single run slot deterministically instead of racing a sleep.
type slowScanner struct {
	block   chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (s *slowScanner) Scan(b []byte) ([]yara.Finding, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.block
	return nil, nil
}

func (s *slowScanner) Names() []string { return yara.MustBuiltin().Names() }
