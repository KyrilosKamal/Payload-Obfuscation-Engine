// Package api exposes the obfuscation engine over HTTP.
//
// The server is stateless per request: every request constructs its own stages
// against a seeded context, so two callers never share a random source or a
// stage's recorded details. The only shared mutable-free objects are the
// compiled ruleset and the stage catalogue, both computed once at construction.
//
// Endpoints:
//
//	GET  /healthz           liveness plus the size of the stage and rule sets
//	GET  /v1/stages         the stage catalogue with capability flags
//	GET  /v1/rules          the detection ruleset
//	POST /v1/obfuscate      run a pipeline, return the artifact and the report
//	POST /v1/analyze        run a pipeline, return the report only
//	POST /v1/benchmark      rank pipeline permutations by measured evasion
package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"pobf/internal/analysis"
	"pobf/internal/pipeline"
	_ "pobf/internal/stages" // registers the built-in stages
	"pobf/internal/yara"
)

// Limits. These are deliberately hard failures rather than silent truncation: a
// caller that asks for something unreasonable should be told, not placated.
const (
	// DefaultMaxPayload bounds a single upload.
	DefaultMaxPayload = 16 << 20
	// DefaultMaxConcurrent bounds how many runs execute at once. Excess
	// requests are refused with 429 rather than queued. An obfuscation run is
	// CPU-bound, so a queue would only convert load into latency without
	// increasing throughput.
	DefaultMaxConcurrent = 4
	// DefaultMaxCandidates caps a single benchmark request.
	DefaultMaxCandidates = 128
	// MaxRounds caps the repeat count.
	MaxRounds = 32
	// MaxStagesPerPipeline caps the benchmark candidate depth.
	MaxStagesPerPipeline = 6
	// multipartOverhead is added to the payload limit to allow for form fields,
	// boundaries and the config blob.
	multipartOverhead = 1 << 20
)

// Options configures a Server. The zero value is usable.
type Options struct {
	// Scanner is the detection oracle. Nil means "load the built-in ruleset",
	// which is almost always what a caller wants.
	Scanner analysis.Scanner
	// MaxPayload is the largest accepted upload in bytes.
	MaxPayload int64
	// MaxConcurrent is the number of simultaneous runs before the server starts
	// refusing work.
	MaxConcurrent int
	// MaxCandidates caps a single benchmark request.
	MaxCandidates int
	// Logger receives request-level diagnostics. Nil discards them.
	Logger *slog.Logger
}

// Server is an http.Handler for the obfuscation engine.
type Server struct {
	analyzer      *analysis.Analyzer
	ruleNames     []string
	stageCatalog  []StageInfo
	maxPayload    int64
	maxCandidates int
	sem           chan struct{}
	log           *slog.Logger
	mux           *http.ServeMux
}

// New builds a Server. It fails only if the built-in ruleset cannot be loaded,
// which would be a build-time defect rather than a runtime condition.
func New(opts Options) (*Server, error) {
	sc := opts.Scanner
	if sc == nil {
		rs, err := yara.Builtin()
		if err != nil {
			return nil, fmt.Errorf("api: loading the built-in ruleset: %w", err)
		}
		sc = rs
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		analyzer:      analysis.New(sc),
		ruleNames:     sc.Names(),
		stageCatalog:  buildStageCatalog(),
		maxPayload:    opts.MaxPayload,
		maxCandidates: opts.MaxCandidates,
		log:           log,
	}
	if s.maxPayload <= 0 {
		s.maxPayload = DefaultMaxPayload
	}
	if s.maxCandidates <= 0 {
		s.maxCandidates = DefaultMaxCandidates
	}
	n := opts.MaxConcurrent
	if n <= 0 {
		n = DefaultMaxConcurrent
	}
	s.sem = make(chan struct{}, n)

	// Go's pattern-routing multiplexer answers 405 for a known path with the
	// wrong method and 404 for an unknown path, which is the behaviour a client
	// expects without any extra code.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/stages", s.handleStages)
	mux.HandleFunc("GET /v1/rules", s.handleRules)
	mux.HandleFunc("POST /v1/obfuscate", s.handleObfuscate(true))
	mux.HandleFunc("POST /v1/analyze", s.handleObfuscate(false))
	mux.HandleFunc("POST /v1/benchmark", s.handleBenchmark)
	mux.HandleFunc("/", s.handleNotFound)
	s.mux = mux
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// GET endpoints
// ---------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"stages":      len(s.stageCatalog),
		"rules":       len(s.ruleNames),
		"max_payload": s.maxPayload,
		"concurrency": cap(s.sem),
	})
}

func (s *Server) handleStages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(s.stageCatalog),
		"stages": s.stageCatalog,
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	rs, err := yara.Builtin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ruleset unavailable", err.Error(), "")
		return
	}
	out := make([]RuleInfo, 0, len(rs.Rules))
	for _, rule := range rs.Rules {
		out = append(out, RuleInfo{
			Name:     rule.Name,
			Tags:     rule.Tags,
			Severity: metaString(rule.Meta, "severity"),
			Summary:  metaString(rule.Meta, "description"),
			Source:   rule.Source,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "rules": out})
}

// routeMethods is the method each route accepts, used to answer a wrong-method
// request with 405 and an Allow header. The method-aware patterns registered on
// the mux cannot do that on their own here, because the catch-all route matches
// every path and therefore wins for a mismatched method.
var routeMethods = map[string]string{
	"/healthz":      http.MethodGet,
	"/v1/stages":    http.MethodGet,
	"/v1/rules":     http.MethodGet,
	"/v1/obfuscate": http.MethodPost,
	"/v1/analyze":   http.MethodPost,
	"/v1/benchmark": http.MethodPost,
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if allow, ok := routeMethods[r.URL.Path]; ok {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed",
			fmt.Sprintf("%s %s is not supported", r.Method, r.URL.Path),
			"this endpoint accepts "+allow)
		return
	}
	writeError(w, http.StatusNotFound, "unknown endpoint",
		fmt.Sprintf("%s %s is not a route", r.Method, r.URL.Path),
		"try GET /v1/stages, GET /v1/rules, POST /v1/obfuscate, POST /v1/analyze or POST /v1/benchmark")
}

// ---------------------------------------------------------------------------
// POST /v1/obfuscate and /v1/analyze
// ---------------------------------------------------------------------------

func (s *Server) handleObfuscate(defaultEmit bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		release, ok := s.acquire()
		if !ok {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "server busy",
				fmt.Sprintf("all %d run slots are occupied", cap(s.sem)),
				"retry shortly; the limit exists so that concurrent runs do not share stages")
			return
		}
		defer release()

		req, payload, filename, err := s.readRequest(w, r)
		if err != nil {
			writeError(w, statusFor(err), "invalid request", err.Error(), "")
			return
		}
		cfg, err := s.normalize(req, defaultEmit, true, filename)
		if err != nil {
			writeError(w, statusFor(err), "invalid configuration", err.Error(), stageHint(err))
			return
		}
		if len(payload) == 0 {
			writeError(w, http.StatusBadRequest, "empty payload", "the uploaded payload has zero bytes", "")
			return
		}

		stages, err := s.buildStages(cfg)
		if err != nil {
			writeError(w, statusFor(err), "invalid configuration", err.Error(), stageHint(err))
			return
		}
		verify, scan, render := ptrBool(cfg.Verify, true), ptrBool(cfg.Scan, true), ptrBool(cfg.Render, true)

		rep, err := s.analyzer.Analyze(cfg.Label, payload, stages, analysis.Options{
			Rounds: cfg.Rounds, Seed: cfg.Seed, Verify: verify, Scan: scan,
		})
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "obfuscation failed", err.Error(),
				"a stage returned an error rather than refusing the payload; this is a bug in that stage")
			return
		}

		resp := ObfuscateResponse{
			Label:        rep.Label,
			Stages:       rep.Pipeline,
			Seed:         rep.Seed,
			Rounds:       rep.Rounds,
			InputSize:    rep.Before.Size,
			InputSHA256:  digest(payload),
			OutputSize:   rep.After.Size,
			OutputSHA256: digest(rep.AfterBlob),
			Report:       rep,
			Warnings:     warnings(rep),
		}
		if ptrBool(cfg.EmitPayload, defaultEmit) {
			resp.PayloadBase64 = base64.StdEncoding.EncodeToString(rep.AfterBlob)
		}
		if render {
			var b bytes.Buffer
			analysis.RenderWith(&b, rep, analysis.RenderOptions{
				DiffBytes: cfg.DiffBytes,
				NoDiff:    cfg.DiffBytes < 0,
			})
			resp.Rendered = b.String()
		}
		s.log.Info("obfuscated",
			"label", resp.Label, "stages", len(resp.Stages), "seed", resp.Seed,
			"input", resp.InputSize, "output", resp.OutputSize,
			"detection_before", rep.DetectionBefore, "detection_after", rep.DetectionAfter,
			"verified", rep.Verified, "skipped", rep.SkippedStages())
		writeJSON(w, http.StatusOK, resp)
	}
}

// warnings states the trade-offs the caller would otherwise have to infer from
// the report. A pipeline that clears rules but grows eightfold is a legitimate
// outcome; hiding that would make the tool dishonest.
func warnings(rep *analysis.Report) []string {
	var out []string
	if rep.DetectionAfter > rep.DetectionBefore && rep.DetectionBefore > 0 {
		out = append(out, fmt.Sprintf(
			"detection rose from %.0f%% to %.0f%%: the emitted decoder stubs, inserted sequences and any entropy increase are themselves signatures",
			rep.DetectionBefore*100, rep.DetectionAfter*100))
	}
	if g := rep.Growth(); g >= 4 {
		out = append(out, fmt.Sprintf("payload grew %.1fx (%d to %d bytes)", g, rep.Before.Size, rep.After.Size))
	}
	if added := distinctAdded(rep); len(added) > 0 {
		out = append(out, "rules newly matching: "+strings.Join(added, ", "))
	}
	if skipped := rep.SkippedStages(); len(skipped) > 0 {
		out = append(out, "stages that declined this payload: "+strings.Join(skipped, ", "))
	}
	return out
}

func distinctAdded(rep *analysis.Report) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range rep.Steps {
		for _, n := range s.Added {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// POST /v1/benchmark
// ---------------------------------------------------------------------------

func (s *Server) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	release, ok := s.acquire()
	if !ok {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "server busy", "all run slots are occupied", "retry shortly")
		return
	}
	defer release()

	req, payload, filename, err := s.readRequest(w, r)
	if err != nil {
		writeError(w, statusFor(err), "invalid request", err.Error(), "")
		return
	}
	if len(payload) == 0 {
		writeError(w, http.StatusBadRequest, "empty payload", "the uploaded payload has zero bytes", "")
		return
	}
	cfg, err := s.normalize(req, false, false, filename)
	if err != nil {
		writeError(w, statusFor(err), "invalid configuration", err.Error(), stageHint(err))
		return
	}
	pool := cfg.Stages
	if len(pool) == 0 {
		pool = pipeline.Names()
	}
	depth := cfg.MaxStagesPerPipeline
	if depth <= 0 {
		depth = 2
	}
	if depth > MaxStagesPerPipeline {
		writeError(w, http.StatusBadRequest, "invalid configuration",
			fmt.Sprintf("max_stages_per_pipeline %d exceeds the limit of %d", depth, MaxStagesPerPipeline),
			"a deeper search multiplies the candidate count")
		return
	}
	candidates := analysis.AllPermutationsUpTo(pool, depth)
	if len(candidates) > s.maxCandidates {
		writeError(w, http.StatusBadRequest, "benchmark too large",
			fmt.Sprintf("%d candidates exceed the limit of %d", len(candidates), s.maxCandidates),
			"narrow \"stages\" or lower \"max_stages_per_pipeline\"")
		return
	}

	// Every candidate gets a freshly built stage set. The seed is the run's
	// effective seed, so the comparison is fair: no candidate inherits another's
	// random stream, and repeating the request reproduces the ranking.
	res, err := s.analyzer.Benchmark(cfg.Label, payload, candidates, func(names []string) ([]pipeline.Stage, error) {
		local := *cfg
		local.Stages = names
		return s.buildStages(&local)
	}, cfg.Seed, cfg.Rounds)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "benchmark failed", err.Error(), "")
		return
	}

	out := BenchmarkResponse{Pool: pool, Depth: depth, Candidates: len(candidates)}
	for _, c := range res.Ranked {
		out.Ranked = append(out.Ranked, Ranked{
			Stages: c.Stages, Detection: c.Score.Detection, SizeBytes: c.Score.SizeBytes,
			Growth: c.Score.Growth, Millis: c.Score.Millisecs, Skipped: c.Skipped, Error: c.Error,
		})
	}
	if ptrBool(cfg.Render, true) {
		var b bytes.Buffer
		analysis.RenderBenchmark(&b, res)
		out.Rendered = b.String()
	}
	s.log.Info("benchmarked", "label", cfg.Label, "candidates", len(candidates), "depth", depth, "seed", cfg.Seed)
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// request parsing
// ---------------------------------------------------------------------------

// readRequest pulls the configuration and the payload out of any of the three
// supported shapes:
//
//   - multipart/form-data with a file part and an optional "config" JSON field,
//     plus optional scalar fields (stages, rounds, seed, ...)
//   - application/json with a base64 "payload_base64" field
//   - anything else: the body is the payload, configuration comes from the query
//
// Query parameters are applied last and therefore override the body, which is
// what makes one-liners like
// `curl --data-binary @p.bin 'host/v1/obfuscate?stages=xor,base64&seed=7'`
// work as written.
func (s *Server) readRequest(w http.ResponseWriter, r *http.Request) (*Request, []byte, string, error) {
	cfg := &Request{}
	var payload []byte
	filename := ""

	ct := r.Header.Get("Content-Type")
	media, _, _ := mime.ParseMediaType(ct)
	switch {
	case media == "multipart/form-data":
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, nil, "", fmt.Errorf("reading multipart body: %w", err)
		}
		fields := map[string]string{}
		payload, filename, err = readMultipart(mr, fields, s.maxPayload)
		if err != nil {
			return nil, nil, "", err
		}
		if raw, ok := fields["config"]; ok && strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), cfg); err != nil {
				return nil, nil, "", fmt.Errorf("parsing the \"config\" field as JSON: %w", err)
			}
		}
		if err := applyFields(cfg, fields); err != nil {
			return nil, nil, "", err
		}
		if b64, ok := fields["payload_base64"]; ok && len(payload) == 0 {
			payload, err = base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
			if err != nil {
				return nil, nil, "", fmt.Errorf("decoding the \"payload_base64\" field: %w", err)
			}
		}

	case media == "application/json":
		var body struct {
			Request
			PayloadBase64 string `json:"payload_base64"`
			PayloadHex    string `json:"payload_hex"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, s.maxPayload+multipartOverhead))
		if err := dec.Decode(&body); err != nil {
			return nil, nil, "", fmt.Errorf("parsing the JSON body: %w", err)
		}
		*cfg = body.Request
		switch {
		case body.PayloadBase64 != "":
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body.PayloadBase64))
			if err != nil {
				return nil, nil, "", fmt.Errorf("decoding payload_base64: %w", err)
			}
			payload = b
		case body.PayloadHex != "":
			b, err := hex.DecodeString(strings.TrimSpace(body.PayloadHex))
			if err != nil {
				return nil, nil, "", fmt.Errorf("decoding payload_hex: %w", err)
			}
			payload = b
		default:
			return nil, nil, "", errors.New("a JSON request must carry payload_base64 or payload_hex")
		}

	default:
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxPayload))
		if err != nil {
			var too *http.MaxBytesError
			if errors.As(err, &too) {
				return nil, nil, "", &tooLargeError{got: int(too.Limit) + 1, max: s.maxPayload}
			}
			return nil, nil, "", fmt.Errorf("reading the request body: %w", err)
		}
		payload = b
	}

	if err := applyQuery(cfg, r.URL.Query()); err != nil {
		return nil, nil, "", err
	}
	if len(payload) > int(s.maxPayload) {
		return nil, nil, "", &tooLargeError{got: len(payload), max: s.maxPayload}
	}
	return cfg, payload, filename, nil
}

// readMultipart consumes the form, returning the payload and the scalar fields.
//
// It rejects a second file part rather than silently ignoring it: a caller that
// uploads two files has misunderstood the endpoint. The total across parts is
// bounded as well, so a body made of a million small fields cannot exhaust
// memory.
func readMultipart(mr *multipart.Reader, fields map[string]string, maxPayload int64) ([]byte, string, error) {
	var payload []byte
	var filename string
	budget := maxPayload + multipartOverhead
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("reading multipart part: %w", err)
		}
		name := part.FormName()
		if part.FileName() != "" || name == "payload" || name == "file" {
			if payload != nil {
				part.Close()
				return nil, "", errors.New("only one payload part is accepted")
			}
			b, err := io.ReadAll(io.LimitReader(part, maxPayload+1))
			part.Close()
			if err != nil {
				return nil, "", fmt.Errorf("reading part %q: %w", name, err)
			}
			if int64(len(b)) > maxPayload {
				return nil, "", &tooLargeError{got: len(b), max: maxPayload}
			}
			payload = b
			budget -= int64(len(b))
			filename = part.FileName()
			if filename == "" {
				filename = name
			}
			continue
		}
		limit := budget
		if limit > 1<<20 {
			limit = 1 << 20
		}
		if limit < 0 {
			limit = 0
		}
		b, err := io.ReadAll(io.LimitReader(part, limit+1))
		part.Close()
		if err != nil {
			return nil, "", fmt.Errorf("reading field %q: %w", name, err)
		}
		budget -= int64(len(b))
		if int64(len(b)) > limit {
			return nil, "", &tooLargeError{got: int(maxPayload - budget), max: maxPayload}
		}
		if name != "" {
			fields[name] = string(b)
		}
	}
	return payload, filename, nil
}

// applyFields lets a multipart caller set individual options as scalar fields
// instead of assembling a JSON config blob.
func applyFields(cfg *Request, fields map[string]string) error {
	get := func(k string) (string, bool) {
		v, ok := fields[k]
		return strings.TrimSpace(v), ok
	}
	if v, ok := get("stages"); ok {
		cfg.Stages = splitList(v)
	}
	if v, ok := get("label"); ok {
		cfg.Label = v
	}
	for _, f := range []struct {
		key string
		dst *int
	}{
		{"rounds", &cfg.Rounds},
		{"min_string_len", &cfg.MinStringLen},
		{"max_insertions", &cfg.MaxInsertions},
		{"cfp_max_blocks", &cfg.CFPMaxBlocks},
		{"max_stages_per_pipeline", &cfg.MaxStagesPerPipeline},
		{"diff_bytes", &cfg.DiffBytes},
	} {
		v, ok := get(f.key)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("field %q must be an integer, got %q", f.key, v)
		}
		*f.dst = n
	}
	if v, ok := get("seed"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("field \"seed\" must be an integer, got %q", v)
		}
		cfg.Seed = n
	}
	for _, f := range []struct {
		key string
		dst **bool
	}{
		{"verify", &cfg.Verify},
		{"scan", &cfg.Scan},
		{"emit_payload", &cfg.EmitPayload},
		{"render", &cfg.Render},
	} {
		v, ok := get(f.key)
		if !ok {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("field %q must be a boolean, got %q", f.key, v)
		}
		*f.dst = ptr(b)
	}
	if v, ok := get("allow_flag_clobber"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("field \"allow_flag_clobber\" must be a boolean, got %q", v)
		}
		cfg.AllowFlagClobber = b
	}
	if v, ok := fields["passphrase"]; ok {
		cfg.Passphrase = v
	}
	return nil
}

func applyQuery(cfg *Request, q map[string][]string) error {
	fields := map[string]string{}
	for k, v := range q {
		if len(v) > 0 {
			fields[k] = v[0]
		}
	}
	// "stages" in a query is comma separated, same as a form field.
	return applyFields(cfg, fields)
}

// normalize validates and fills in the defaults that do not depend on the
// endpoint, returning a Request that is safe to hand to buildStages.
//
// requireStages distinguishes /v1/obfuscate (where an empty pipeline would
// silently return the input untouched, so it is an error) from /v1/benchmark
// (where an empty pool means "every registered stage").
func (s *Server) normalize(cfg *Request, defaultEmit, requireStages bool, filename string) (*Request, error) {
	if cfg.Label == "" {
		cfg.Label = filename
	}
	if cfg.Label == "" {
		cfg.Label = "upload"
	}
	// Trim an extension so that "shellcode.bin" reports as "shellcode".
	if i := strings.LastIndexByte(cfg.Label, '.'); i > 0 {
		cfg.Label = cfg.Label[:i]
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = 1
	}
	if cfg.Rounds > MaxRounds {
		return nil, fmt.Errorf("rounds %d exceeds the limit of %d", cfg.Rounds, MaxRounds)
	}
	if cfg.MinStringLen < 0 {
		return nil, fmt.Errorf("min_string_len must not be negative, got %d", cfg.MinStringLen)
	}
	if cfg.MaxInsertions < 0 {
		return nil, fmt.Errorf("max_insertions must not be negative, got %d", cfg.MaxInsertions)
	}
	// Validate stage names here so that /v1/benchmark reports a bad pool with a
	// 400 instead of a per-candidate error inside the result.
	if len(cfg.Stages) == 0 {
		if requireStages {
			return nil, errors.New(`"stages" is required: send an ordered list of stage names, for example ["polymorph", "deadcode", "cff", "strings", "xor", "base64"]`)
		}
	} else {
		for _, n := range cfg.Stages {
			if _, err := pipeline.NewStage(n, pipeline.NewContext(1, pipeline.DefaultOptions(), nil)); err != nil {
				return nil, err
			}
		}
	}
	if cfg.Seed == 0 {
		// Let the pipeline pick a random seed and report it back.
		cfg.Seed = pipeline.NewContext(0, pipeline.DefaultOptions(), nil).Seed
	}
	if cfg.EmitPayload == nil {
		cfg.EmitPayload = ptr(defaultEmit)
	}
	return cfg, nil
}

func (s *Server) buildStages(cfg *Request) ([]pipeline.Stage, error) {
	opts := pipeline.DefaultOptions()
	if cfg.MinStringLen > 0 {
		opts.MinStringLen = cfg.MinStringLen
	}
	if cfg.MaxInsertions > 0 {
		opts.MaxInsertions = cfg.MaxInsertions
	}
	opts.AllowFlagClobber = cfg.AllowFlagClobber
	opts.CFPMaxBlocks = cfg.CFPMaxBlocks
	opts.Passphrase = cfg.Passphrase

	seeded := cfg.Seed
	if seeded == 0 {
		seeded = 1
	}
	ctx := pipeline.NewContext(seeded, opts, s.log)
	out := make([]pipeline.Stage, 0, len(cfg.Stages))
	for _, n := range cfg.Stages {
		st, err := pipeline.NewStage(n, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// acquire takes a run slot without blocking. Reporting "busy" immediately is
// better than queueing: the caller can decide whether to wait.
func (s *Server) acquire() (func(), bool) {
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, true
	default:
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildStageCatalog() []StageInfo {
	ctx := pipeline.NewContext(1, pipeline.DefaultOptions(), nil)
	var out []StageInfo
	for _, n := range pipeline.Names() {
		st, err := pipeline.NewStage(n, ctx)
		if err != nil {
			continue
		}
		info := StageInfo{Name: st.Name(), Kind: string(st.Kind()), Description: st.Description()}
		_, info.Reversible = st.(pipeline.Reversible)
		_, info.Detailable = st.(pipeline.Detailable)
		out = append(out, info)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding response", err.Error(), "")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(buf, '\n'))
}

func writeError(w http.ResponseWriter, status int, msg, detail, hint string) {
	writeJSON(w, status, ErrorResponse{Error: msg, Detail: detail, Hint: hint})
}

// tooLargeError carries the two numbers so the handler can report both.
type tooLargeError struct {
	got int
	max int64
}

func (e *tooLargeError) Error() string {
	return fmt.Sprintf("payload is %d bytes, the limit is %d", e.got, e.max)
}

// statusFor maps a request-parsing failure to the right status code. A payload
// that is too large is 413; everything else the parser rejects is 400.
func statusFor(err error) int {
	var too *tooLargeError
	if errors.As(err, &too) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// stageHint names the valid stages when the failure looks like a bad stage name,
// which is by far the most common client mistake.
func stageHint(err error) string {
	if err == nil || !strings.Contains(err.Error(), "unknown stage") {
		return ""
	}
	return "available stages: " + strings.Join(pipeline.Names(), ", ")
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func ptr[T any](v T) *T { return &v }

func ptrBool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '>' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func metaString(meta map[string]any, key string) string {
	if s, ok := meta[key].(string); ok {
		return s
	}
	return ""
}
