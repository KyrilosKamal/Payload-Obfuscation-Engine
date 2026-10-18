// Command poe is the payload obfuscation engine's command line interface.
//
// It is a thin shell over internal/pipeline and internal/analysis: every
// command constructs a pipeline, runs it over one payload and prints the
// measured result. Nothing here contains obfuscation logic of its own, which
// keeps the CLI and the HTTP API honest about doing the same thing.
//
// Conventions:
//
//   - artifacts go to stdout (or --out); reports go to stderr, so a shell
//     redirection captures the payload and still shows the numbers
//   - --in - reads the payload from stdin
//   - --seed is echoed in the report, and passing it back reproduces the exact
//     bytes
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"pobf/internal/analysis"
	"pobf/internal/pipeline"
	_ "pobf/internal/stages" // registers the built-in stages
	"pobf/internal/yara"
)

// DefaultPipeline is the stage order used when --stages is omitted.
//
// The order is deliberate and is not the order the stages are described in:
// the instruction-level stages must see raw code, so they run first, and the
// encoding stages run last because each one wraps the payload in a container
// that a later code-level stage could no longer disassemble.
var DefaultPipeline = []string{"polymorph", "deadcode", "cff", "strings", "xor", "base64"}

// flags holds every option the CLI understands. One struct keeps the flag
// registration and the code that consumes it in step.
type flags struct {
	// input and output
	in  string
	out string

	// pipeline
	stages           []string
	rounds           int
	seed             int64
	passphrase       string
	minStringLen     int
	maxInsertions    int
	cfpMaxBlocks     int
	allowFlagClobber bool
	noScan           bool
	noVerify         bool

	// reporting
	jsonOut   string
	diffBytes int
	noDiff    bool
	quiet     bool
	verbose   bool

	// benchmark
	depth int

	// serve
	addr          string
	maxPayload    int64
	maxConcurrent int
	maxCandidates int
}

func (f *flags) addIO(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.in, "in", "i", "-",
		`payload to read ("-" reads stdin)`)
	cmd.Flags().StringVarP(&f.out, "out", "o", "-",
		`where to write the artifact ("-" writes stdout)`)
}

func (f *flags) addPipeline(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&f.stages, "stages", "s", nil,
		"ordered pipeline stages, comma separated or repeated (default: the recommended order)")
	cmd.Flags().IntVarP(&f.rounds, "rounds", "r", 1,
		"repeat the whole pipeline this many times")
	cmd.Flags().Int64Var(&f.seed, "seed", 0,
		"reproduce a previous run exactly; 0 picks a random seed and reports it")
	cmd.Flags().StringVar(&f.passphrase, "passphrase", "",
		"AES passphrase; empty derives a random key and records it in the stub descriptor")
	cmd.Flags().IntVar(&f.minStringLen, "min-string-len", 0,
		"shortest printable run the strings stage masks (default 6)")
	cmd.Flags().IntVar(&f.maxInsertions, "max-insertions", 0,
		"cap on dead-code snippets inserted per pass (default 64)")
	cmd.Flags().IntVar(&f.cfpMaxBlocks, "cfp-max-blocks", 0,
		"cap on basic blocks rewritten by control-flow flattening (0 means unlimited)")
	cmd.Flags().BoolVar(&f.allowFlagClobber, "allow-flag-clobber", false,
		"allow substitutions that change EFLAGS even when the next instruction reads them")
	cmd.Flags().BoolVar(&f.noScan, "no-scan", false,
		"skip the YARA measurement and report static shape only")
	cmd.Flags().BoolVar(&f.noVerify, "no-verify", false,
		"skip self-extraction verification")
}

func (f *flags) addReport(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.jsonOut, "json", "",
		`write the machine-readable report to this file ("-" writes stdout)`)
	cmd.Flags().IntVar(&f.diffBytes, "diff", 0,
		"byte-diff window in the rendered report (default 128)")
	cmd.Flags().BoolVar(&f.noDiff, "no-diff", false, "omit the diff sections from the report")
	cmd.Flags().BoolVarP(&f.quiet, "quiet", "q", false, "suppress the human-readable report")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "log each stage's decision at debug level")
}

// analysisOptions builds the options for a run. seed must be the effective seed
// from the run's context, never the raw flag value, or the report would claim a
// seed that does not reproduce the bytes.
func (f *flags) analysisOptions(seed int64, rounds int) analysis.Options {
	return analysis.Options{
		Rounds: rounds,
		Seed:   seed,
		Verify: !f.noVerify,
		Scan:   !f.noScan,
	}
}

func (f *flags) renderOptions() analysis.RenderOptions {
	n := f.diffBytes
	if f.noDiff {
		n = -1
	}
	return analysis.RenderOptions{DiffBytes: n, NoDiff: f.noDiff}
}

// pipelineOptions maps the flags onto the engine's option set.
func (f *flags) pipelineOptions() pipeline.Options {
	opts := pipeline.DefaultOptions()
	if f.minStringLen > 0 {
		opts.MinStringLen = f.minStringLen
	}
	if f.maxInsertions > 0 {
		opts.MaxInsertions = f.maxInsertions
	}
	opts.CFPMaxBlocks = f.cfpMaxBlocks
	opts.AllowFlagClobber = f.allowFlagClobber
	opts.Passphrase = f.passphrase
	opts.Verbose = f.verbose
	return opts
}

// newContext creates the run's context. The returned context's Seed is the
// effective seed, which the report must use.
func (f *flags) newContext(log io.Writer) *pipeline.Context {
	opts := f.pipelineOptions()
	if f.verbose {
		return pipeline.NewContext(f.seed, opts, newLogger(log, true))
	}
	return pipeline.NewContext(f.seed, opts, nil)
}

// stageNames resolves the pipeline names, falling back to DefaultPipeline.
func (f *flags) stageNames() []string {
	if len(f.stages) > 0 {
		return splitStageList(f.stages)
	}
	return append([]string(nil), DefaultPipeline...)
}

// buildStages instantiates the named stages against the context.
func (f *flags) buildStages(ctx *pipeline.Context, names []string) ([]pipeline.Stage, error) {
	out := make([]pipeline.Stage, 0, len(names))
	for _, n := range names {
		st, err := pipeline.NewStage(n, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// buildStagesWithSeed instantiates the stages against a fresh context built
// from an explicit seed. Benchmarking uses it so that every candidate is
// compared under the same random conditions instead of each picking its own.
func (f *flags) buildStagesWithSeed(seed int64, names []string) ([]pipeline.Stage, error) {
	return f.buildStages(pipeline.NewContext(seed, f.pipelineOptions(), nil), names)
}

// scanner returns the detection oracle, or nil when --no-scan is set.
func (f *flags) scanner() (analysis.Scanner, error) {
	if f.noScan {
		return nil, nil
	}
	rs, err := yara.Builtin()
	if err != nil {
		return nil, fmt.Errorf("loading the built-in ruleset: %w", err)
	}
	return rs, nil
}

// readInput reads the payload and returns a label for the report.
func (f *flags) readInput() ([]byte, string, error) {
	if f.in == "" || f.in == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, "", fmt.Errorf("reading stdin: %w", err)
		}
		return b, "stdin", nil
	}
	b, err := os.ReadFile(f.in)
	if err != nil {
		return nil, "", err
	}
	label := filepath.Base(f.in)
	if i := strings.LastIndexByte(label, '.'); i > 0 {
		label = label[:i]
	}
	return b, label, nil
}

// writeArtifact writes the obfuscated payload.
func (f *flags) writeArtifact(b []byte) error {
	if f.out == "" || f.out == "-" {
		if isTerminal(os.Stdout) {
			fmt.Fprintln(os.Stderr,
				"note: the artifact is binary and stdout is a terminal; use --out FILE to redirect it")
		}
		_, err := os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(f.out, b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(b), f.out)
	return nil
}

// writeJSONReport writes the machine-readable report, if a destination was
// given.
func (f *flags) writeJSONReport(rep *analysis.Report) error {
	if f.jsonOut == "" {
		return nil
	}
	if f.jsonOut == "-" {
		return analysis.WriteJSON(os.Stdout, rep)
	}
	file, err := os.Create(f.jsonOut)
	if err != nil {
		return err
	}
	defer file.Close()
	return analysis.WriteJSON(file, rep)
}

// renderReport prints the human-readable report to w unless --quiet.
func (f *flags) renderReport(w io.Writer, rep *analysis.Report) {
	if f.quiet {
		return
	}
	analysis.RenderWith(w, rep, f.renderOptions())
}

// splitStageList flattens "a,b c>d" into an ordered list.
func splitStageList(in []string) []string {
	var out []string
	for _, item := range in {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ' ' || r == '>' || r == '+'
		}) {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// isTerminal reports whether w is a character device, which is the cheapest
// portable check for "a human is watching this".
func isTerminal(w *os.File) bool {
	info, err := w.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// errUsage marks an error as the caller's mistake, so cobra prints usage for it
// and the process exits non-zero.
var errUsage = errors.New("invalid usage")
