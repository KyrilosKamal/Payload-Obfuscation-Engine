package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"pobf/internal/pipeline"
)

// Score is the ranking metric for one pipeline combination.
//
// Lower is better. Detection rate dominates because avoiding detection is the
// entire point; size growth and runtime are tie-breakers, so that among
// pipelines that clear exactly the same rules the report prefers the one that
// wastes the least space and time.
type Score struct {
	Detection float64 `json:"detection_rate"`
	SizeBytes int     `json:"size_bytes"`
	Growth    float64 `json:"growth"`
	Millisecs float64 `json:"ms"`
}

// Weighted collapses the score into a single number for ranking.
//
// The weights are deliberately lopsided. Detection is measured in whole rules
// (a ruleset of 20 means each rule is 5%), so a 0.05 detection difference is
// worth 1.0 -- i.e. one extra cleared rule outweighs any plausible size or time
// difference.
func (s Score) Weighted() float64 {
	return s.Detection*20 + s.Growth*0.05 + s.Millisecs/1000
}

// Combination is one pipeline permutation with its measured score.
type Combination struct {
	Stages []string `json:"stages"`
	Score  Score    `json:"score"`
	// Skipped names the stages that declined to run in this order. A
	// combination that silently degraded to two stages is less interesting than
	// one where every stage ran, so it is recorded rather than hidden.
	Skipped []string `json:"skipped,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// BenchmarkResult is the ranked outcome of a benchmark run.
type BenchmarkResult struct {
	Input      string        `json:"input"`
	Rounds     int           `json:"rounds"`
	Seed       int64         `json:"seed"`
	TotalRules int           `json:"total_rules"`
	Candidates int           `json:"candidates"`
	Ranked     []Combination `json:"ranked"`
}

// Permutations enumerates every ordered selection of `length` stages taken from
// names.
//
// Ordered subsets rather than the full powerset: stage order genuinely changes
// the result (running the polymorphic rewriter after an encoding stage has
// nothing to rewrite), so a set-based search would report combinations that
// cannot be built.
func Permutations(names []string, length int) [][]string {
	if length <= 0 || length > len(names) {
		return nil
	}
	var out [][]string
	used := make([]bool, len(names))
	cur := make([]string, 0, length)
	var rec func()
	rec = func() {
		if len(cur) == length {
			out = append(out, append([]string(nil), cur...))
			return
		}
		for i, n := range names {
			if used[i] {
				continue
			}
			used[i] = true
			cur = append(cur, n)
			rec()
			cur = cur[:len(cur)-1]
			used[i] = false
		}
	}
	rec()
	return out
}

// AllPermutationsUpTo enumerates every ordered selection of at most maxLen
// stages. This is the `--benchmark` candidate set.
func AllPermutationsUpTo(names []string, maxLen int) [][]string {
	var out [][]string
	for l := 1; l <= maxLen && l <= len(names); l++ {
		out = append(out, Permutations(names, l)...)
	}
	return out
}

// Benchmark runs every candidate pipeline over the payload and ranks them.
//
// Each candidate gets a freshly constructed stage set from the factory, so the
// comparison is fair: no candidate inherits another's random stream.
func (a *Analyzer) Benchmark(label string, input []byte, candidates [][]string, newStages func(names []string) ([]pipeline.Stage, error), seed int64, rounds int) (*BenchmarkResult, error) {
	if rounds < 1 {
		rounds = 1
	}
	res := &BenchmarkResult{
		Input:      label,
		Rounds:     rounds,
		Seed:       seed,
		TotalRules: a.rules,
		Candidates: len(candidates),
	}
	opts := Options{Rounds: rounds, Seed: seed, Scan: a.Scanner != nil}
	for _, cand := range candidates {
		stages, err := newStages(cand)
		if err != nil {
			res.Ranked = append(res.Ranked, Combination{Stages: cand, Error: err.Error()})
			continue
		}
		rep, err := a.Analyze(label, input, stages, opts)
		if err != nil {
			res.Ranked = append(res.Ranked, Combination{Stages: cand, Error: err.Error()})
			continue
		}
		res.Ranked = append(res.Ranked, Combination{
			Stages:  cand,
			Skipped: rep.SkippedStages(),
			Score: Score{
				Detection: rep.DetectionAfter,
				SizeBytes: rep.After.Size,
				Growth:    rep.Growth(),
				Millisecs: rep.TotalMS,
			},
		})
	}
	sort.SliceStable(res.Ranked, func(i, j int) bool {
		// Failed candidates sink to the bottom.
		if (res.Ranked[i].Error == "") != (res.Ranked[j].Error == "") {
			return res.Ranked[i].Error == ""
		}
		li, lj := res.Ranked[i].Score.Weighted(), res.Ranked[j].Score.Weighted()
		if li != lj {
			return li < lj
		}
		return strings.Join(res.Ranked[i].Stages, ",") < strings.Join(res.Ranked[j].Stages, ",")
	})
	return res, nil
}

// WriteBenchmarkJSON emits a ranking as indented JSON.
func WriteBenchmarkJSON(w io.Writer, res *BenchmarkResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// RenderBenchmark prints the ranking as a table, with the best and worst
// single-stage pipelines called out.
func RenderBenchmark(w io.Writer, res *BenchmarkResult) {
	fmt.Fprintf(w, "benchmark: %s\n", res.Input)
	fmt.Fprintf(w, "  candidates %d   rules %d   rounds %d   seed %d\n\n",
		res.Candidates, res.TotalRules, res.Rounds, res.Seed)

	fmt.Fprintf(w, "  %-4s %-46s %8s %9s %7s %8s  %s\n",
		"rank", "pipeline", "detect", "size", "growth", "ms", "notes")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 104))
	limit := len(res.Ranked)
	if limit > 25 {
		// The head and tail are what matter; the middle is a smear of
		// near-identical pipelines.
		limit = 25
	}
	for i := 0; i < limit; i++ {
		printCombination(w, i+1, res.Ranked[i])
	}
	if len(res.Ranked) > limit {
		fmt.Fprintf(w, "  ... %d more\n", len(res.Ranked)-limit)
		fmt.Fprintf(w, "  worst ranked:\n")
		for i := len(res.Ranked) - 3; i < len(res.Ranked); i++ {
			if i < 0 {
				continue
			}
			printCombination(w, i+1, res.Ranked[i])
		}
	}
	fmt.Fprintf(w, "\n")
	renderStageValue(w, res)
}

func printCombination(w io.Writer, rank int, c Combination) {
	notes := []string{}
	if len(c.Skipped) > 0 {
		notes = append(notes, "skipped "+strings.Join(c.Skipped, ","))
	}
	if c.Error != "" {
		notes = append(notes, "ERROR "+truncate(c.Error, 40))
	}
	name := strings.Join(c.Stages, "->")
	if len(name) > 44 {
		name = name[:41] + "..."
	}
	fmt.Fprintf(w, "  %-4d %-46s %7s %9d %7.2f %8.1f  %s\n",
		rank, name, pct(c.Score.Detection), c.Score.SizeBytes, c.Score.Growth,
		c.Score.Millisecs, strings.Join(notes, "; "))
}

// renderStageValue answers the question the ranking alone does not: which single
// stage is doing the work, and which stages make things worse?
//
// "Worse" is not a bug. Every encoding stage has to ship a decoder stub, and
// this ruleset deliberately detects decoder stubs and entropy, so some stages
// are expected to add detections. Reporting that honestly is the point.
func renderStageValue(w io.Writer, res *BenchmarkResult) {
	type agg struct {
		n      int
		detect float64
		growth float64
	}
	byStage := map[string]*agg{}
	for _, c := range res.Ranked {
		if c.Error != "" {
			continue
		}
		for _, s := range c.Stages {
			a := byStage[s]
			if a == nil {
				a = &agg{}
				byStage[s] = a
			}
			a.n++
			a.detect += c.Score.Detection
			a.growth += c.Score.Growth
		}
	}
	if len(byStage) == 0 {
		return
	}
	names := make([]string, 0, len(byStage))
	for n := range byStage {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "  average outcome by inclusion\n")
	fmt.Fprintf(w, "  %-12s %6s %10s %8s\n", "stage", "runs", "detect", "growth")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 42))
	for _, n := range names {
		a := byStage[n]
		fmt.Fprintf(w, "  %-12s %6d %9s %8.2f\n", n, a.n, pct(a.detect/float64(a.n)), a.growth/float64(a.n))
	}
}

// StagePresence reports, for each stage, how often it appears in the ranking.
// It exists so tests can assert the candidate set actually covered every stage.
func (res *BenchmarkResult) StagePresence() map[string]int {
	out := map[string]int{}
	for _, c := range res.Ranked {
		for _, s := range c.Stages {
			out[s]++
		}
	}
	return out
}
