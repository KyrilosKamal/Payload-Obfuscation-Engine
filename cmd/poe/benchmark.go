package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"pobf/internal/analysis"
	"pobf/internal/pipeline"
)

func newBenchmarkCmd() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "rank pipeline permutations by measured evasion",
		Long: `Benchmark every ordered combination of stages up to a given depth.

Candidates are ordered selections, not sets: stage order genuinely changes the
result (a polymorphic rewriter placed after an encoding stage has nothing to
rewrite), so a set-based search would rank combinations that cannot be built.

Every candidate gets a freshly constructed stage set, so no candidate inherits
another's random stream.

The ranking is by detection rate first, then by size growth and runtime. The
closing table answers the question the ranking alone does not: which stage is
doing the work, and which stages make detection worse, which for an obfuscation
tool is a real and expected outcome.

  poe benchmark -i shellcode.bin --depth 2
  poe benchmark -i payload.bin -s xor,aes,base64 --depth 3 --json bench.json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			payload, label, err := f.readInput()
			if err != nil {
				return err
			}
			if len(payload) == 0 {
				return fmt.Errorf("%w: the payload is empty", errUsage)
			}
			if f.depth < 1 {
				return fmt.Errorf("%w: --depth must be at least 1", errUsage)
			}
			pool := f.stages
			if len(pool) == 0 {
				pool = pipeline.Names()
			} else {
				pool = splitStageList(pool)
			}
			for _, n := range pool {
				if _, err := pipeline.NewStage(n, pipeline.NewContext(1, pipeline.DefaultOptions(), nil)); err != nil {
					return err
				}
			}
			candidates := analysis.AllPermutationsUpTo(pool, f.depth)
			if len(candidates) == 0 {
				return fmt.Errorf("%w: no candidate pipelines for %d stages at depth %d", errUsage, len(pool), f.depth)
			}

			ctx := f.newContext(os.Stderr)
			sc, err := f.scanner()
			if err != nil {
				return err
			}
			analyzer := analysis.New(sc)

			// Every candidate gets its own stage instances built from the same
			// seed, so the comparison is fair and the ranking reproducible.
			res, err := analyzer.Benchmark(label, payload, candidates,
				func(names []string) ([]pipeline.Stage, error) {
					return f.buildStagesWithSeed(ctx.Seed, names)
				}, ctx.Seed, f.rounds)
			if err != nil {
				return err
			}
			if !f.quiet {
				analysis.RenderBenchmark(os.Stdout, res)
			}
			if f.jsonOut != "" {
				return writeBenchmarkJSON(f.jsonOut, res)
			}
			return nil
		},
	}
	f.addIO(cmd)
	f.addPipeline(cmd)
	f.addReport(cmd)
	cmd.Flags().IntVarP(&f.depth, "depth", "d", 2, "how many stages a candidate pipeline may contain")
	return cmd
}

func writeBenchmarkJSON(path string, res *analysis.BenchmarkResult) error {
	if path == "-" {
		return analysis.WriteBenchmarkJSON(os.Stdout, res)
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return analysis.WriteBenchmarkJSON(file, res)
}
