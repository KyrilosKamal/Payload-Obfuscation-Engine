package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"pobf/internal/analysis"
)

func newAnalyzeCmd() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "run a pipeline and report what it did, without keeping the artifact",
		Long: `Analyze a payload through a pipeline and print the report.

Nothing is written to disk: the artifact is measured, not saved. Use this to
compare stage orders, inspect which rules a stage clears, and see where a stage
made things worse (decoder stubs and inserted sequences are themselves
signatures, and the report says so rather than hiding it).

  poe analyze -i shellcode.bin -s xor,base64
  poe analyze -i payload.bin --json report.json --no-diff`,
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
			ctx := f.newContext(os.Stderr)
			stages, err := f.buildStages(ctx, f.stageNames())
			if err != nil {
				return err
			}
			sc, err := f.scanner()
			if err != nil {
				return err
			}
			rep, err := analysis.New(sc).Analyze(label, payload, stages, f.analysisOptions(ctx.Seed, f.rounds))
			if err != nil {
				return err
			}
			f.renderReport(os.Stdout, rep)
			return f.writeJSONReport(rep)
		},
	}
	f.addIO(cmd)
	f.addPipeline(cmd)
	f.addReport(cmd)
	return cmd
}
