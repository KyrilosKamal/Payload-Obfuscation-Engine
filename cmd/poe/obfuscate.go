package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"pobf/internal/analysis"
)

func newObfuscateCmd() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "obfuscate",
		Short: "run a pipeline over a payload and write the obfuscated artifact",
		Long: `Obfuscate a payload and write the artifact.

The artifact goes to stdout (or --out) and the report goes to stderr, so the
usual shell idiom captures the payload and still shows the numbers:

  poe obfuscate -i shellcode.bin -s strings,xor,base64 -o out.bin

  cat shellcode.bin | poe obfuscate -s polymorph,deadcode,cff,strings,xor > out.bin

The reported seed reproduces the run exactly: passing it back with the same
payload and the same stage list produces byte-identical output.`,
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
			names := f.stageNames()
			ctx := f.newContext(os.Stderr)
			stages, err := f.buildStages(ctx, names)
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
			f.renderReport(os.Stderr, rep)
			if err := f.writeJSONReport(rep); err != nil {
				return err
			}
			if err := f.writeArtifact(rep.AfterBlob); err != nil {
				return err
			}

			// Exit non-zero only on a real failure. A pipeline that clears
			// nothing is a legitimate result on a payload no rule matched, so it
			// is reported, not turned into an error.
			if rep.DetectionBefore > 0 && rep.DetectionAfter >= rep.DetectionBefore && !f.quiet {
				fmt.Fprintf(os.Stderr,
					"warning: detection did not fall (%.0f%% -> %.0f%%); see the per-stage table for which stage added signatures\n",
					rep.DetectionBefore*100, rep.DetectionAfter*100)
			}
			return nil
		},
	}
	f.addIO(cmd)
	f.addPipeline(cmd)
	f.addReport(cmd)
	return cmd
}
