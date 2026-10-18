package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"pobf/internal/pipeline"
	"pobf/internal/yara"
)

func newStagesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stages",
		Short: "list the registered stages and their capabilities",
		Long: `List every registered stage.

"reversible" means the stage embeds a decoder stub, so the engine can walk it
backwards and prove self-extraction. The instruction-level stages are
semantics-preserving rather than invertible and are correctly marked as not
reversible; a run that contains only those stages cannot demonstrate a round
trip, and the report says so instead of claiming one.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "stage\treversible\tkind\tdescription")
			for _, name := range pipeline.Names() {
				st, err := pipeline.NewStage(name, pipeline.NewContext(1, pipeline.DefaultOptions(), nil))
				if err != nil {
					return err
				}
				_, reversible := st.(pipeline.Reversible)
				fmt.Fprintf(w, "%s\t%v\t%s\t%s\n", st.Name(), reversible, st.Kind(), st.Description())
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(out, "\nrecommended order: %s\n", joinArrow(DefaultPipeline))
			return nil
		},
	}
}

func newRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "list the detection rules",
		Long: `List every rule in the built-in detection ruleset.

The ruleset is the measurement instrument. It is deliberately small and
transparent: shellcode shapes, the API names that allocation and injection
imports leave behind, decoder stubs, entropy heuristics and PE structure. A
different instrument would produce different numbers, which is why the rules
ship with the tool instead of being fetched.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rs, err := yara.Builtin()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "rule\tseverity\ttags\tdescription")
			for _, r := range rs.Rules {
				sev, _ := r.Meta["severity"].(string)
				desc, _ := r.Meta["description"].(string)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, sev, joinComma(r.Tags), desc)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(out, "\n%d rules\n", len(rs.Rules))
			return nil
		},
	}
}

func joinArrow(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += " -> "
		}
		out += n
	}
	return out
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
