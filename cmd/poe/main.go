package main

import (
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// version is reported by `poe version` and --version. It is a plain constant
// because the project is not a released library; a build can override it with
//
//	go build -ldflags "-X main.version=$(git describe --tags)"
var version = "0.1.0-dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "poe",
		Short: "multi-layer payload obfuscation engine with measured evasion",
		Long: `poe chains obfuscation stages over a payload and measures, with a YARA
ruleset, how much of the detected surface each stage removes.

The point of the tool is the measurement. Every stage reports what it did, every
run reports the detection rate before and after, and a stage that declines a
payload says so instead of quietly passing it through.

Stages, in the order the recommended pipeline uses them:

  polymorph   rewrite instructions into equivalent encodings
  deadcode    insert inert instruction sequences
  cff         flatten control flow through a dispatcher loop
  strings     mask printable literals and rebuild them at run time
  xor         encrypt with a per-run key, ship a decoder stub
  aes         encrypt with AES-256-CBC over a PBKDF2 key
  base64      re-encode with a custom alphabet, ship a decoder stub

See "poe stages" for the full catalogue and "poe rules" for what detection
currently looks like.

Use it only against systems you own or are authorised to test.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newObfuscateCmd(),
		newAnalyzeCmd(),
		newBenchmarkCmd(),
		newServeCmd(),
		newStagesCmd(),
		newRulesCmd(),
		newVersionCmd(),
	)
	return root
}

// newLogger builds the process logger. Everything goes to stderr so that stdout
// stays clean for artifacts.
func newLogger(w io.Writer, debug bool) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write([]byte("poe " + version + "\n"))
			return err
		},
	}
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// cobra already printed the error message if it came from a Run function;
		// SilenceErrors means it did not, so print it here exactly once.
		_, _ = os.Stderr.WriteString("poe: " + err.Error() + "\n")
		os.Exit(1)
	}
}
