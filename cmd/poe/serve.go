package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"pobf/internal/api"
)

func newServeCmd() *cobra.Command {
	f := &flags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "run the HTTP API",
		Long: `Serve the engine over HTTP.

  GET  /healthz         liveness plus the size of the stage and rule sets
  GET  /v1/stages       the stage catalogue with capability flags
  GET  /v1/rules        the detection ruleset
  POST /v1/obfuscate    run a pipeline, return the artifact and the report
  POST /v1/analyze      run a pipeline, return the report only
  POST /v1/benchmark    rank pipeline permutations by measured evasion

The three POST endpoints accept the payload three ways:

  multipart/form-data with a "payload" file part and an optional "config" JSON
  field (individual scalar fields such as stages=, seed= and rounds= also work)

  application/json with "payload_base64" or "payload_hex" alongside the config

  any other content type, with the body as the payload and the configuration in
  the query string:

    curl --data-binary @shellcode.bin \
      'http://127.0.0.1:8080/v1/obfuscate?stages=strings,xor,base64&seed=7'

  curl -F payload=@shellcode.bin \
      -F 'config={"stages":["xor","base64"],"seed":7}' \
      http://127.0.0.1:8080/v1/obfuscate

The server defaults to a loopback address and refuses more concurrent runs than
it has slots for (429) rather than queueing them, because an obfuscation run is
CPU-bound and a queue would only convert load into latency.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			handler, err := api.New(api.Options{
				MaxPayload:    f.maxPayload,
				MaxConcurrent: f.maxConcurrent,
				MaxCandidates: f.maxCandidates,
				Logger:        newLogger(os.Stderr, f.verbose),
			})
			if err != nil {
				return err
			}

			srv := &http.Server{
				Addr:              f.addr,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       5 * time.Minute,
				// No write timeout: a benchmark over a large candidate set is
				// legitimately slow, and cutting the connection would lose the
				// result rather than bound the work.
				IdleTimeout: 2 * time.Minute,
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
			}()

			fmt.Fprintf(os.Stderr, "poe listening on http://%s\n", f.addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.addr, "addr", "127.0.0.1:8080",
		"address to listen on; the default is loopback on purpose")
	cmd.Flags().Int64Var(&f.maxPayload, "max-payload", api.DefaultMaxPayload,
		"largest accepted upload in bytes")
	cmd.Flags().IntVar(&f.maxConcurrent, "max-concurrent", api.DefaultMaxConcurrent,
		"how many runs may execute at once before requests are refused with 429")
	cmd.Flags().IntVar(&f.maxCandidates, "max-candidates", api.DefaultMaxCandidates,
		"cap on the candidate count of a single benchmark request")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "log every request")
	return cmd
}
