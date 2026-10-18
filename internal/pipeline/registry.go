package pipeline

import (
	"fmt"
	"sort"
	"sync"
)

// Factory constructs a fresh stage bound to a run Context.
//
// Fresh construction per run (rather than a shared singleton) is what keeps the
// HTTP API safe under concurrency: two requests never share a stage's random
// source or its recorded details.
type Factory func(ctx *Context) (Stage, error)

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register makes a stage name resolvable by the CLI and the HTTP API. It is
// intended to be called from a package init function.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[name]; dup {
		panic("pipeline: duplicate stage registration: " + name)
	}
	registry[name] = f
}

// NewStage instantiates the named stage for the given context.
func NewStage(name string, ctx *Context) (Stage, error) {
	regMu.RLock()
	f, ok := registry[name]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown stage %q (available: %v)", name, Names())
	}
	return f(ctx)
}

// Names lists every registered stage name, sorted.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Build resolves an ordered list of stage names into a pipeline.
func Build(ctx *Context, names ...string) (*Pipeline, error) {
	stages := make([]Stage, 0, len(names))
	for _, n := range names {
		st, err := NewStage(n, ctx)
		if err != nil {
			return nil, err
		}
		stages = append(stages, st)
	}
	return New(stages...), nil
}
