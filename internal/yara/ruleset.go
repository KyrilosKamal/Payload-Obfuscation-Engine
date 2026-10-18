package yara

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

//go:embed rules/*.yar
var builtinFS embed.FS

// Match is one occurrence of a string in the scanned data, in exported form.
type Match struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

// Finding is one rule that fired.
type Finding struct {
	Rule      string             `json:"rule"`
	Tags      []string           `json:"tags,omitempty"`
	Meta      map[string]any     `json:"meta,omitempty"`
	Matches   map[string][]Match `json:"matches,omitempty"`
	Namespace string             `json:"namespace,omitempty"`
}

// Severity reads the rule's declared severity out of its metadata.
func (f Finding) Severity() string {
	if s, ok := f.Meta["severity"].(string); ok {
		return s
	}
	return "unknown"
}

// Description reads the rule's declared description.
func (f Finding) Description() string {
	if s, ok := f.Meta["description"].(string); ok {
		return s
	}
	return ""
}

// Scan evaluates every rule against b.
//
// The returned findings are in rule order, which keeps reports stable across
// runs for the same ruleset.
func (rs *Ruleset) Scan(b []byte) ([]Finding, error) {
	var findings []Finding
	// A global rule gates the whole ruleset: if one is false, nothing else is
	// reported. That is the reference implementation's behaviour and it is the
	// only sensible reading of "global".
	globalOK := true
	for _, r := range rs.Rules {
		if !r.Global {
			continue
		}
		ok, err := rs.evalRule(r, b)
		if err != nil {
			return nil, err
		}
		if !ok {
			globalOK = false
		}
	}
	if !globalOK {
		return nil, nil
	}
	for _, r := range rs.Rules {
		if r.Global || r.Private {
			continue
		}
		ok, err := rs.evalRule(r, b)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		f := Finding{
			Rule: r.Name, Tags: append([]string(nil), r.Tags...),
			Meta: r.Meta, Namespace: r.Source,
			Matches: map[string][]Match{},
		}
		for _, def := range r.Strings {
			var ms []match
			for _, m := range def.matchers {
				m.findAll(b, &ms)
			}
			if len(ms) == 0 {
				continue
			}
			exported := make([]Match, 0, len(ms))
			for _, m := range ms {
				exported = append(exported, Match{Offset: m.Off, Length: m.Len})
			}
			f.Matches[def.ID] = exported
		}
		if len(f.Matches) == 0 {
			f.Matches = nil
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (rs *Ruleset) evalRule(r *Rule, b []byte) (bool, error) {
	ctx := &scanCtx{data: b, rule: r, matches: map[string][]match{}, imports: rs.Imports}
	for _, def := range r.Strings {
		var ms []match
		for _, m := range def.matchers {
			m.findAll(b, &ms)
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].Off < ms[j].Off })
		ctx.matches[def.ID] = ms
	}
	v, err := r.Condition.eval(ctx)
	if err != nil {
		return false, fmt.Errorf("rule %s: %w", r.Name, err)
	}
	return v.truthy(), nil
}

// Names lists the rule names in order.
func (rs *Ruleset) Names() []string {
	out := make([]string, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		out = append(out, r.Name)
	}
	return out
}

var (
	builtinOnce sync.Once
	builtinRS   *Ruleset
	builtinErr  error
)

// Builtin returns the embedded ruleset.
//
// The rules are parsed once per process: parsing is cheap but not free, and the
// ruleset is immutable afterwards, so sharing it across the CLI and the HTTP
// handler is safe.
func Builtin() (*Ruleset, error) {
	builtinOnce.Do(func() {
		rs := &Ruleset{Imports: map[string]bool{}}
		entries, err := fs.Glob(builtinFS, "rules/*.yar")
		if err != nil {
			builtinErr = err
			return
		}
		sort.Strings(entries)
		for _, name := range entries {
			data, err := builtinFS.ReadFile(name)
			if err != nil {
				builtinErr = fmt.Errorf("reading %s: %w", name, err)
				return
			}
			part, err := Parse(string(data), name)
			if err != nil {
				builtinErr = err
				return
			}
			rs.Rules = append(rs.Rules, part.Rules...)
			for k, v := range part.Imports {
				rs.Imports[k] = v
			}
		}
		if len(rs.Rules) == 0 {
			builtinErr = fmt.Errorf("the embedded ruleset is empty")
			return
		}
		builtinRS = rs
	})
	return builtinRS, builtinErr
}

// MustBuiltin returns the embedded ruleset or panics, for tests and init paths
// where a broken ruleset is a build-time problem.
func MustBuiltin() *Ruleset {
	rs, err := Builtin()
	if err != nil {
		panic("yara: embedded ruleset does not compile: " + err.Error())
	}
	return rs
}

// Summary renders the ruleset's rule names and tags as a short report.
func (rs *Ruleset) Summary() string {
	var b strings.Builder
	for _, r := range rs.Rules {
		fmt.Fprintf(&b, "%-34s %s\n", r.Name, strings.Join(r.Tags, ","))
	}
	return b.String()
}
