package analysis

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"pobf/internal/yara"
)

// WriteJSON emits the report as indented JSON.
func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// DefaultDiffBytes is the byte-diff window used when a caller does not specify
// one. It is one screenful at 16 bytes per row.
const DefaultDiffBytes = 128

// RenderOptions adjusts the human-readable report.
type RenderOptions struct {
	// DiffBytes is how many leading bytes the byte diff shows. Zero means
	// DefaultDiffBytes.
	DiffBytes int
	// NoDiff drops both diff sections, which is what a caller wants when it only
	// needs the numbers.
	NoDiff bool
}

// Render writes the human-readable report: summary, per-stage table, detection
// deltas and the structural diff.
func Render(w io.Writer, rep *Report) { RenderWith(w, rep, RenderOptions{}) }

// RenderWith writes the human-readable report with explicit options.
func RenderWith(w io.Writer, rep *Report, opts RenderOptions) {
	fmt.Fprintf(w, "payload:   %s\n", rep.Label)
	fmt.Fprintf(w, "pipeline:  %s\n", strings.Join(rep.Pipeline, " -> "))
	if rep.Rounds > 1 {
		fmt.Fprintf(w, "rounds:    %d\n", rep.Rounds)
	}
	fmt.Fprintf(w, "seed:      %d\n\n", rep.Seed)

	renderSummary(w, rep)
	renderSteps(w, rep)
	renderFindings(w, rep)
	if !opts.NoDiff {
		renderDiff(w, rep, opts)
	}
	if len(rep.Notes) > 0 {
		fmt.Fprintf(w, "\nnotes\n")
		for _, n := range rep.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
}

func renderSummary(w io.Writer, rep *Report) {
	b, a := rep.Before, rep.After
	fmt.Fprintf(w, "summary\n")
	fmt.Fprintf(w, "  size        %8d B -> %8d B   (%+.1f%%, x%.2f)\n",
		b.Size, a.Size, percentChange(b.Size, a.Size), rep.Growth())
	fmt.Fprintf(w, "  entropy     %8.3f  -> %8.3f    (%+0.3f bits/byte)\n", b.Entropy, a.Entropy, a.Entropy-b.Entropy)
	fmt.Fprintf(w, "  |entropy|   %s\n", entropyBar(b.Entropy))
	fmt.Fprintf(w, "              %s\n", entropyBar(a.Entropy))
	fmt.Fprintf(w, "  printable   %s -> %s\n", pct(b.PrintableRatio), pct(a.PrintableRatio))
	fmt.Fprintf(w, "  distinct    %8d  -> %8d\n", b.DistinctBytes, a.DistinctBytes)
	fmt.Fprintf(w, "  chi-square  %8.1f  -> %8.1f    (lower is closer to random)\n", b.ChiSquare, a.ChiSquare)
	if rep.TotalRules > 0 {
		fmt.Fprintf(w, "  detections  %8d  -> %8d    of %d rules  (%s -> %s)\n",
			len(rep.FindingsBefore), len(rep.FindingsAfter), rep.TotalRules,
			pct(rep.DetectionBefore), pct(rep.DetectionAfter))
		fmt.Fprintf(w, "  evasion             %s of the firing rules cleared\n", pct(rep.EvasionGain()))
	}
	fmt.Fprintf(w, "  verified    %v\n", rep.Verified)
	fmt.Fprintf(w, "  elapsed     %.1f ms\n\n", rep.TotalMS)
}

func percentChange(from, to int) float64 {
	if from == 0 {
		return 0
	}
	return float64(to-from) / float64(from) * 100
}

func renderSteps(w io.Writer, rep *Report) {
	if len(rep.Steps) == 0 {
		return
	}
	fmt.Fprintf(w, "stages\n")
	fmt.Fprintf(w, "  %-3s %-10s %-14s %9s %9s %8s %7s %7s  %s\n",
		"#", "stage", "kind", "size", "delta", "entropy", "detect", "ms", "effect")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 100))
	for _, s := range rep.Steps {
		name := s.Name
		if rep.Rounds > 1 {
			name = fmt.Sprintf("%d.%s", s.Round, s.Name)
		}
		effect := ""
		switch {
		case s.Skipped:
			effect = "skipped: " + truncate(s.SkipReason, 30)
		default:
			var bits []string
			if n := len(s.Cleared); n > 0 {
				bits = append(bits, fmt.Sprintf("cleared %d", n))
			}
			if n := len(s.Added); n > 0 {
				bits = append(bits, fmt.Sprintf("added %d", n))
			}
			if s.StubKind != "" {
				bits = append(bits, "stub="+s.StubKind)
			}
			if s.PayloadKind == "pe" {
				bits = append(bits, "input=PE")
			}
			effect = strings.Join(bits, ", ")
		}
		fmt.Fprintf(w, "  %-3d %-10s %-14s %9d %+9d %8.3f %7s %7.1f  %s\n",
			s.Index, name, string(s.Kind), s.OutSize, s.Delta, s.EntropyOut,
			fmt.Sprintf("%d->%d", s.DetectionsBefore, s.DetectionsAfter), s.DurationMS, effect)
	}
	fmt.Fprintf(w, "\n")
}

func renderFindings(w io.Writer, rep *Report) {
	if rep.TotalRules == 0 {
		return
	}
	fmt.Fprintf(w, "detections before\n")
	writeFindingList(w, rep.FindingsBefore)
	fmt.Fprintf(w, "detections after\n")
	writeFindingList(w, rep.FindingsAfter)
}

func writeFindingList(w io.Writer, fs []yara.Finding) {
	if len(fs) == 0 {
		fmt.Fprintf(w, "  (none)\n\n")
		return
	}
	for _, f := range fs {
		desc := f.Description()
		if len(desc) > 68 {
			desc = desc[:65] + "..."
		}
		fmt.Fprintf(w, "  %-38s %-7s %s\n", f.Rule, f.Severity(), desc)
		if n := len(f.Matches); n > 0 {
			var parts []string
			for id, ms := range f.Matches {
				first := ms[0]
				extra := ""
				if len(ms) > 1 {
					extra = fmt.Sprintf("+%d", len(ms)-1)
				}
				parts = append(parts, fmt.Sprintf("%s@%d%s", id, first.Offset, extra))
			}
			fmt.Fprintf(w, "  %-38s         %s\n", "", strings.Join(parts, " "))
		}
	}
	fmt.Fprintf(w, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ---------------------------------------------------------------------------
// Diff visualisation
// ---------------------------------------------------------------------------

// Diff renders a byte-level comparison of the first n bytes of two blobs, one
// row per 16 bytes, with changed lanes marked by a caret underneath.
//
// The marker line is built from two-character lanes separated by single spaces,
// so a caret sits exactly under the byte it refers to.
func Diff(before, after []byte, n int) string {
	if n <= 0 {
		n = 128
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  offset  before                                              after\n")
	rows := (n + 15) / 16
	for row := 0; row < rows; row++ {
		off := row * 16
		fmt.Fprintf(&b, "  %06x  %-47s  %s\n", off, hexLane(before, off), hexLane(after, off))
		marks := make([]string, 0, 16)
		for i := 0; i < 16; i++ {
			switch {
			// Where only one blob has a byte at this offset there is nothing to
			// compare, so nothing is marked. A positional diff cannot honestly
			// distinguish "removed" from "the window ran past the end".
			case off+i >= len(before) || off+i >= len(after):
				marks = append(marks, "  ")
			case lane(before, off+i) != lane(after, off+i):
				marks = append(marks, "^ ")
			default:
				marks = append(marks, "  ")
			}
		}
		fmt.Fprintf(&b, "          %s\n", strings.Join(marks, " "))
	}
	shown := n
	if shown > len(before) && shown > len(after) {
		shown = max(len(before), len(after))
	}
	fmt.Fprintf(&b, "  %d bytes before, %d bytes after, first %d shown\n", len(before), len(after), shown)
	return b.String()
}

func lane(b []byte, i int) byte {
	if i >= len(b) {
		return 0
	}
	return b[i]
}

func hexLane(b []byte, off int) string {
	var parts []string
	for i := 0; i < 16; i++ {
		if off+i >= len(b) {
			parts = append(parts, "  ")
			continue
		}
		parts = append(parts, fmt.Sprintf("%02x", b[off+i]))
	}
	return strings.Join(parts, " ")
}

// StructuralDiff compares the per-chunk entropy profile of the two blobs, which
// shows where structure was destroyed and where the encoding stages reintroduced
// it. It is the "did this stage do what it claims" view.
func StructuralDiff(before, after Profile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  chunk entropy (in  %s)\n", sparkline(before.ChunkEntropy))
	fmt.Fprintf(&b, "  chunk entropy (out %s)\n", sparkline(after.ChunkEntropy))
	fmt.Fprintf(&b, "  peak chunk   %6.3f @ %-5d -> %6.3f @ %-5d\n",
		before.PeakChunkEntropy, before.PeakChunk, after.PeakChunkEntropy, after.PeakChunk)
	fmt.Fprintf(&b, "  low-entropy chunks  %s -> %s   (structure retained)\n",
		pct(before.StructuredChunkRatio), pct(after.StructuredChunkRatio))
	return b.String()
}

func renderDiff(w io.Writer, rep *Report, opts RenderOptions) {
	n := opts.DiffBytes
	if n <= 0 {
		n = DefaultDiffBytes
	}
	fmt.Fprintf(w, "structural diff\n")
	fmt.Fprint(w, StructuralDiff(rep.Before, rep.After))
	fmt.Fprintf(w, "\nbyte diff (first %d bytes)\n", n)
	if rep.BeforeBlob == nil && rep.AfterBlob == nil {
		fmt.Fprintf(w, "  (unavailable: the report was rendered without the payloads)\n")
	} else {
		fmt.Fprint(w, Diff(rep.BeforeBlob, rep.AfterBlob, n))
	}
	fmt.Fprintf(w, "\n")
}

// WriteText writes the rendered report to a file, creating parent directories.
func WriteText(path string, rep *Report) error {
	return WriteTextWith(path, rep, RenderOptions{})
}

// WriteTextWith is WriteText with explicit rendering options.
func WriteTextWith(path string, rep *Report, opts RenderOptions) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	RenderWith(f, rep, opts)
	return nil
}
