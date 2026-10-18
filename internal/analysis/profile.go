// Package analysis measures what an obfuscation pipeline did to a payload.
//
// The measurement is deliberately two-sided:
//
//   - static shape - size, Shannon entropy overall and per chunk, byte
//     distribution, printable and null ratios. These are cheap, deterministic
//     and they are what a packer heuristic looks at.
//   - detection - which rules of a YARA ruleset still fire after each stage. A
//     payload can look completely opaque and still be caught by its own decoder
//     stub, so entropy alone is not evidence of evasion.
//
// Everything is reported per stage, because the interesting result is usually
// not the final number but the stage where detection got worse.
package analysis

import (
	"fmt"
	"math"
	"strings"

	"pobf/internal/entropy"
)

// ChunkSize is the granularity of the entropy profile. 256 bytes is small
// enough to localise a high-entropy blob inside a structured file and large
// enough that the estimate is not dominated by sampling noise.
const ChunkSize = 256

// Profile is a static description of one blob.
type Profile struct {
	Size           int     `json:"size"`
	Entropy        float64 `json:"entropy"`
	DistinctBytes  int     `json:"distinct_bytes"`
	PrintableRatio float64 `json:"printable_ratio"`
	ZeroRatio      float64 `json:"zero_ratio"`
	MeanByte       float64 `json:"mean_byte"`
	ChiSquare      float64 `json:"chi_square"`
	// ChunkEntropy holds the entropy of each ChunkSize-byte chunk.
	ChunkEntropy []float64 `json:"chunk_entropy,omitempty"`
	// PeakChunkEntropy is the highest per-chunk entropy in the blob, which is
	// the value a sliding-window packer heuristic thresholds on.
	PeakChunkEntropy float64 `json:"peak_chunk_entropy"`
	// PeakChunk is the index of that chunk, -1 when the blob is a single chunk.
	PeakChunk int `json:"peak_chunk"`
	// StructuredChunkRatio is a cheap "is there structure in here" indicator:
	// the fraction of chunks whose entropy is below 6.0 bits/byte. Structured
	// data (headers, import tables, ASCII) has low-entropy chunks; ciphertext
	// does not.
	StructuredChunkRatio float64 `json:"structured_chunk_ratio"`
}

// ProfileBytes computes the static profile of a blob.
func ProfileBytes(b []byte) Profile {
	p := Profile{Size: len(b), PeakChunk: -1}
	if len(b) == 0 {
		return p
	}
	p.Entropy = entropy.Shannon(b)
	p.PrintableRatio = entropy.PrintableRatio(b)
	p.ChiSquare = entropy.ChiSquare(b)

	var counts [256]int
	zeros := 0
	var sum float64
	for _, c := range b {
		counts[c]++
		sum += float64(c)
		if c == 0 {
			zeros++
		}
	}
	for _, c := range counts {
		if c > 0 {
			p.DistinctBytes++
		}
	}
	p.ZeroRatio = float64(zeros) / float64(len(b))
	p.MeanByte = sum / float64(len(b))

	windows := entropy.Profile(b, ChunkSize)
	if len(windows) > 1 {
		p.ChunkEntropy = make([]float64, 0, len(windows))
		structured := 0
		for _, w := range windows {
			p.ChunkEntropy = append(p.ChunkEntropy, w.Entropy)
			if w.Entropy > p.PeakChunkEntropy {
				p.PeakChunkEntropy = w.Entropy
				p.PeakChunk = len(p.ChunkEntropy) - 1
			}
			if w.Entropy < 6.0 {
				structured++
			}
		}
		p.StructuredChunkRatio = float64(structured) / float64(len(p.ChunkEntropy))
	} else {
		p.PeakChunkEntropy = p.Entropy
		if p.Entropy < 6.0 {
			p.StructuredChunkRatio = 1
		}
	}
	return p
}

// EntropyDelta is the change in whole-blob entropy.
func (p Profile) EntropyDelta(q Profile) float64 { return q.Entropy - p.Entropy }

// SizeDelta is the change in size.
func (p Profile) SizeDelta(q Profile) int { return q.Size - p.Size }

// Growth is the size multiplier, e.g. 3.5 for a payload that tripled.
func (p Profile) Growth(q Profile) float64 {
	if p.Size == 0 {
		return 0
	}
	return float64(q.Size) / float64(p.Size)
}

// sparkline renders a chunk-entropy series as Unicode block characters scaled
// to [0, 8] bits per byte.
func sparkline(values []float64) string {
	const blocks = "▁▂▃▄▅▆▇█"
	var b strings.Builder
	for _, v := range values {
		if v < 0 {
			v = 0
		}
		if v > 8 {
			v = 8
		}
		idx := int(v/8*float64(len(blocks)-1) + 0.5)
		b.WriteByte(blocks[idx])
	}
	return b.String()
}

// entropyBar renders one entropy value as a short bar, for the terminal table.
func entropyBar(v float64) string {
	const width = 20
	n := int(math.Round(v / 8 * width))
	if n < 0 {
		n = 0
	}
	if n > width {
		n = width
	}
	return strings.Repeat("#", n) + strings.Repeat(".", width-n)
}

// pct formats a ratio as a percentage.
func pct(v float64) string { return fmt.Sprintf("%5.1f%%", v*100) }
