// Package entropy implements the byte-level statistics used for reporting and
// for the entropy-based YARA rules.
//
// Shannon entropy is the canonical first-order heuristic antivirus engines use
// to flag packed or encrypted content: a uniformly random byte stream carries
// 8 bits of entropy per byte, whereas ordinary compiled code sits around 6 and
// plain text well below that. It is a cheap, weak signal - which is exactly why
// obfuscation frameworks chase it and detection engineers distrust it.
package entropy

import "math"

// Shannon returns the Shannon entropy of b in bits per byte (0..8).
func Shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Window is an entropy measurement over a slice of the payload.
type Window struct {
	Offset  int     `json:"offset"`
	Size    int     `json:"size"`
	Entropy float64 `json:"entropy"`
}

// Profile splits b into windows of the given size and measures each one. The
// final window is whatever remains. This is how a real analyst eyeballs where
// the packed/encrypted region of a sample starts.
func Profile(b []byte, size int) []Window {
	if size <= 0 || len(b) == 0 {
		return nil
	}
	var out []Window
	for off := 0; off < len(b); off += size {
		end := off + size
		if end > len(b) {
			end = len(b)
		}
		out = append(out, Window{Offset: off, Size: end - off, Entropy: Shannon(b[off:end])})
	}
	return out
}

// MaxWindow returns the highest-entropy window in the profile, which is the
// value an AV heuristic rule would threshold on.
func MaxWindow(profile []Window) Window {
	var best Window
	for _, w := range profile {
		if w.Entropy > best.Entropy {
			best = w
		}
	}
	return best
}

// PrintableRatio is the fraction of bytes in b that are printable ASCII. YARA
// rules for strings and shellcode commonly pair entropy with this measure,
// because encrypted payloads lose their printable runs.
func PrintableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	p := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			p++
		}
	}
	return float64(p) / float64(len(b))
}

// ChiSquare measures how far a byte distribution is from uniform. Unlike
// entropy it is sensitive to small sample sizes, which is why packer detectors
// frequently use it instead. Values near 0 mean "indistinguishable from
// random".
func ChiSquare(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	expected := float64(len(b)) / 256.0
	var chi float64
	for _, c := range counts {
		d := float64(c) - expected
		chi += d * d / expected
	}
	return chi
}
