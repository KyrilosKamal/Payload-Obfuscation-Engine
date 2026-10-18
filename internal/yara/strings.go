package yara

import (
	"fmt"
	"regexp"
	"strings"
)

// StringKind is the three-way split YARA makes between string definitions.
type StringKind uint8

const (
	// KindText is a quoted literal.
	KindText StringKind = iota
	// KindHex is a hex blob with wildcards, alternations and jumps.
	KindHex
	// KindRegex is a regular expression.
	KindRegex
)

// StringDef is one `$id = ...` definition.
type StringDef struct {
	ID   string
	Kind StringKind

	// Text holds the literal for KindText.
	Text string
	// Nodes holds the parsed body for KindHex.
	Nodes []HexNode
	// Regex holds the pattern for KindRegex.
	Regex string
	// Compiled is the compiled regular expression for KindRegex.
	Compiled *regexp.Regexp

	NoCase   bool
	Wide     bool
	Ascii    bool
	Fullword bool

	Line int

	// matchers are built by compile: one per requested encoding (ascii/wide).
	matchers []matcher
}

// HasExplicitAscii reports whether the rule said `ascii` rather than relying on
// the default. YARA's default for a text string is ascii-only.
func (d *StringDef) wantsAscii() bool {
	if d.Kind == KindRegex {
		return d.Ascii
	}
	return d.Ascii || !d.Wide
}

// ---------------------------------------------------------------------------
// Hex patterns
// ---------------------------------------------------------------------------

// HexNodeKind distinguishes the three things a hex blob can contain.
type HexNodeKind uint8

const (
	// HexByteNode matches one byte, possibly with wildcarded nibbles.
	HexByteNode HexNodeKind = iota
	// HexAltNode matches one of several alternatives.
	HexAltNode
	// HexJumpNode matches between Min and Max arbitrary bytes.
	HexJumpNode
)

// HexByte is a byte matcher: a value, a mask of the bits that must match, and
// whether the comparison is inverted.
//
//	0xFF exact, 0x00 `??`, 0xF0 `4?`, 0x0F `?A`, with Negate for `~4D`
type HexByte struct {
	Val    byte
	Mask   byte
	Negate bool
}

func (h HexByte) match(b byte) bool {
	if h.Negate {
		return b&h.Mask != h.Val&h.Mask
	}
	return b&h.Mask == h.Val&h.Mask
}

// HexNode is one element of a hex pattern.
type HexNode struct {
	Kind HexNodeKind
	Byte HexByte
	Alts [][]HexNode
	Min  int
	Max  int
}

// parseHexBody parses the contents of `{ ... }` (the braces already consumed).
func (p *parser) parseHexBody() ([]HexNode, error) {
	nodes, err := p.parseHexSequence('}')
	if err != nil {
		return nil, err
	}
	if err := p.expect('}'); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, p.errf("empty hex string")
	}
	return nodes, nil
}

// parseHexSequence parses elements until terminator is next.
func (p *parser) parseHexSequence(terminator byte) ([]HexNode, error) {
	var nodes []HexNode
	for {
		p.skipSpace()
		if p.eof() {
			return nil, p.errf("unterminated hex string")
		}
		c := p.peek()
		switch {
		case c == terminator || c == '|':
			return nodes, nil
		case c == '(':
			p.advance()
			alt, err := p.parseHexAlternation()
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, HexNode{Kind: HexAltNode, Alts: alt})
		case c == '[':
			p.advance()
			jump, err := p.parseHexJump()
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, jump)
		case c == '~':
			// `~4D` matches any byte whose masked bits differ from 0x4D. Note
			// that this is a comparison inversion, not a bitwise NOT of the
			// pattern byte: `~5A` must match 0x5B as well as 0x00.
			p.advance()
			hb, err := p.parseHexByte()
			if err != nil {
				return nil, err
			}
			hb.Negate = true
			nodes = append(nodes, HexNode{Kind: HexByteNode, Byte: hb})
		case isHexDigit(c) || c == '?':
			hb, err := p.parseHexByte()
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, HexNode{Kind: HexByteNode, Byte: hb})
		default:
			return nil, p.errf("unexpected %q inside a hex string", string(c))
		}
	}
}

func (p *parser) parseHexAlternation() ([][]HexNode, error) {
	var alts [][]HexNode
	for {
		seq, err := p.parseHexSequence(')')
		if err != nil {
			return nil, err
		}
		if len(seq) == 0 {
			return nil, p.errf("empty alternative in hex string")
		}
		alts = append(alts, seq)
		p.skipSpace()
		if p.peek() == '|' {
			p.advance()
			continue
		}
		break
	}
	if err := p.expect(')'); err != nil {
		return nil, err
	}
	return alts, nil
}

func (p *parser) parseHexJump() (HexNode, error) {
	p.skipSpace()
	lo, err := p.number()
	if err != nil {
		return HexNode{}, p.errf("expected a jump length")
	}
	hi := lo
	p.skipSpace()
	if p.peek() == '-' {
		p.advance()
		hi, err = p.number()
		if err != nil {
			return HexNode{}, p.errf("expected a jump upper bound")
		}
	}
	if err := p.expect(']'); err != nil {
		return HexNode{}, err
	}
	if hi < lo {
		return HexNode{}, p.errf("jump range %v-%v is inverted", lo, hi)
	}
	return HexNode{Kind: HexJumpNode, Min: int(lo), Max: int(hi)}, nil
}

func (p *parser) parseHexByte() (HexByte, error) {
	var hb HexByte
	for i := 0; i < 2; i++ {
		c := p.peek()
		shift := uint(4 - 4*i)
		switch {
		case c == '?':
			p.advance()
			// A wildcard nibble contributes no mask bits.
		case isHexDigit(c):
			hb.Val |= byte(hexVal(p.advance())) << shift
			hb.Mask |= 0xF << shift
		default:
			return hb, p.errf("unexpected %q inside a hex byte", string(c))
		}
	}
	return hb, nil
}

// hexNodesString renders a hex pattern back to source form, for reporting.
func hexNodesString(nodes []HexNode) string {
	var parts []string
	for _, n := range nodes {
		switch n.Kind {
		case HexByteNode:
			b := fmt.Sprintf("%02X/%02X", n.Byte.Val, n.Byte.Mask)
			if n.Byte.Negate {
				b = "~" + b
			}
			parts = append(parts, b)
		case HexAltNode:
			var alts []string
			for _, a := range n.Alts {
				alts = append(alts, hexNodesString(a))
			}
			parts = append(parts, "("+strings.Join(alts, " | ")+")")
		case HexJumpNode:
			if n.Min == n.Max {
				parts = append(parts, fmt.Sprintf("[%d]", n.Min))
			} else {
				parts = append(parts, fmt.Sprintf("[%d-%d]", n.Min, n.Max))
			}
		}
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

// match is one occurrence of a string in the scanned data.
type match struct {
	Off int
	Len int
}

// matcher finds occurrences of one encoded form of a string definition.
type matcher interface {
	findAll(b []byte, out *[]match)
}

// compile builds the matchers for a definition. It is called once, when the
// ruleset is compiled, so scanning does not pay for pattern interpretation.
func (d *StringDef) compile() error {
	d.matchers = nil
	switch d.Kind {
	case KindText:
		if d.Text == "" {
			return fmt.Errorf("string %s has an empty literal", d.ID)
		}
	case KindHex:
		if len(d.Nodes) == 0 {
			return fmt.Errorf("string %s has an empty hex body", d.ID)
		}
	case KindRegex:
		pat := d.Regex
		// YARA requires `/` to be escaped inside a regular expression; Go's
		// regexp does not accept the `\/` escape at all, so translate it. Every
		// other escape in the supported subset means the same thing in both
		// dialects, and the cross-validation test against libyara enforces that.
		pat = strings.ReplaceAll(pat, `\/`, `/`)
		flags := "(?s)"
		if d.NoCase {
			flags += "(?i)"
		}
		re, err := regexp.Compile(flags + pat)
		if err != nil {
			return fmt.Errorf("string %s: %w", d.ID, err)
		}
		d.Compiled = re
		// Go's regexp has no notion of `fullword`; enforce it in the matcher.
		if !d.Wide {
			d.matchers = append(d.matchers, &regexMatcher{re: re, fullword: d.Fullword})
			return nil
		}
	}
	if d.Kind == KindRegex && d.Wide {
		// A wide regex is not meaningfully expressible by transforming the
		// pattern, so YARA itself applies it to the raw bytes. Match that.
		d.matchers = append(d.matchers, &regexMatcher{re: d.Compiled, fullword: d.Fullword})
		return nil
	}

	if d.wantsAscii() {
		d.matchers = append(d.matchers, d.newByteMatcher(false))
	}
	if d.Wide {
		d.matchers = append(d.matchers, d.newByteMatcher(true))
	}
	if len(d.matchers) == 0 {
		return fmt.Errorf("string %s requests no encoding", d.ID)
	}
	return nil
}

func (d *StringDef) newByteMatcher(wide bool) matcher {
	switch d.Kind {
	case KindText:
		return &textMatcher{needle: encodeWide([]byte(d.Text), wide), nocase: d.NoCase, wide: wide, fullword: d.Fullword}
	default:
		return &hexMatcher{nodes: d.Nodes, wide: wide}
	}
}

// encodeWide expands a byte slice to UTF-16LE when wide is set.
func encodeWide(b []byte, wide bool) []byte {
	if !wide {
		return b
	}
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c, 0)
	}
	return out
}

// textMatcher matches a literal, optionally case-insensitively, optionally in
// UTF-16LE, optionally only on word boundaries.
type textMatcher struct {
	needle   []byte
	nocase   bool
	wide     bool
	fullword bool
}

func (m *textMatcher) findAll(b []byte, out *[]match) {
	if len(m.needle) == 0 {
		return
	}
	// The cursor advances by one byte after every match, not by the needle
	// length: the reference implementation counts *overlapping* occurrences, so
	// `#a` for "aaaa" against "aaaaaaaa" is 5, not 2. Getting this wrong makes
	// every count-based rule disagree with libyara, which is how this was
	// caught.
	for i := 0; i+len(m.needle) <= len(b); i++ {
		ok := true
		for j := range m.needle {
			c := b[i+j]
			w := m.needle[j]
			if c == w {
				continue
			}
			if !m.nocase || lower(c) != lower(w) {
				ok = false
				break
			}
		}
		if ok && (!m.fullword || wordBounded(b, i, len(m.needle))) {
			*out = append(*out, match{Off: i, Len: len(m.needle)})
		}
	}
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// wordBounded reports whether the range sits between non-word characters.
//
// For a wide match the neighbouring bytes are inspected in pairs, which is what
// makes `fullword wide` behave like the reference implementation rather than
// like a naive byte test.
func wordBounded(b []byte, off, n int) bool {
	if off > 0 && isWordByte(b[off-1]) {
		return false
	}
	end := off + n
	if end < len(b) && isWordByte(b[end]) {
		return false
	}
	return true
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// hexMatcher matches a hex pattern by backtracking over jumps and alternations.
type hexMatcher struct {
	nodes []HexNode
	wide  bool
}

func (m *hexMatcher) findAll(b []byte, out *[]match) {
	// Every offset is a candidate start, and the cursor advances by one byte
	// after a match, so overlapping occurrences are counted, as in the
	// reference implementation.
	for i := 0; i < len(b); i++ {
		ends := matchNodes(b, i, m.nodes)
		if len(ends) == 0 {
			continue
		}
		// ends is in grammar order: alternatives and jump lengths are tried in
		// the order they were written. The reference implementation commits to
		// the first successful path, so the first end that consumes at least one
		// byte is the length it reports - `{ 4D [1-3] 90 }` against
		// `4D 01 90 90` has length 3, not 4.
		for _, e := range ends {
			if e > i {
				*out = append(*out, match{Off: i, Len: e - i})
				break
			}
		}
	}
}

// matchNodes returns every offset at which nodes can finish when matched
// starting at pos.
func matchNodes(b []byte, pos int, nodes []HexNode) []int {
	if len(nodes) == 0 {
		return []int{pos}
	}
	n, rest := nodes[0], nodes[1:]
	switch n.Kind {
	case HexByteNode:
		if pos >= len(b) || !n.Byte.match(b[pos]) {
			return nil
		}
		return matchNodes(b, pos+1, rest)
	case HexAltNode:
		var out []int
		for _, alt := range n.Alts {
			for _, after := range matchNodes(b, pos, alt) {
				out = append(out, matchNodes(b, after, rest)...)
			}
		}
		return out
	default:
		var out []int
		for k := n.Min; k <= n.Max; k++ {
			if pos+k > len(b) {
				break
			}
			out = append(out, matchNodes(b, pos+k, rest)...)
		}
		return out
	}
}

// regexMatcher wraps Go's regexp engine.
type regexMatcher struct {
	re       *regexp.Regexp
	fullword bool
}

func (m *regexMatcher) findAll(b []byte, out *[]match) {
	// A regex is tried at every offset rather than scanned for non-overlapping
	// leftmost matches, because the reference implementation reports overlapping
	// occurrences: /abab/ against "abababab" matches 3 times.
	for i := 0; i < len(b); i++ {
		loc := m.re.FindIndex(b[i:])
		if loc == nil || loc[0] != 0 || loc[1] == 0 {
			continue
		}
		if m.fullword && !wordBounded(b, i, loc[1]) {
			continue
		}
		*out = append(*out, match{Off: i, Len: loc[1]})
	}
}

// String summary helpers used by the report.

// Source renders the definition back to a readable YARA-ish form.
func (d *StringDef) Source() string {
	switch d.Kind {
	case KindText:
		s := fmt.Sprintf("%s = %q", d.ID, d.Text)
		return s + d.modifierString()
	case KindRegex:
		return fmt.Sprintf("%s = /%s/%s", d.ID, d.Regex, d.modifierString())
	default:
		return fmt.Sprintf("%s = { %s }", d.ID, hexNodesString(d.Nodes))
	}
}

func (d *StringDef) modifierString() string {
	var mods []string
	if d.NoCase {
		mods = append(mods, "nocase")
	}
	if d.Wide {
		mods = append(mods, "wide")
	}
	if d.Ascii {
		mods = append(mods, "ascii")
	}
	if d.Fullword {
		mods = append(mods, "fullword")
	}
	if len(mods) == 0 {
		return ""
	}
	return " " + strings.Join(mods, " ")
}

// CountLiteralBytes reports how many literal bytes a definition contributes, to
// keep trivially-short rules out of the ruleset.
func (d *StringDef) CountLiteralBytes() int {
	switch d.Kind {
	case KindText:
		return len(d.Text)
	case KindHex:
		n := 0
		for _, node := range d.Nodes {
			if node.Kind == HexByteNode && node.Byte.Mask == 0xFF {
				n++
			}
		}
		return n
	default:
		return len(d.Regex)
	}
}

// Bytes returns the pattern's ascii form, for tests that assert a rule cannot
// match its own literal.
func (d *StringDef) Bytes() []byte {
	switch d.Kind {
	case KindText:
		return []byte(d.Text)
	case KindRegex:
		return []byte(d.Regex)
	default:
		var out []byte
		for _, node := range d.Nodes {
			if node.Kind == HexByteNode && node.Byte.Mask == 0xFF {
				out = append(out, node.Byte.Val)
			}
		}
		return out
	}
}
