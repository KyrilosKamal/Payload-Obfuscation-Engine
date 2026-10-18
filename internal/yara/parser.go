// Package yara implements the subset of the YARA rule language this project
// needs to measure its own output, together with a scanner that evaluates those
// rules against a byte blob.
//
// It is a deliberately partial implementation of a well-specified language, so
// the supported grammar is written down rather than assumed:
//
//	import "pe" | import "math"
//	[global] [private] rule <name> [: tag...] {
//	    meta:     <ident> = <string|number|true|false>
//	    strings:  $id = "text" [ascii] [wide] [nocase] [fullword]
//	              $id = { 4D 5A ?? ( 11 | 22 33 ) }
//	              $id = /regex/ [nocase] [wide]
//	    condition: <expr>
//	}
//
//	expr  := or ; or := and ('or' and)* ; and := not ('and' not)*
//	not   := 'not' not | cmp
//	cmp   := sum (('=='|'!='|'<='|'>='|'<'|'>') sum)?
//	sum   := term (('+'|'-') term)*
//	term  := factor (('*'|'\'|'%') factor)*
//	factor:= '(' expr ')' | 'not' factor | number | string literal
//	       | '$id' ['at' number] | '#id' | '@id' | '!id'
//	       | (number|'any'|'all') 'of' ('them'|'(' $id,... ')')
//	       | ident '(' args ')' | ident ('(' args ')')?
//
// Division is spelled `\`, as in the reference implementation: a bare `/` is the
// delimiter of a regular expression and the reference lexer therefore rejects it
// as an operator. This parser additionally accepts `/`, which cannot be
// ambiguous here, but no shipped rule uses it.
//
// The engine exists so the project can *show* what obfuscation changes about
// detectability instead of asserting it. The rules it ships are therefore
// ordinary detection rules — MZ headers, shellcode prologues, encoder stubs,
// suspicious API names, entropy heuristics — and the scanner reports which ones
// still fire after each stage.
//
// Cross-validation against the reference implementation (libyara) is a test
// concern: see TestRulesAgreeWithLibyara.
package yara

import (
	"fmt"
	"strings"
)

// Rule is a parsed YARA rule.
type Rule struct {
	Name      string
	Tags      []string
	Meta      map[string]any
	Strings   []*StringDef
	Condition Expr
	Global    bool
	Private   bool
	// Source and Line locate the rule in the ruleset for error messages.
	Source string
	Line   int
}

// Ruleset is a compiled collection of rules.
type Ruleset struct {
	Rules   []*Rule
	Imports map[string]bool
}

// parser is a hand-written recursive-descent parser over the raw rule text.
//
// It works on raw text rather than a token stream because two YARA constructs —
// hex string bodies and regular expressions — are context-sensitive: `{ 4D 5A }`
// and `/foo/` mean something only in the value position of a string definition.
type parser struct {
	src  string
	pos  int
	line int
	name string
}

func newParser(src, name string) *parser {
	return &parser{src: src, line: 1, name: name}
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("%s:%d: %s", p.name, p.line, fmt.Sprintf(format, args...))
}

func (p *parser) eof() bool { return p.pos >= len(p.src) }

func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.src[p.pos]
}

func (p *parser) at(off int) byte {
	if p.pos+off >= len(p.src) {
		return 0
	}
	return p.src[p.pos+off]
}

func (p *parser) advance() byte {
	c := p.src[p.pos]
	p.pos++
	if c == '\n' {
		p.line++
	}
	return c
}

// skipSpace consumes whitespace and both comment forms.
func (p *parser) skipSpace() {
	for !p.eof() {
		switch c := p.peek(); {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			p.advance()
		case c == '/' && p.at(1) == '/':
			for !p.eof() && p.peek() != '\n' {
				p.advance()
			}
		case c == '/' && p.at(1) == '*':
			p.advance()
			p.advance()
			for !p.eof() && !(p.peek() == '*' && p.at(1) == '/') {
				p.advance()
			}
			if !p.eof() {
				p.advance()
				p.advance()
			}
		default:
			return
		}
	}
}

// wordAt reports whether the given keyword starts at the cursor and, if so,
// consumes it. Leading whitespace and comments are skipped, because a keyword
// test is always about the next *token*.
func (p *parser) wordAt(kw string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], kw) {
		return false
	}
	end := p.pos + len(kw)
	if end < len(p.src) && isIdentByte(p.src[end]) {
		return false
	}
	for p.pos < end {
		p.advance()
	}
	return true
}

// peekWord reports whether the keyword is next, without consuming it.
func (p *parser) peekWord(kw string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], kw) {
		return false
	}
	end := p.pos + len(kw)
	if end < len(p.src) && isIdentByte(p.src[end]) {
		return false
	}
	return true
}

func isIdentByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (p *parser) expect(c byte) error {
	p.skipSpace()
	if p.eof() || p.peek() != c {
		return p.errf("expected %q, found %q", string(c), p.context(12))
	}
	p.advance()
	return nil
}

// context returns a short preview of the upcoming text for error messages.
func (p *parser) context(n int) string {
	end := p.pos + n
	if end > len(p.src) {
		end = len(p.src)
	}
	s := p.src[p.pos:end]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// simpleIdent reads one identifier without dots. Dotted names (pe.is_pe) are
// assembled by the expression parser, which is where the dot is meaningful.
func (p *parser) simpleIdent() (string, error) {
	p.skipSpace()
	start := p.pos
	for !p.eof() && isIdentByte(p.peek()) {
		p.advance()
	}
	if p.pos == start {
		return "", p.errf("expected an identifier, found %q", p.context(12))
	}
	return p.src[start:p.pos], nil
}

// number parses a decimal or hexadecimal integer, with the optional K/M/G
// multiplier suffix YARA allows.
func (p *parser) number() (float64, error) {
	p.skipSpace()
	start := p.pos
	base := 10.0
	if p.peek() == '0' && (p.at(1) == 'x' || p.at(1) == 'X') {
		p.advance()
		p.advance()
		base = 16
		digits := 0
		var v float64
		for !p.eof() && isHexDigit(p.peek()) {
			v = v*base + float64(hexVal(p.advance()))
			digits++
		}
		if digits == 0 {
			return 0, p.errf("malformed hexadecimal literal")
		}
		return p.suffix(v)
	}
	var v float64
	digits := 0
	for !p.eof() && p.peek() >= '0' && p.peek() <= '9' {
		v = v*10 + float64(p.advance()-'0')
		digits++
	}
	if digits == 0 {
		return 0, p.errf("expected a number, found %q", p.src[start:p.contextEnd()])
	}
	if p.peek() == '.' {
		p.advance()
		frac := 0.1
		for !p.eof() && p.peek() >= '0' && p.peek() <= '9' {
			v += float64(p.advance()-'0') * frac
			frac /= 10
		}
	}
	return p.suffix(v)
}

func (p *parser) contextEnd() int {
	end := p.pos + 8
	if end > len(p.src) {
		end = len(p.src)
	}
	return end
}

func (p *parser) suffix(v float64) (float64, error) {
	mult := 1.0
	switch {
	case p.wordAt("KB"):
		mult = 1024
	case p.wordAt("MB"):
		mult = 1024 * 1024
	case p.wordAt("GB"):
		mult = 1024 * 1024 * 1024
	}
	return v * mult, nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}

// quotedString parses a double-quoted string literal with the usual escapes.
func (p *parser) quotedString() (string, error) {
	p.skipSpace()
	if p.peek() != '"' {
		return "", p.errf("expected a quoted string, found %q", p.context(12))
	}
	p.advance()
	var b strings.Builder
	for {
		if p.eof() {
			return "", p.errf("unterminated string literal")
		}
		c := p.advance()
		if c == '"' {
			return b.String(), nil
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if p.eof() {
			return "", p.errf("unterminated escape sequence")
		}
		switch e := p.advance(); e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0':
			b.WriteByte(0)
		case '\\', '"':
			b.WriteByte(e)
		case 'x':
			if !isHexDigit(p.peek()) || !isHexDigit(p.at(1)) {
				return "", p.errf("malformed \\x escape")
			}
			b.WriteByte(byte(hexVal(p.advance())*16 + hexVal(p.advance())))
		default:
			b.WriteByte(e)
		}
	}
}
