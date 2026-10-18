package yara

import (
	"fmt"
	"strings"
)

// Parse compiles the rules in src. name is used in error messages.
func Parse(src, name string) (*Ruleset, error) {
	p := newParser(src, name)
	rs := &Ruleset{Imports: map[string]bool{}}
	for {
		p.skipSpace()
		if p.eof() {
			break
		}
		switch {
		case p.wordAt("import"):
			mod, err := p.quotedString()
			if err != nil {
				return nil, err
			}
			rs.Imports[mod] = true
		case p.peekWord("include"):
			return nil, p.errf("`include` is not supported by this implementation")
		default:
			r, err := p.parseRule()
			if err != nil {
				return nil, err
			}
			r.Source = name
			rs.Rules = append(rs.Rules, r)
		}
	}
	for _, r := range rs.Rules {
		if err := checkReferences(r); err != nil {
			return nil, p.errf("rule %s: %v", r.Name, err)
		}
		if err := validateRefs(r, rs.Imports); err != nil {
			return nil, p.errf("rule %s: %v", r.Name, err)
		}
	}
	return rs, nil
}

// Module and builtin references this engine knows about. The sets exist so a
// typo or an unsupported property is a load-time error rather than a rule that
// silently evaluates to false, which is how the reference implementation treats
// them.
var (
	peVars = map[string]bool{
		"pe.is_pe": true, "pe.is_32bit": true, "pe.is_64bit": true,
		"pe.machine": true, "pe.number_of_sections": true, "pe.timestamp": true,
		"pe.entry_point": true, "pe.number_of_imported_functions": true,
		"pe.imports": true, "pe.sections": true, "pe.section_index": true,
	}
	peSectionProps = map[string]bool{
		"raw_data_offset": true, "raw_data_size": true, "virtual_size": true,
		"virtual_address": true, "characteristics": true, "name": true,
		"full_name": true,
	}
	mathFuncs = map[string]bool{
		"math.entropy": true, "math.mean": true, "math.min": true,
		"math.max": true, "math.deviation": true,
	}
)

// validateRefs walks every condition and rejects identifiers, module references
// and properties this engine does not implement.
//
// Doing this at parse time rather than during evaluation matters: a rule that
// references something unsupported must fail loudly, because the alternative is
// a scan that quietly reports "no match" and a detection rate that looks better
// than it really is.
func validateRefs(r *Rule, imports map[string]bool) error {
	var walk func(Expr) error
	walk = func(e Expr) error {
		switch n := e.(type) {
		case *strRef:
			if n.index != nil {
				return walk(n.index)
			}
		case *strAt:
			if err := walk(n.ref); err != nil {
				return err
			}
			return walk(n.offset)
		case *unaryExpr:
			return walk(n.x)
		case *binaryExpr:
			if err := walk(n.l); err != nil {
				return err
			}
			return walk(n.r)
		case *ofExpr:
			if n.n != nil {
				return walk(n.n)
			}
		case *refExpr:
			for _, a := range n.args {
				if err := walk(a); err != nil {
					return err
				}
			}
			if n.index != nil {
				if err := walk(n.index); err != nil {
					return err
				}
			}
			return checkRef(n, imports)
		}
		return nil
	}
	return walk(r.Condition)
}

func checkRef(e *refExpr, imports map[string]bool) error {
	switch {
	case e.name == "filesize" || e.name == "entrypoint":
		return nil
	case isIntReader(e.name):
		if !e.hasArgs || len(e.args) != 1 {
			return fmt.Errorf("%s takes exactly one argument", e.name)
		}
		return nil
	case strings.HasPrefix(e.name, "pe."):
		if !imports["pe"] {
			return fmt.Errorf("rule uses the %q module without importing it", "pe")
		}
		if !peVars[e.name] {
			return fmt.Errorf("unsupported pe module reference %q", e.name)
		}
		if e.name == "pe.sections" {
			if e.index == nil {
				return fmt.Errorf("pe.sections requires an index, as in pe.sections[0].raw_data_size")
			}
			if e.prop == "" {
				return fmt.Errorf("pe.sections needs a property, as in pe.sections[0].raw_data_size")
			}
			if !peSectionProps[e.prop] {
				return fmt.Errorf("unsupported pe.sections property %q", e.prop)
			}
		}
		return nil
	case strings.HasPrefix(e.name, "math."):
		if !imports["math"] {
			return fmt.Errorf("rule uses the %q module without importing it", "math")
		}
		if !mathFuncs[e.name] {
			return fmt.Errorf("unsupported math function %q", e.name)
		}
		if !e.hasArgs || len(e.args) != 2 {
			return fmt.Errorf("%s takes two arguments", e.name)
		}
		return nil
	default:
		return fmt.Errorf("unknown identifier or function %q", e.name)
	}
}

func (p *parser) parseRule() (*Rule, error) {
	r := &Rule{Meta: map[string]any{}}
	for {
		switch {
		case p.wordAt("global"):
			r.Global = true
			continue
		case p.wordAt("private"):
			r.Private = true
			continue
		}
		break
	}
	p.skipSpace()
	line := p.line
	if !p.wordAt("rule") {
		return nil, p.errf("expected `rule`, `import` or end of file, found %q", p.context(16))
	}
	r.Line = line
	name, err := p.simpleIdent()
	if err != nil {
		return nil, err
	}
	r.Name = name

	p.skipSpace()
	if p.peek() == ':' {
		p.advance()
		for {
			p.skipSpace()
			if p.peek() == '{' {
				break
			}
			tag, err := p.simpleIdent()
			if err != nil {
				return nil, err
			}
			r.Tags = append(r.Tags, tag)
		}
	}
	if err := p.expect('{'); err != nil {
		return nil, err
	}
	if err := p.parseSections(r); err != nil {
		return nil, err
	}
	if err := p.expect('}'); err != nil {
		return nil, err
	}
	for _, s := range r.Strings {
		if err := s.compile(); err != nil {
			return nil, p.errf("rule %s: %v", r.Name, err)
		}
	}
	if r.Condition == nil {
		return nil, p.errf("rule %s has no condition section", r.Name)
	}
	return r, nil
}

func (p *parser) parseSections(r *Rule) error {
	seen := map[string]bool{}
	for {
		p.skipSpace()
		switch {
		case p.peek() == '}':
			return nil
		case p.wordAt("meta:"):
			if seen["meta"] {
				return p.errf("duplicate meta section")
			}
			seen["meta"] = true
			if err := p.parseMetaSection(r); err != nil {
				return err
			}
		case p.wordAt("strings:"):
			if seen["strings"] {
				return p.errf("duplicate strings section")
			}
			seen["strings"] = true
			if err := p.parseStringsSection(r); err != nil {
				return err
			}
		case p.wordAt("condition:"):
			if seen["condition"] {
				return p.errf("duplicate condition section")
			}
			seen["condition"] = true
			expr, err := p.parseExpr()
			if err != nil {
				return err
			}
			r.Condition = expr
		default:
			return p.errf("expected a section keyword (meta:, strings:, condition:) or `}`, found %q", p.context(16))
		}
	}
}

func (p *parser) atSectionEnd() bool {
	return p.peekWord("meta:") || p.peekWord("strings:") || p.peekWord("condition:")
}

func (p *parser) parseMetaSection(r *Rule) error {
	for {
		p.skipSpace()
		if p.peek() == '}' || p.atSectionEnd() {
			return nil
		}
		key, err := p.simpleIdent()
		if err != nil {
			return err
		}
		if err := p.expect('='); err != nil {
			return err
		}
		p.skipSpace()
		switch {
		case p.peek() == '"':
			v, err := p.quotedString()
			if err != nil {
				return err
			}
			r.Meta[key] = v
		case p.wordAt("true"):
			r.Meta[key] = true
		case p.wordAt("false"):
			r.Meta[key] = false
		default:
			v, err := p.number()
			if err != nil {
				return err
			}
			r.Meta[key] = v
		}
	}
}

func (p *parser) parseStringsSection(r *Rule) error {
	for {
		p.skipSpace()
		if p.peek() == '}' || p.atSectionEnd() {
			return nil
		}
		if p.peek() != '$' {
			return p.errf("expected a string identifier starting with `$`, found %q", p.context(16))
		}
		p.advance()
		suffix, err := p.simpleIdentNoDot()
		if err != nil {
			return err
		}
		def := &StringDef{ID: "$" + suffix, Line: p.line}
		if err := p.expect('='); err != nil {
			return err
		}
		p.skipSpace()
		switch {
		case p.peek() == '"':
			def.Kind = KindText
			v, err := p.quotedString()
			if err != nil {
				return err
			}
			def.Text = v
		case p.peek() == '{':
			p.advance()
			def.Kind = KindHex
			nodes, err := p.parseHexBody()
			if err != nil {
				return err
			}
			def.Nodes = nodes
		case p.peek() == '/':
			def.Kind = KindRegex
			re, err := p.regexLiteral()
			if err != nil {
				return err
			}
			def.Regex = re
		default:
			return p.errf("expected a quoted string, a hex blob or a regular expression, found %q", p.context(16))
		}
		if err := p.parseStringModifiers(def); err != nil {
			return err
		}
		r.Strings = append(r.Strings, def)
	}
}

// simpleIdentNoDot reads an identifier that may be empty, which is how YARA
// allows the bare `$` identifier.
func (p *parser) simpleIdentNoDot() (string, error) {
	p.skipSpace()
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			p.advance()
			continue
		}
		break
	}
	return p.src[start:p.pos], nil
}

func (p *parser) parseStringModifiers(def *StringDef) error {
	for {
		p.skipSpace()
		switch {
		case p.wordAt("nocase"):
			def.NoCase = true
		case p.wordAt("wide"):
			def.Wide = true
		case p.wordAt("ascii"):
			def.Ascii = true
		case p.wordAt("fullword"):
			def.Fullword = true
		case p.wordAt("private"):
			// Accepted and ignored: private affects reporting only.
		default:
			return nil
		}
	}
}

// regexLiteral reads /.../ including escapes and character classes.
func (p *parser) regexLiteral() (string, error) {
	if p.peek() != '/' {
		return "", p.errf("expected a regular expression")
	}
	p.advance()
	var b strings.Builder
	inClass := false
	for {
		if p.eof() {
			return "", p.errf("unterminated regular expression")
		}
		c := p.advance()
		switch {
		case c == '\\':
			if p.eof() {
				return "", p.errf("unterminated escape in regular expression")
			}
			b.WriteByte(c)
			b.WriteByte(p.advance())
		case c == '[':
			inClass = true
			b.WriteByte(c)
		case c == ']':
			inClass = false
			b.WriteByte(c)
		case c == '/' && !inClass:
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
}

// ---------------------------------------------------------------------------
// Expression grammar
// ---------------------------------------------------------------------------

func (p *parser) parseExpr() (Expr, error) { return p.parseOr() }

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.wordAt("or") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{op: "or", l: left, r: right}
	}
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.wordAt("and") {
			return left, nil
		}
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{op: "and", l: left, r: right}
	}
}

func (p *parser) parseNot() (Expr, error) {
	p.skipSpace()
	if p.wordAt("not") {
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{op: "not", x: x}, nil
	}
	return p.parseComparison()
}

var comparisonOps = []string{"==", "!=", "<=", ">=", "<", ">"}

func (p *parser) parseComparison() (Expr, error) {
	left, err := p.parseSum()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	for _, op := range comparisonOps {
		if strings.HasPrefix(p.src[p.pos:], op) {
			for range op {
				p.advance()
			}
			right, err := p.parseSum()
			if err != nil {
				return nil, err
			}
			return &binaryExpr{op: op, l: left, r: right}, nil
		}
	}
	return left, nil
}

func (p *parser) parseSum() (Expr, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		c := p.peek()
		if c != '+' && c != '-' {
			return left, nil
		}
		p.advance()
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{op: string(c), l: left, r: right}
	}
}

func (p *parser) parseTerm() (Expr, error) {
	left, err := p.parseFactor()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		c := p.peek()
		if c != '*' && c != '/' && c != '%' && c != '\\' {
			return left, nil
		}
		// YARA spells division with a backslash, because a bare `/` is the
		// delimiter of a regular expression and the lexer cannot always tell
		// the two apart. `\` is what the rules in this project use and what the
		// cross-validation test exercises. `/` is additionally accepted here as
		// an extension: it is unambiguous in this hand-written parser, and
		// rejecting it would only make some correct-looking rules unusable.
		// Shipped rules never use it, so the extension cannot hide a divergence
		// from libyara.
		p.advance()
		right, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		op := string(c)
		if op == "\\" {
			op = "/"
		}
		left = &binaryExpr{op: op, l: left, r: right}
	}
}

func (p *parser) parseFactor() (Expr, error) {
	p.skipSpace()
	if p.eof() {
		return nil, p.errf("unexpected end of input in a condition")
	}
	switch c := p.peek(); {
	case c == '(':
		p.advance()
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		return e, nil
	case c == '-' && !isDigitOrDot(p.at(1)):
		p.advance()
		x, err := p.parseFactor()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{op: "-", x: x}, nil
	case c == '$' || c == '#' || c == '@' || c == '!':
		return p.parseStringRef()
	case p.wordAt("not"):
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{op: "not", x: x}, nil
	case p.wordAt("true"):
		return &litBool{v: true}, nil
	case p.wordAt("false"):
		return &litBool{v: false}, nil
	case p.wordAt("any"):
		return p.parseOf(quantAny, nil)
	case p.wordAt("all"):
		return p.parseOf(quantAll, nil)
	case p.wordAt("them"):
		return nil, p.errf("`them` is only valid after `of`")
	case p.wordAt("for"):
		return nil, p.errf("`for` loops are not supported by this implementation")
	case p.peek() == '"':
		s, err := p.quotedString()
		if err != nil {
			return nil, err
		}
		return &litStr{v: s}, nil
	case isDigitOrDot(c):
		n, err := p.number()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.peekWord("of") {
			return p.parseOf(quantN, &litNum{v: n})
		}
		return &litNum{v: n}, nil
	default:
		return p.parseRef()
	}
}

func isDigitOrDot(c byte) bool { return (c >= '0' && c <= '9') || c == '.' }

// parseOf parses the tail of a quantifier: `of them` or `of ($a, $b)`.
func (p *parser) parseOf(kind quantKind, n Expr) (Expr, error) {
	if !p.wordAt("of") {
		return nil, p.errf("expected `of`")
	}
	p.skipSpace()
	e := &ofExpr{quant: kind, n: n}
	if p.wordAt("them") {
		e.them = true
		return e, nil
	}
	if p.peek() != '(' {
		return nil, p.errf("expected `them` or a string list after `of`")
	}
	p.advance()
	for {
		p.skipSpace()
		if p.peek() == ')' {
			p.advance()
			return e, nil
		}
		if p.peek() != '$' {
			return nil, p.errf("expected a string identifier in the `of` list")
		}
		p.advance()
		suffix, _ := p.simpleIdentNoDot()
		e.ids = append(e.ids, "$"+suffix)
		p.skipSpace()
		if p.peek() == ',' {
			p.advance()
			continue
		}
		if p.peek() == ')' {
			p.advance()
			return e, nil
		}
		return nil, p.errf("expected `,` or `)` in the `of` list")
	}
}

func (p *parser) parseStringRef() (Expr, error) {
	prefix := p.advance()
	suffix, _ := p.simpleIdentNoDot()
	id := "$" + suffix
	ref := &strRef{id: id}
	switch prefix {
	case '$':
		ref.op = opMatched
	case '#':
		ref.op = opCount
	case '@':
		ref.op = opOffset
	case '!':
		ref.op = opLength
	}
	p.skipSpace()
	if p.peek() == '[' {
		p.advance()
		idx, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(']'); err != nil {
			return nil, err
		}
		ref.index = idx
	}
	if ref.op == opMatched {
		p.skipSpace()
		if p.wordAt("at") {
			off, err := p.parseSum()
			if err != nil {
				return nil, err
			}
			return &strAt{ref: ref, offset: off}, nil
		}
	}
	return ref, nil
}

func (p *parser) parseRef() (Expr, error) {
	first, err := p.simpleIdentNoDot()
	if err != nil {
		return nil, err
	}
	parts := []string{first}
	for {
		p.skipSpace()
		if p.peek() != '.' {
			break
		}
		p.advance()
		next, err := p.simpleIdentNoDot()
		if err != nil {
			return nil, err
		}
		parts = append(parts, next)
	}
	e := &refExpr{name: strings.Join(parts, ".")}
	p.skipSpace()
	if p.peek() == '[' {
		p.advance()
		idx, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(']'); err != nil {
			return nil, err
		}
		e.index = idx
	}
	p.skipSpace()
	if p.peek() == '.' {
		p.advance()
		prop, err := p.simpleIdentNoDot()
		if err != nil {
			return nil, err
		}
		e.prop = prop
	}
	p.skipSpace()
	if p.peek() == '(' {
		e.hasArgs = true
		p.advance()
		p.skipSpace()
		if p.peek() == ')' {
			p.advance()
			return e, nil
		}
		for {
			arg, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			e.args = append(e.args, arg)
			p.skipSpace()
			if p.peek() == ',' {
				p.advance()
				continue
			}
			if p.peek() == ')' {
				p.advance()
				return e, nil
			}
			return nil, p.errf("expected `,` or `)` in the argument list of %s", e.name)
		}
	}
	return e, nil
}

// checkReferences verifies that the condition's string identifiers and the
// strings section agree in both directions: nothing is used that is not
// defined, and nothing is defined that is not used. The reference
// implementation treats both as errors, and an unreferenced string is almost
// always a rule-authoring mistake rather than an intention.
func checkReferences(r *Rule) error {
	defined := map[string]bool{}
	for _, s := range r.Strings {
		if defined[s.ID] {
			return fmt.Errorf("string %s is defined twice", s.ID)
		}
		defined[s.ID] = true
	}
	used := map[string]bool{}
	allUsed := false
	var walk func(Expr) error
	walk = func(e Expr) error {
		switch n := e.(type) {
		case *strRef:
			if !defined[n.id] {
				return fmt.Errorf("condition refers to %s, which is not defined in the strings section", n.id)
			}
			used[n.id] = true
		case *strAt:
			return walk(n.ref)
		case *unaryExpr:
			return walk(n.x)
		case *binaryExpr:
			if err := walk(n.l); err != nil {
				return err
			}
			return walk(n.r)
		case *ofExpr:
			if n.them {
				allUsed = true
			}
			for _, id := range n.ids {
				if !defined[id] {
					return fmt.Errorf("condition refers to %s, which is not defined in the strings section", id)
				}
				used[id] = true
			}
			if n.n != nil {
				return walk(n.n)
			}
		case *refExpr:
			if n.index != nil {
				if err := walk(n.index); err != nil {
					return err
				}
			}
			for _, a := range n.args {
				if err := walk(a); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(r.Condition); err != nil {
		return err
	}
	if !allUsed {
		for _, s := range r.Strings {
			if !used[s.ID] {
				return fmt.Errorf("unreferenced string %q", s.ID)
			}
		}
	}
	return nil
}
