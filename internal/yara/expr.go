package yara

import (
	"fmt"
	"strings"
)

// Value is a runtime value in a condition. YARA's type system is small: numbers,
// strings and booleans, with strings usable mostly as function arguments.
type Value struct {
	Kind ValueKind
	Num  float64
	Str  string
	Bool bool
}

// ValueKind tags a Value.
type ValueKind uint8

// The runtime kinds.
const (
	VNum ValueKind = iota
	VStr
	VBool
)

// Num builds a numeric value.
func Num(f float64) Value { return Value{Kind: VNum, Num: f} }

// Str builds a string value.
func Str(s string) Value { return Value{Kind: VStr, Str: s} }

// Bool builds a boolean value.
func Bool(b bool) Value { return Value{Kind: VBool, Bool: b} }

func (v Value) truthy() bool {
	switch v.Kind {
	case VNum:
		return v.Num != 0
	case VStr:
		return v.Str != ""
	default:
		return v.Bool
	}
}

func (v Value) number() (float64, error) {
	switch v.Kind {
	case VNum:
		return v.Num, nil
	case VBool:
		if v.Bool {
			return 1, nil
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("expected a number, found a string")
	}
}

func (v Value) String() string {
	switch v.Kind {
	case VNum:
		if v.Num == float64(int64(v.Num)) {
			return fmt.Sprintf("%d", int64(v.Num))
		}
		return fmt.Sprintf("%g", v.Num)
	case VStr:
		return fmt.Sprintf("%q", v.Str)
	default:
		if v.Bool {
			return "true"
		}
		return "false"
	}
}

// Expr is a node in a condition expression tree.
type Expr interface {
	eval(c *scanCtx) (Value, error)
	// String renders the node back to source-ish form for diagnostics.
	String() string
}

// ---------------------------------------------------------------------------
// Literals
// ---------------------------------------------------------------------------

type litNum struct{ v float64 }

func (e *litNum) eval(*scanCtx) (Value, error) { return Num(e.v), nil }
func (e *litNum) String() string               { return Num(e.v).String() }

type litStr struct{ v string }

func (e *litStr) eval(*scanCtx) (Value, error) { return Str(e.v), nil }
func (e *litStr) String() string               { return fmt.Sprintf("%q", e.v) }

type litBool struct{ v bool }

func (e *litBool) eval(*scanCtx) (Value, error) { return Bool(e.v), nil }
func (e *litBool) String() string {
	if e.v {
		return "true"
	}
	return "false"
}

// ---------------------------------------------------------------------------
// String references
// ---------------------------------------------------------------------------

type strOp uint8

const (
	opMatched strOp = iota // $a
	opCount                // #a
	opOffset               // @a
	opLength               // !a
)

type strRef struct {
	id    string
	op    strOp
	index Expr // optional selector for @a[i] / !a[i]
}

func (e *strRef) String() string {
	pre := map[strOp]string{opMatched: "$", opCount: "#", opOffset: "@", opLength: "!"}[e.op]
	s := pre + strings.TrimPrefix(e.id, "$")
	if e.index != nil {
		s += "[" + e.index.String() + "]"
	}
	return s
}

func (e *strRef) eval(c *scanCtx) (Value, error) {
	ms, ok := c.matches[e.id]
	if !ok {
		return Value{}, fmt.Errorf("condition refers to undefined string %s", e.id)
	}
	idx := 1
	if e.index != nil {
		v, err := e.index.eval(c)
		if err != nil {
			return Value{}, err
		}
		n, err := v.number()
		if err != nil {
			return Value{}, err
		}
		idx = int(n)
	}
	switch e.op {
	case opMatched:
		if idx == 1 {
			return Bool(len(ms) > 0), nil
		}
		return Value{}, fmt.Errorf("%s cannot be indexed", e.id)
	case opCount:
		if idx != 1 {
			return Value{}, fmt.Errorf("#%s cannot be indexed", e.id)
		}
		return Num(float64(len(ms))), nil
	case opOffset:
		if idx < 1 || idx > len(ms) {
			return Num(-1), nil
		}
		return Num(float64(ms[idx-1].Off)), nil
	default:
		if idx < 1 || idx > len(ms) {
			return Num(0), nil
		}
		return Num(float64(ms[idx-1].Len)), nil
	}
}

// strAt implements the `$a at <offset>` operator.
type strAt struct {
	ref    *strRef
	offset Expr
}

func (e *strAt) String() string { return e.ref.String() + " at " + e.offset.String() }

func (e *strAt) eval(c *scanCtx) (Value, error) {
	v, err := e.offset.eval(c)
	if err != nil {
		return Value{}, err
	}
	n, err := v.number()
	if err != nil {
		return Value{}, err
	}
	for _, m := range c.matches[e.ref.id] {
		if float64(m.Off) == n {
			return Bool(true), nil
		}
	}
	return Bool(false), nil
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

type unaryExpr struct {
	op string // "not" | "-"
	x  Expr
}

func (e *unaryExpr) String() string { return e.op + " " + e.x.String() }

func (e *unaryExpr) eval(c *scanCtx) (Value, error) {
	v, err := e.x.eval(c)
	if err != nil {
		return Value{}, err
	}
	switch e.op {
	case "not":
		return Bool(!v.truthy()), nil
	default:
		n, err := v.number()
		if err != nil {
			return Value{}, err
		}
		return Num(-n), nil
	}
}

type binaryExpr struct {
	op   string
	l, r Expr
}

func (e *binaryExpr) String() string {
	return "(" + e.l.String() + " " + e.op + " " + e.r.String() + ")"
}

func (e *binaryExpr) eval(c *scanCtx) (Value, error) {
	// Short-circuiting matters: `not defined and $a` style guards are common,
	// and a condition that errors on one branch should not error the whole scan.
	switch e.op {
	case "and":
		l, err := e.l.eval(c)
		if err != nil {
			return Value{}, err
		}
		if !l.truthy() {
			return Bool(false), nil
		}
		r, err := e.r.eval(c)
		if err != nil {
			return Value{}, err
		}
		return Bool(r.truthy()), nil
	case "or":
		l, lerr := e.l.eval(c)
		if lerr == nil && l.truthy() {
			return Bool(true), nil
		}
		r, rerr := e.r.eval(c)
		if rerr != nil {
			return Value{}, rerr
		}
		if r.truthy() {
			return Bool(true), nil
		}
		if lerr != nil {
			return Value{}, lerr
		}
		return Bool(false), nil
	}

	l, err := e.l.eval(c)
	if err != nil {
		return Value{}, err
	}
	r, err := e.r.eval(c)
	if err != nil {
		return Value{}, err
	}
	if l.Kind == VStr || r.Kind == VStr {
		ls, rs := l.Str, r.Str
		switch e.op {
		case "==":
			return Bool(ls == rs), nil
		case "!=":
			return Bool(ls != rs), nil
		default:
			return Value{}, fmt.Errorf("operator %s is not defined for strings", e.op)
		}
	}
	ln, err := l.number()
	if err != nil {
		return Value{}, err
	}
	rn, err := r.number()
	if err != nil {
		return Value{}, err
	}
	switch e.op {
	case "+":
		return Num(ln + rn), nil
	case "-":
		return Num(ln - rn), nil
	case "*":
		return Num(ln * rn), nil
	case "/":
		if rn == 0 {
			return Num(0), nil
		}
		return Num(ln / rn), nil
	case "%":
		if rn == 0 {
			return Num(0), nil
		}
		return Num(float64(int64(ln) % int64(rn))), nil
	case "==":
		return Bool(ln == rn), nil
	case "!=":
		return Bool(ln != rn), nil
	case "<":
		return Bool(ln < rn), nil
	case "<=":
		return Bool(ln <= rn), nil
	case ">":
		return Bool(ln > rn), nil
	case ">=":
		return Bool(ln >= rn), nil
	default:
		return Value{}, fmt.Errorf("unimplemented operator %s", e.op)
	}
}

// ---------------------------------------------------------------------------
// Quantifiers: `N of them`, `any of ($a, $b)`
// ---------------------------------------------------------------------------

type quantKind uint8

const (
	quantAny quantKind = iota
	quantAll
	quantN
)

type ofExpr struct {
	quant quantKind
	n     Expr
	ids   []string // empty means `them`
	them  bool
}

func (e *ofExpr) String() string {
	var q string
	switch e.quant {
	case quantAny:
		q = "any"
	case quantAll:
		q = "all"
	default:
		q = e.n.String()
	}
	target := "them"
	if !e.them {
		target = "(" + strings.Join(e.ids, ", ") + ")"
	}
	return q + " of " + target
}

func (e *ofExpr) eval(c *scanCtx) (Value, error) {
	ids := e.ids
	if e.them {
		ids = c.allStringIDs()
	}
	matched := 0
	for _, id := range ids {
		if len(c.matches[id]) > 0 {
			matched++
		}
	}
	switch e.quant {
	case quantAny:
		return Bool(matched > 0), nil
	case quantAll:
		return Bool(matched == len(ids)), nil
	default:
		v, err := e.n.eval(c)
		if err != nil {
			return Value{}, err
		}
		n, err := v.number()
		if err != nil {
			return Value{}, err
		}
		return Bool(float64(matched) >= n), nil
	}
}

// ---------------------------------------------------------------------------
// Module and function references
// ---------------------------------------------------------------------------

// refExpr covers every dotted identifier: `filesize`, `pe.is_pe`,
// `math.entropy(0, filesize)` and `pe.sections[0].entropy`.
type refExpr struct {
	name    string
	index   Expr
	prop    string
	args    []Expr
	hasArgs bool
}

func (e *refExpr) String() string {
	s := e.name
	if e.index != nil {
		s += "[" + e.index.String() + "]"
	}
	if e.prop != "" {
		s += "." + e.prop
	}
	if e.hasArgs {
		parts := make([]string, len(e.args))
		for i, a := range e.args {
			parts[i] = a.String()
		}
		s += "(" + strings.Join(parts, ", ") + ")"
	}
	return s
}

func (e *refExpr) eval(c *scanCtx) (Value, error) {
	return c.evalRef(e)
}
