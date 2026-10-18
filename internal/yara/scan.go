package yara

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// scanCtx carries everything a condition needs while it is being evaluated
// against one blob.
type scanCtx struct {
	data    []byte
	rule    *Rule
	matches map[string][]match
	imports map[string]bool

	pe     *peFile
	peOnce bool
}

func (c *scanCtx) allStringIDs() []string {
	ids := make([]string, 0, len(c.rule.Strings))
	for _, s := range c.rule.Strings {
		ids = append(ids, s.ID)
	}
	return ids
}

func (c *scanCtx) peFile() *peFile {
	if !c.peOnce {
		c.pe = parsePE(c.data)
		c.peOnce = true
	}
	return c.pe
}

func (c *scanCtx) needImport(mod string) error {
	if !c.imports[mod] {
		return fmt.Errorf("rule %s uses the %q module without importing it", c.rule.Name, mod)
	}
	return nil
}

func (c *scanCtx) numArg(args []Expr, i int) (float64, error) {
	if i >= len(args) {
		return 0, fmt.Errorf("missing argument %d", i+1)
	}
	v, err := args[i].eval(c)
	if err != nil {
		return 0, err
	}
	return v.number()
}

func (c *scanCtx) strArg(args []Expr, i int) (string, error) {
	if i >= len(args) {
		return "", fmt.Errorf("missing argument %d", i+1)
	}
	v, err := args[i].eval(c)
	if err != nil {
		return "", err
	}
	if v.Kind != VStr {
		return "", fmt.Errorf("argument %d must be a string, found %s", i+1, v.KindName())
	}
	return v.Str, nil
}

// KindName names a value kind for error messages.
func (v Value) KindName() string {
	switch v.Kind {
	case VNum:
		return "a number"
	case VStr:
		return "a string"
	default:
		return "a boolean"
	}
}

// evalRef resolves a dotted identifier to a value.
func (c *scanCtx) evalRef(e *refExpr) (Value, error) {
	switch {
	case e.name == "filesize":
		return Num(float64(len(c.data))), nil
	case e.name == "entrypoint":
		return Num(0), nil
	case strings.HasPrefix(e.name, "pe."):
		return c.evalPE(e)
	case strings.HasPrefix(e.name, "math."):
		return c.evalMath(e)
	case isIntReader(e.name):
		return c.evalIntReader(e)
	default:
		return Value{}, fmt.Errorf("unknown identifier or function %q", e.name)
	}
}

func isIntReader(name string) bool {
	switch name {
	case "uint8", "uint16", "uint32", "int8", "int16", "int32",
		"uint8be", "uint16be", "uint32be", "int8be", "int16be", "int32be":
		return true
	}
	return false
}

func (c *scanCtx) evalIntReader(e *refExpr) (Value, error) {
	if !e.hasArgs || len(e.args) != 1 {
		return Value{}, fmt.Errorf("%s takes exactly one argument", e.name)
	}
	offF, err := c.numArg(e.args, 0)
	if err != nil {
		return Value{}, err
	}
	off := int(offF)
	big := strings.HasSuffix(e.name, "be")
	n := 4
	switch {
	case strings.HasPrefix(e.name, "uint8"), strings.HasPrefix(e.name, "int8"):
		n = 1
	case strings.HasPrefix(e.name, "uint16"), strings.HasPrefix(e.name, "int16"):
		n = 2
	}
	if off < 0 || off+n > len(c.data) {
		return Num(0), nil
	}
	b := c.data[off : off+n]
	if big {
		switch n {
		case 1:
			return Num(float64(int64(int8(b[0])))), nil
		case 2:
			v := int64(int16(binary.BigEndian.Uint16(b)))
			if strings.HasPrefix(e.name, "uint16") {
				return Num(float64(binary.BigEndian.Uint16(b))), nil
			}
			return Num(float64(v)), nil
		default:
			if strings.HasPrefix(e.name, "uint32") {
				return Num(float64(binary.BigEndian.Uint32(b))), nil
			}
			return Num(float64(int64(int32(binary.BigEndian.Uint32(b))))), nil
		}
	}
	switch n {
	case 1:
		if strings.HasPrefix(e.name, "uint8") {
			return Num(float64(b[0])), nil
		}
		return Num(float64(int64(int8(b[0])))), nil
	case 2:
		v := binary.LittleEndian.Uint16(b)
		if strings.HasPrefix(e.name, "uint16") {
			return Num(float64(v)), nil
		}
		return Num(float64(int64(int16(v)))), nil
	default:
		v := binary.LittleEndian.Uint32(b)
		if strings.HasPrefix(e.name, "uint32") {
			return Num(float64(v)), nil
		}
		return Num(float64(int64(int32(v)))), nil
	}
}

func (c *scanCtx) evalMath(e *refExpr) (Value, error) {
	if err := c.needImport("math"); err != nil {
		return Value{}, err
	}
	if e.name == "math.entropy" {
		if len(e.args) != 2 {
			return Value{}, fmt.Errorf("math.entropy takes two arguments")
		}
		off, err := c.numArg(e.args, 0)
		if err != nil {
			return Value{}, err
		}
		size, err := c.numArg(e.args, 1)
		if err != nil {
			return Value{}, err
		}
		return Num(entropyOfRange(c.data, int(off), int(size))), nil
	}
	// Range functions: math.mean(offset, size), math.min, math.max,
	// math.deviation.
	if len(e.args) != 2 {
		return Value{}, fmt.Errorf("%s takes two arguments", e.name)
	}
	off, err := c.numArg(e.args, 0)
	if err != nil {
		return Value{}, err
	}
	size, err := c.numArg(e.args, 1)
	if err != nil {
		return Value{}, err
	}
	start := int(off)
	end := start + int(size)
	if start < 0 || end > len(c.data) || end <= start {
		return Num(0), nil
	}
	seg := c.data[start:end]
	switch e.name {
	case "math.mean":
		var sum float64
		for _, b := range seg {
			sum += float64(b)
		}
		return Num(sum / float64(len(seg))), nil
	case "math.min":
		m := 255.0
		for _, b := range seg {
			if float64(b) < m {
				m = float64(b)
			}
		}
		return Num(m), nil
	case "math.max":
		m := 0.0
		for _, b := range seg {
			if float64(b) > m {
				m = float64(b)
			}
		}
		return Num(m), nil
	case "math.deviation":
		var sum float64
		for _, b := range seg {
			sum += float64(b)
		}
		mean := sum / float64(len(seg))
		var acc float64
		for _, b := range seg {
			d := float64(b) - mean
			acc += d * d
		}
		return Num(math.Sqrt(acc / float64(len(seg)))), nil
	default:
		return Value{}, fmt.Errorf("unsupported math function %q", e.name)
	}
}

func (c *scanCtx) evalPE(e *refExpr) (Value, error) {
	if err := c.needImport("pe"); err != nil {
		return Value{}, err
	}
	pe := c.peFile()
	switch e.name {
	case "pe.is_pe":
		return Bool(pe.valid), nil
	case "pe.is_32bit":
		return Bool(pe.valid && !pe.is64), nil
	case "pe.is_64bit":
		return Bool(pe.valid && pe.is64), nil
	case "pe.machine":
		return Num(float64(pe.machine)), nil
	case "pe.number_of_sections":
		return Num(float64(len(pe.sections))), nil
	case "pe.timestamp":
		return Num(float64(pe.timestamp)), nil
	case "pe.entry_point":
		// The reference implementation reports the entry point as a raw file
		// offset rather than an RVA, which is easy to get wrong and was caught
		// by the cross-validation test. Translating here keeps the rules
		// portable to libyara.
		if off, ok := pe.rvaToOffset(pe.entryRVA); ok {
			return Num(float64(off)), nil
		}
		return Num(0), nil
	case "pe.number_of_imported_functions":
		return Num(float64(len(pe.imports))), nil
	case "pe.imports":
		switch len(e.args) {
		case 1:
			fn, err := c.strArg(e.args, 0)
			if err != nil {
				return Value{}, err
			}
			if !pe.valid {
				return Bool(false), nil
			}
			return Bool(pe.importAny[strings.ToLower(fn)]), nil
		case 2:
			dll, err := c.strArg(e.args, 0)
			if err != nil {
				return Value{}, err
			}
			fn, err := c.strArg(e.args, 1)
			if err != nil {
				return Value{}, err
			}
			if !pe.valid {
				return Bool(false), nil
			}
			m := pe.importByDLL[strings.ToLower(dll)]
			return Bool(m != nil && m[strings.ToLower(fn)]), nil
		default:
			return Value{}, fmt.Errorf("pe.imports takes one or two arguments")
		}
	case "pe.sections":
		if e.index == nil || e.prop == "" {
			return Value{}, fmt.Errorf("pe.sections requires an index and a property, as in pe.sections[0].entropy")
		}
		idxF, err := c.numArg([]Expr{e.index}, 0)
		if err != nil {
			return Value{}, err
		}
		idx := int(idxF)
		if idx < 0 || idx >= len(pe.sections) {
			return Num(0), nil
		}
		s := pe.sections[idx]
		switch e.prop {
		case "raw_data_offset":
			return Num(float64(s.RawPtr)), nil
		case "raw_data_size":
			return Num(float64(s.RawSize)), nil
		case "virtual_size":
			return Num(float64(s.VirtualSize)), nil
		case "virtual_address":
			return Num(float64(s.VirtualAddress)), nil
		case "characteristics":
			return Num(float64(s.Characteristics)), nil
		case "name", "full_name":
			return Str(s.Name), nil
		default:
			return Value{}, fmt.Errorf("unsupported pe.sections property %q", e.prop)
		}
	case "pe.section_index":
		name, err := c.strArg(e.args, 0)
		if err != nil {
			return Value{}, err
		}
		for i, s := range pe.sections {
			if s.Name == name {
				return Num(float64(i)), nil
			}
		}
		return Num(-1), nil
	default:
		return Value{}, fmt.Errorf("unsupported pe module reference %q", e.name)
	}
}
