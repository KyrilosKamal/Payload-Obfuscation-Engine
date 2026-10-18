package x86

import (
	"golang.org/x/arch/x86/x86asm"
)

// Instr is a decoded instruction plus the control-flow and flag metadata the
// obfuscation stages need.
//
// x86asm gives us mnemonics, operands and lengths; it deliberately does not
// model EFLAGS effects or build a control-flow graph. Those are exactly the
// facts a metamorphic engine needs, so they are derived here.
type Instr struct {
	Off     int         // offset in the decoded buffer
	Len     int         // encoded length in bytes
	Raw     []byte      // the encoded bytes
	Inst    x86asm.Inst // decoded form
	Decoded bool        // false when the byte stream could not be decoded here

	// Control flow.
	IsCond     bool // conditional branch (Jcc / LOOPcc / JRCXZ)
	IsJmp      bool // unconditional direct jump
	IsCall     bool // direct call with a relative target
	IsIndirect bool // jump or call through a register/memory operand
	IsRet      bool // RET / RETF / IRET
	IsTrap     bool // HLT / UD2 / INT3 family: flow stops here
	// IsSyscall marks SYSCALL / SYSENTER. They are *not* traps: they enter the
	// kernel and return to the following instruction, so control flow still
	// continues linearly and everything after them stays relocatable.
	IsSyscall   bool
	Cond        byte // condition code for IsCond
	Target      int  // absolute offset of the branch target when HasTarget
	HasTarget   bool
	FallThrough int // Off + Len

	// Flags.
	WritesFlags bool
	ReadsFlags  bool

	// Operand summary, for substitution matching.
	DestReg  int
	DestBits int
	SrcReg   int
	SrcBits  int
}

// Terminates reports whether control flow cannot fall through to Off+Len.
func (in *Instr) Terminates() bool {
	return in.IsJmp || in.IsIndirect || in.IsRet || in.IsTrap
}

// String renders the instruction the way objdump would, for logging.
func (in *Instr) String() string {
	if !in.Decoded {
		return "db " + hex(in.Raw)
	}
	return in.Inst.String()
}

func hex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, d[c>>4], d[c&0x0f])
	}
	return string(out)
}

// Mode is the processor mode assumed by the decoder.
const Mode = 64

// Disassemble linearly sweeps b, decoding x86-64 instructions.
//
// Shellcode has no section table or entry point, so a linear sweep is the only
// option available. Bytes that fail to decode are reported as a one-byte
// undocumented item and the sweep resynchronises on the next byte; stages that
// need an exact instruction stream reject such payloads rather than produce
// incorrect output (see PolymorphicRewriter and Flatten).
func Disassemble(b []byte) []Instr {
	var out []Instr
	for off := 0; off < len(b); {
		inst, err := x86asm.Decode(b[off:], Mode)
		if err != nil || inst.Len <= 0 || off+inst.Len > len(b) {
			out = append(out, Instr{
				Off: off, Len: 1, Raw: b[off : off+1],
				FallThrough: off + 1,
			})
			off++
			continue
		}
		in := Instr{
			Off:         off,
			Len:         inst.Len,
			Raw:         b[off : off+inst.Len],
			Inst:        inst,
			Decoded:     true,
			FallThrough: off + inst.Len,
		}
		classify(&in)
		out = append(out, in)
		off += inst.Len
	}
	return out
}

// IsClean reports whether every byte decoded as an instruction.
func IsClean(instrs []Instr) (bool, int) {
	bad := 0
	for i := range instrs {
		if !instrs[i].Decoded {
			bad++
		}
	}
	return bad == 0, bad
}

func classify(in *Instr) {
	op := in.Inst.Op
	name := op.String()

	// --- control flow -----------------------------------------------------
	opc := stripPrefixes(in.Raw)
	switch {
	case name == "RET" || name == "RETF" || name == "IRET" || name == "IRETD" || name == "IRETQ":
		in.IsRet = true
	case name == "SYSCALL" || name == "SYSENTER":
		// These enter the kernel and *return to the next instruction*, so they
		// are fallthrough, not terminators. Classifying them as traps made
		// every code-level stage refuse any payload containing one -- which is
		// to say, essentially every real payload. The only instruction here
		// that genuinely does not fall through is SYSRET/SYSEXIT, which resumes
		// at a saved RIP elsewhere.
		in.IsSyscall = true
	case name == "HLT" || name == "UD2" || name == "INT3" || name == "INT" || name == "INTO" ||
		name == "SYSRET" || name == "SYSEXIT":
		// Kept conservative: control leaves this module (or faults), so a static
		// CFG cannot see where it goes.
		in.IsTrap = true
	case name == "JMP":
		if rel, ok := relArg(in); ok {
			in.IsJmp = true
			in.Target, in.HasTarget = rel, true
		} else {
			in.IsIndirect = true
		}
	case name == "JMPE":
		in.IsIndirect = true
	case name == "CALL":
		if rel, ok := relArg(in); ok {
			in.IsCall = true
			in.Target, in.HasTarget = rel, true
		} else {
			in.IsIndirect = true
		}
	case isCondBranch(name):
		in.IsCond = true
		if cc, ok := condCode(opc); ok {
			in.Cond = cc
		}
		if rel, ok := relArg(in); ok {
			in.Target, in.HasTarget = rel, true
		} else {
			// JRCXZ etc. always carry a relative operand; treat anything else
			// as unresolved.
			in.IsIndirect = true
		}
	case name == "LOOP" || name == "LOOPE" || name == "LOOPNE":
		in.IsCond = true
		if rel, ok := relArg(in); ok {
			in.Target, in.HasTarget = rel, true
		}
	}

	// --- flags ------------------------------------------------------------
	in.WritesFlags = writesFlags(name)
	in.ReadsFlags = readsFlags(name)

	// --- operands ---------------------------------------------------------
	if len(in.Inst.Args) > 0 {
		if r, ok := in.Inst.Args[0].(x86asm.Reg); ok {
			if idx, bits, ok := RegClass(r); ok {
				in.DestReg, in.DestBits = idx, bits
			}
		}
	}
	if len(in.Inst.Args) > 1 {
		if r, ok := in.Inst.Args[1].(x86asm.Reg); ok {
			if idx, bits, ok := RegClass(r); ok {
				in.SrcReg, in.SrcBits = idx, bits
			}
		}
	}
}

// relArg returns the absolute target offset of a relative branch operand.
func relArg(in *Instr) (int, bool) {
	if len(in.Inst.Args) == 0 {
		return 0, false
	}
	rel, ok := in.Inst.Args[0].(x86asm.Rel)
	if !ok {
		return 0, false
	}
	return in.Off + in.Len + int(rel), true
}

// stripPrefixes removes legacy and REX prefixes so the primary opcode can be
// inspected byte-wise. Using the encoding (rather than the mnemonic table)
// makes condition-code extraction exact and immune to x86asm's choice of
// canonical Jcc spelling.
func stripPrefixes(b []byte) []byte {
	i := 0
	for i < len(b) {
		switch b[i] {
		case 0x66, 0x67, 0xF0, 0xF2, 0xF3,
			0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
			i++
			continue
		}
		if b[i] >= 0x40 && b[i] <= 0x4F {
			i++
			continue
		}
		break
	}
	return b[i:]
}

// condCode extracts the condition code from a conditional instruction's
// opcode bytes.
func condCode(opc []byte) (byte, bool) {
	if len(opc) == 0 {
		return 0, false
	}
	switch {
	case opc[0] >= 0x70 && opc[0] <= 0x7F:
		return opc[0] & 0x0F, true
	case opc[0] == 0x0F && len(opc) >= 2 && opc[1] >= 0x80 && opc[1] <= 0x8F:
		return opc[1] & 0x0F, true
	case opc[0] == 0x0F && len(opc) >= 2 && opc[1] >= 0x40 && opc[1] <= 0x4F:
		return opc[1] & 0x0F, true
	case opc[0] == 0x0F && len(opc) >= 2 && opc[1] >= 0x90 && opc[1] <= 0x9F:
		return opc[1] & 0x0F, true
	}
	return 0, false
}

func isCondBranch(name string) bool {
	if len(name) < 2 || name[0] != 'J' {
		return false
	}
	switch name {
	case "JMP", "JMPE":
		return false
	}
	return true
}

// writesFlags lists mnemonics that modify EFLAGS. NOT, LEA, MOV, MOVZX/MOVSX,
// PUSH, POP and XCHG are deliberately absent.
var flagWriters = map[string]bool{
	"ADD": true, "ADC": true, "SUB": true, "SBB": true,
	"MUL": true, "IMUL": true, "DIV": true, "IDIV": true,
	"INC": true, "DEC": true, "NEG": true,
	"AND": true, "OR": true, "XOR": true,
	"SHL": true, "SHR": true, "SAR": true, "SAL": true,
	"ROL": true, "ROR": true, "RCL": true, "RCR": true,
	"TEST": true, "CMP": true,
	"BT": true, "BTS": true, "BTR": true, "BTC": true,
	"BSF": true, "BSR": true, "XADD": true,
	"CMPXCHG": true, "CMPXCHG8B": true, "CMPXCHG16B": true,
	"LZCNT": true, "TZCNT": true, "POPCNT": true,
	"CLC": true, "STC": true, "CMC": true,
	"SAHF": true, "POPF": true, "POPFQ": true,
	"SCASB": true, "SCASW": true, "SCASD": true, "SCASQ": true,
	"CMPSB": true, "CMPSW": true, "CMPSD": true, "CMPSQ": true,
	"ANDN": true, "BLSI": true, "BLSMSK": true, "BLSR": true,
}

// readsFlags lists mnemonics that consume EFLAGS. Jcc/SETcc/CMOVcc are matched
// by the caller through the encoding-derived condition code, but are included
// here by prefix for completeness.
var flagReaderSet = map[string]bool{
	"ADC": true, "SBB": true, "RCL": true, "RCR": true,
	"LAHF": true, "LOOPE": true, "LOOPNE": true,
	"CMOVO": true, "CMOVNO": true,
}

func writesFlags(name string) bool { return flagWriters[name] }

func readsFlags(name string) bool {
	switch {
	case name == "ADC" || name == "SBB" || name == "RCL" || name == "RCR" || name == "LAHF":
		return true
	case name == "LOOPE" || name == "LOOPNE":
		return true
	case len(name) >= 2 && name[0] == 'J' && name != "JMP" && name != "JMPE":
		return true
	case len(name) >= 3 && name[:3] == "SET":
		return true
	case len(name) >= 4 && name[:4] == "CMOV":
		return true
	}
	return false
}

// RegClass maps a general-purpose register to (index, width-in-bits).
func RegClass(r x86asm.Reg) (idx int, bits int, ok bool) {
	switch {
	case x86asm.AL <= r && r <= x86asm.R15B:
		return int(r - x86asm.AL), 8, true
	case x86asm.AX <= r && r <= x86asm.R15W:
		return int(r - x86asm.AX), 16, true
	case x86asm.EAX <= r && r <= x86asm.R15L:
		return int(r - x86asm.EAX), 32, true
	case x86asm.RAX <= r && r <= x86asm.R15:
		return int(r - x86asm.RAX), 64, true
	}
	return 0, 0, false
}

// Reg64 returns the 64-bit register for an index 0..15.
func Reg64(idx int) x86asm.Reg { return x86asm.RAX + x86asm.Reg(idx) }

// Reg32 returns the 32-bit register for an index 0..15.
func Reg32(idx int) x86asm.Reg { return x86asm.EAX + x86asm.Reg(idx) }

// RegName renders the 64-bit register for an index.
func RegName(idx int) string {
	if idx < 0 || idx > 15 {
		return "?"
	}
	return Reg64(idx).String()
}

// IsStackPointer reports whether the register index is RSP (4).
func IsStackPointer(idx int) bool { return idx == 4 }
