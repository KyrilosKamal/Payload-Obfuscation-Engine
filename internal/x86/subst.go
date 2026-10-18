package x86

import (
	"strconv"

	"golang.org/x/arch/x86/x86asm"
)

// resolveFunc maps an original instruction offset to its new offset in the
// re-emitted stream.
type resolveFunc func(oldOff int) (int, bool)

// FlagEffect classifies what a substitution does to EFLAGS.
type FlagEffect uint8

const (
	// FlagsPreserved means the replacement leaves every EFLAGS bit in exactly
	// the state the original instruction would have. These are always safe.
	FlagsPreserved FlagEffect = iota
	// FlagsModified means the replacement writes EFLAGS differently (or not at
	// all). It is only applied when the following instruction does not read
	// them, unless AllowFlagClobber is set.
	FlagsModified
)

// Substitution is one morph of an instruction into a functionally equivalent
// alternative encoding.
type Substitution struct {
	Name        string
	Description string
	// Effect is the EFLAGS behaviour of the replacement relative to the original.
	Effect FlagEffect
	// Match decides whether this morph applies to an instruction.
	Match func(in *Instr) bool
	// Emit produces the replacement encoding. res resolves relative targets.
	Emit func(in *Instr, res resolveFunc) ([]byte, error)
	// Pair, when non-nil, marks this morph as consuming the *next* instruction
	// as well (for example "push rax; pop rbx"). The second instruction is
	// identified by Pair(in, next).
	Pair func(in, next *Instr) bool
	// PairEmit produces the replacement for a matched pair. The second
	// instruction of the pair is deleted.
	PairEmit func(in, next *Instr) []byte
}

// Size returns the byte length of the replacement encoding.
//
// The probe resolver returns 0 for every label: every morph in this table emits
// a fixed-size encoding for a given input instruction, with only the *contents*
// of the displacement field depending on the resolver.
func (s *Substitution) Size(in *Instr) (int, error) {
	probe := func(int) (int, bool) { return 0, true }
	b, err := s.Emit(in, probe)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// SizeDelta is the change in encoded length caused by this morph.
func (s *Substitution) SizeDelta(in *Instr) (int, error) {
	n, err := s.Size(in)
	if err != nil {
		return 0, err
	}
	return n - in.Len, nil
}

// ---------------------------------------------------------------------------
// operand helpers
// ---------------------------------------------------------------------------

func argImm(in *Instr, i int) (int64, bool) {
	if i >= len(in.Inst.Args) || in.Inst.Args[i] == nil {
		return 0, false
	}
	v, ok := in.Inst.Args[i].(x86asm.Imm)
	return int64(v), ok
}

func argReg(in *Instr, i int) (idx, bits int, ok bool) {
	if i >= len(in.Inst.Args) || in.Inst.Args[i] == nil {
		return 0, 0, false
	}
	r, isReg := in.Inst.Args[i].(x86asm.Reg)
	if !isReg {
		return 0, 0, false
	}
	return RegClass(r)
}

func argMem(in *Instr, i int) (x86asm.Mem, bool) {
	if i >= len(in.Inst.Args) || in.Inst.Args[i] == nil {
		return x86asm.Mem{}, false
	}
	m, ok := in.Inst.Args[i].(x86asm.Mem)
	return m, ok
}

func sameRegOperands(in *Instr) bool {
	if len(in.Inst.Args) < 2 {
		return false
	}
	d, db, ok1 := argReg(in, 0)
	s, sb, ok2 := argReg(in, 1)
	return ok1 && ok2 && d == s && db == sb
}

// regEndsWithByte reports whether a 32/64-bit register's low byte is the given
// 8-bit register, i.e. EAX/RAX <-> AL. This is what makes MOVZX EAX, AL
// reducible to AND EAX, 0xFF - but only when the two operands alias.
func lowByteAliases(wideIdx, byteIdx int) bool {
	return wideIdx == byteIdx
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

// Substitutions is the morph table: 24 instruction equivalences covering
// zeroing idioms, arithmetic peepholes, register moves, flag-neutral rewrites
// of conditional branches, multi-byte NOPs and dead push/pop pairs.
//
// The "classic" metamorphic morphs (mov/xor zeroing, add/inc, push-pop moves)
// are exactly the ones Shikata Ga Nai-style engines use, because a signature
// scanner keyed on "B8 00 00 00 00" or "48 89 D8" stops matching as soon as the
// bytes change, even though the semantics do not.
var Substitutions = []Substitution{
	{
		Name:        "mov32_0_to_xor",
		Description: "mov r32, 0  ->  xor r32, r32 (shorter zeroing idiom)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.MOV || in.DestReg < 0 || in.DestBits != 32 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 0
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x31, false, in.DestReg, in.DestReg), nil
		},
	},
	{
		Name:        "mov64_0_to_xor",
		Description: "mov r64, 0  ->  xor r32, r32 (32-bit xor zero-extends)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.MOV || in.DestReg < 0 || in.DestBits != 64 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 0
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x31, false, in.DestReg, in.DestReg), nil
		},
	},
	{
		Name:        "mov8_0_to_xor",
		Description: "mov r8, 0  ->  xor r8, r8",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.MOV || in.DestReg < 0 || in.DestBits != 8 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 0
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x30, false, in.DestReg, in.DestReg), nil
		},
	},
	{
		Name:        "xor_to_mov0",
		Description: "xor r, r  ->  mov r, 0 (binary signatures look for the xor idiom)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.XOR || !sameRegOperands(in) {
				return false
			}
			return in.DestBits == 32 || in.DestBits == 64
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			if in.DestBits == 64 {
				return RegRMImm32(0xC7, true, 0, in.DestReg, 0), nil
			}
			out := []byte{byte(0xB8 + (in.DestReg & 7))}
			if in.DestReg >= 8 {
				out = []byte{0x41, byte(0xB8 + (in.DestReg & 7))}
			}
			return append(out, 0, 0, 0, 0), nil
		},
	},
	{
		Name:        "add1_to_inc",
		Description: "add r, 1  ->  inc r (drops the CF update, hence flag-sensitive)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.ADD || in.DestReg < 0 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 1 && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0xFF, in.DestBits == 64, 0, in.DestReg), nil
		},
	},
	{
		Name:        "sub1_to_dec",
		Description: "sub r, 1  ->  dec r",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.SUB || in.DestReg < 0 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 1 && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0xFF, in.DestBits == 64, 1, in.DestReg), nil
		},
	},
	{
		Name:        "inc_to_add1",
		Description: "inc r  ->  add r, 1",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.INC && in.DestReg >= 0 && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRMImm8(0x83, in.DestBits == 64, 0, in.DestReg, 1), nil
		},
	},
	{
		Name:        "dec_to_sub1",
		Description: "dec r  ->  sub r, 1",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.DEC && in.DestReg >= 0 && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRMImm8(0x83, in.DestBits == 64, 5, in.DestReg, 1), nil
		},
	},
	{
		Name:        "mov64_to_push_pop",
		Description: "mov r64, r64  ->  push src ; pop dst (flags and stack neutral)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.MOV || in.DestBits != 64 || in.SrcBits != 64 {
				return false
			}
			return in.DestReg >= 0 && in.SrcReg >= 0 &&
				!IsStackPointer(in.DestReg) && !IsStackPointer(in.SrcReg)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			// Writes 8 bytes into the red zone below RSP, like the compiled code
			// it replaces would have; the stack pointer itself is restored.
			out := PushReg(in.SrcReg)
			return append(out, PopReg(in.DestReg)...), nil
		},
	},
	{
		Name:        "or_to_test",
		Description: "or r, r  ->  test r, r (identical EFLAGS: both clear CF/OF and set SF/ZF/PF)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.OR && sameRegOperands(in) && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x85, in.DestBits == 64, in.SrcReg, in.DestReg), nil
		},
	},
	{
		Name:        "test_to_or",
		Description: "test r, r  ->  or r, r (identical EFLAGS)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.TEST && sameRegOperands(in) && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x09, in.DestBits == 64, in.SrcReg, in.DestReg), nil
		},
	},
	{
		Name:        "sub_self_to_xor",
		Description: "sub r, r  ->  xor r, r (identical EFLAGS: CF=OF=0, ZF=1, SF=0, PF=1)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.SUB && sameRegOperands(in) && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x31, in.DestBits == 64, in.SrcReg, in.DestReg), nil
		},
	},
	{
		Name:        "cmp0_to_test",
		Description: "cmp r, 0  ->  test r, r (identical EFLAGS)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.CMP || in.DestReg < 0 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 0 && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x85, in.DestBits == 64, in.DestReg, in.DestReg), nil
		},
	},
	{
		Name:        "movzx_to_and",
		Description: "movzx r32, r8  ->  and r32, 0xFF",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.MOVZX || in.DestBits != 32 || in.SrcBits != 8 {
				return false
			}
			return lowByteAliases(in.DestReg, in.SrcReg)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRMImm32(0x81, false, 4, in.DestReg, 0xFF), nil
		},
	},
	{
		Name:        "lea_self_to_mov",
		Description: "lea r, [r+0]  ->  mov r, r",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.LEA || in.DestReg < 0 || in.DestBits != 64 {
				return false
			}
			m, ok := argMem(in, 1)
			if !ok {
				return false
			}
			return m.Segment == 0 && m.Scale == 0 && m.Index == 0 && m.Disp == 0 &&
				int(m.Base) == int(Reg64(in.DestReg))
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return MovRegReg(in.DestReg, in.DestReg), nil
		},
	},
	{
		Name:        "neg_to_not_inc",
		Description: "neg r  ->  not r ; inc r  (two's complement identity, drops the CF/OF update)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.NEG && in.DestReg >= 0 && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			w := in.DestBits == 64
			out := RegRM(0xF7, w, 2, in.DestReg)
			return append(out, RegRM(0xFF, w, 0, in.DestReg)...), nil
		},
	},
	{
		Name:        "shl1_to_add_self",
		Description: "shl r, 1  ->  add r, r",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.SHL || in.DestReg < 0 || (in.DestBits != 32 && in.DestBits != 64) {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 1
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRM(0x01, in.DestBits == 64, in.DestReg, in.DestReg), nil
		},
	},
	{
		Name:        "add_self_to_shl1",
		Description: "add r, r  ->  shl r, 1",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.ADD && sameRegOperands(in) && (in.DestBits == 32 || in.DestBits == 64)
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) {
			return RegRMImm8(0xC1, in.DestBits == 64, 4, in.DestReg, 1), nil
		},
	},
	{
		Name:        "and_all_ones_to_nop",
		Description: "and r, -1  ->  (removed)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.AND || in.DestReg < 0 || (in.DestBits != 32 && in.DestBits != 64) {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == -1
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) { return nil, nil },
	},
	{
		Name:        "add0_to_nop",
		Description: "add r, 0  ->  (removed)",
		Effect:      FlagsModified,
		Match: func(in *Instr) bool {
			if in.Inst.Op != x86asm.ADD || in.DestReg < 0 {
				return false
			}
			imm, ok := argImm(in, 1)
			return ok && imm == 0
		},
		Emit: func(in *Instr, _ resolveFunc) ([]byte, error) { return nil, nil },
	},
	{
		Name:        "nop1_to_nop3",
		Description: "nop  ->  0F 1F 00 (multi-byte nop)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.NOP && len(in.Raw) == 1 && in.Raw[0] == 0x90
		},
		Emit: func(*Instr, resolveFunc) ([]byte, error) { return []byte{0x0F, 0x1F, 0x00}, nil },
	},
	{
		Name:        "nop3_to_nop2",
		Description: "0F 1F 00  ->  66 90",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.NOP && len(in.Raw) == 3 && in.Raw[0] == 0x0F && in.Raw[1] == 0x1F && in.Raw[2] == 0x00
		},
		Emit: func(*Instr, resolveFunc) ([]byte, error) { return []byte{0x66, 0x90}, nil },
	},
	{
		Name:        "nop2_to_nop1",
		Description: "66 90  ->  nop",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.NOP && len(in.Raw) == 2 && in.Raw[0] == 0x66 && in.Raw[1] == 0x90
		},
		Emit: func(*Instr, resolveFunc) ([]byte, error) { return []byte{0x90}, nil },
	},
	{
		Name:        "xchg_self_to_nop",
		Description: "xchg r, r  ->  nop",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.XCHG && sameRegOperands(in)
		},
		Emit: func(*Instr, resolveFunc) ([]byte, error) { return []byte{0x90}, nil },
	},
	{
		Name:        "jmp_short_to_near",
		Description: "jmp rel8  ->  jmp rel32 (relocation-visible size change)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.IsJmp && in.HasTarget && len(in.Raw) == 2 && in.Raw[0] == 0xEB
		},
		Emit: func(in *Instr, res resolveFunc) ([]byte, error) {
			return emitJmp(in, res, 5)
		},
	},
	{
		Name:        "jmp_near_to_short",
		Description: "jmp rel32  ->  jmp rel8 (fails when the target is out of range)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.IsJmp && in.HasTarget && len(in.Raw) == 5 && in.Raw[0] == 0xE9
		},
		Emit: func(in *Instr, res resolveFunc) ([]byte, error) {
			return emitJmp(in, res, 2)
		},
	},
	{
		Name:        "jcc_short_to_near",
		Description: "jcc rel8  ->  jcc rel32",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			opc := stripPrefixes(in.Raw)
			return in.IsCond && in.HasTarget && len(opc) >= 1 && opc[0] >= 0x70 && opc[0] <= 0x7F
		},
		Emit: func(in *Instr, res resolveFunc) ([]byte, error) {
			return emitJcc(in, res, 6)
		},
	},
	{
		Name:        "jcc_near_to_short",
		Description: "jcc rel32  ->  jcc rel8 (fails when the target is out of range)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			opc := stripPrefixes(in.Raw)
			return in.IsCond && in.HasTarget && len(opc) >= 2 && opc[0] == 0x0F &&
				opc[1] >= 0x80 && opc[1] <= 0x8F
		},
		Emit: func(in *Instr, res resolveFunc) ([]byte, error) {
			return emitJcc(in, res, 2)
		},
	},
	{
		Name:        "push_pop_same_to_nop",
		Description: "push r ; pop r  ->  (removed)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.PUSH && in.DestReg >= 0 && !IsStackPointer(in.DestReg)
		},
		Pair: func(in, next *Instr) bool {
			if next.Inst.Op != x86asm.POP {
				return false
			}
			a, _, okA := argReg(in, 0)
			b, _, okB := argReg(next, 0)
			return okA && okB && a == b
		},
		PairEmit: func(in, next *Instr) []byte { return nil },
	},
	{
		Name:        "push_pop_to_mov",
		Description: "push src ; pop dst  ->  mov dst, src (differing registers)",
		Effect:      FlagsPreserved,
		Match: func(in *Instr) bool {
			return in.Inst.Op == x86asm.PUSH && in.DestReg >= 0 && !IsStackPointer(in.DestReg)
		},
		Pair: func(in, next *Instr) bool {
			if next.Inst.Op != x86asm.POP {
				return false
			}
			a, _, okA := argReg(in, 0)
			b, _, okB := argReg(next, 0)
			return okA && okB && a != b && !IsStackPointer(b)
		},
		PairEmit: func(in, next *Instr) []byte {
			src, _, _ := argReg(in, 0)
			dst, _, _ := argReg(next, 0)
			return MovRegReg(dst, src)
		},
	},
}

// emitJmp encodes a direct jump to the relocated target using the requested
// total instruction length (2 for rel8, 5 for rel32).
func emitJmp(in *Instr, res resolveFunc, size int) ([]byte, error) {
	self, ok := res(in.Off)
	if !ok {
		return nil, errUnresolved(in)
	}
	target, ok := res(in.Target)
	if !ok {
		return nil, errUnresolved(in)
	}
	rel := target - (self + size)
	if size == 2 {
		return []byte{0xEB, byte(int8(rel))}, nil
	}
	out := []byte{0xE9, 0, 0, 0, 0}
	putU32(out[1:], uint32(int32(rel)))
	return out, nil
}

// emitJcc encodes a conditional branch using the requested total length.
func emitJcc(in *Instr, res resolveFunc, size int) ([]byte, error) {
	self, ok := res(in.Off)
	if !ok {
		return nil, errUnresolved(in)
	}
	target, ok := res(in.Target)
	if !ok {
		return nil, errUnresolved(in)
	}
	rel := target - (self + size)
	if size == 2 {
		return []byte{0x70 | (in.Cond & 0x0F), byte(int8(rel))}, nil
	}
	out := []byte{0x0F, 0x80 | (in.Cond & 0x0F), 0, 0, 0, 0}
	putU32(out[2:], uint32(int32(rel)))
	return out, nil
}

func putU32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func errUnresolved(in *Instr) error {
	return &UnresolvedError{Instr: in.String(), Off: in.Off}
}

// UnresolvedError reports a relative operand whose target could not be located
// in the re-emitted stream.
type UnresolvedError struct {
	Instr string
	Off   int
}

func (e *UnresolvedError) Error() string {
	return "x86: cannot resolve relative target of " + strconv.Quote(e.Instr) + " at offset " + strconv.FormatInt(int64(e.Off), 0)
}
