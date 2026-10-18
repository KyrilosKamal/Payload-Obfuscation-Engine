// Package x86 implements the instruction-level obfuscation stages: polymorphic
// rewriting, dead-code insertion and control-flow flattening.
//
// Everything in this package is a pure []byte -> []byte transform with no
// pipeline dependency, which keeps it independently unit-testable. The
// generated machine code is real: internal/x86/native executes it on
// linux/amd64 so the tests can assert semantic equivalence rather than merely
// eyeballing a disassembly.
package x86

import (
	"encoding/binary"
	"fmt"
)

// Assembler is a minimal x86-64 code emitter with labels and relocation fixups.
//
// Obfuscation stubs are built from relative jumps and RIP-relative memory
// references whose displacement depends on the final layout. Hand-patching
// those by hand is the classic source of subtly broken shellcode, so the
// emitter records a fixup for every such operand and resolves them in a single
// pass once all offsets are known.
type Assembler struct {
	buf    []byte
	labels map[int]int
	fixups []fixup
	next   int
}

type fixKind uint8

const (
	// fixRel32 patches a 4-byte displacement: target - (fieldEnd).
	fixRel32 fixKind = iota
	// fixRIP32 patches a 4-byte RIP-relative displacement: same arithmetic as
	// fixRel32, kept separate for readability of the emitted code.
	fixRIP32
	// fixRel8 patches a 1-byte displacement: target - (fieldEnd).
	fixRel8
	// fixAbs64 patches the absolute buffer offset of the label as a little
	// endian 64-bit value. Used for jump tables that live inside the buffer and
	// are therefore only resolvable once the layout is fixed.
	fixAbs64
	// fixRelToLabel patches a 32-bit value equal to (label - base). This is how
	// the flattened dispatcher's table stores the offset of a block relative to
	// the table itself: at runtime the dispatcher adds the table's real address,
	// which is position-independent and therefore needs no loader relocation.
	fixRelToLabel
)

type fixup struct {
	at    int
	label int
	kind  fixKind
	// base is used by fixRelToLabel: the patched value is base-label - label.
	base int
	// extra is the number of bytes that follow the patched field but still
	// belong to the same instruction (a trailing immediate, for instance). A
	// relative displacement is measured from the end of the instruction, not
	// from the end of the field.
	extra int
}

// NewAssembler returns an empty assembler.
func NewAssembler() *Assembler {
	return &Assembler{labels: map[int]int{}}
}

// NewLabel allocates a fresh label.
func (a *Assembler) NewLabel() int {
	l := a.next
	a.next++
	return l
}

// Bind marks label l as pointing at the current offset.
func (a *Assembler) Bind(l int) { a.labels[l] = len(a.buf) }

// SetLabel binds a label to an explicit buffer offset, which may be negative.
//
// This is what lets a stub reference a region that lives *outside* the code
// being assembled — the container's parameter block, which the image builder
// places immediately before the stub. Fixups are resolved as differences of
// buffer offsets, so a negative label is exactly as well-defined as a positive
// one, and the resulting displacement is correct at runtime.
func (a *Assembler) SetLabel(l, off int) { a.labels[l] = off }

// Len reports the current offset.
func (a *Assembler) Len() int { return len(a.buf) }

// Emit appends raw bytes.
func (a *Assembler) Emit(b ...byte) { a.buf = append(a.buf, b...) }

// EmitBytes appends a byte slice.
func (a *Assembler) EmitBytes(b []byte) { a.buf = append(a.buf, b...) }

// Imm32 appends a little-endian 32-bit immediate.
func (a *Assembler) Imm32(v int32) {
	a.buf = binary.LittleEndian.AppendUint32(a.buf, uint32(v))
}

// Imm64 appends a little-endian 64-bit immediate.
func (a *Assembler) Imm64(v uint64) {
	a.buf = binary.LittleEndian.AppendUint64(a.buf, v)
}

// Rel32 reserves a 4-byte relative displacement to label l.
func (a *Assembler) Rel32(l int) {
	a.fixups = append(a.fixups, fixup{at: len(a.buf), label: l, kind: fixRel32})
	a.buf = append(a.buf, 0, 0, 0, 0)
}

// RIP32 reserves a 4-byte RIP-relative displacement to label l.
func (a *Assembler) RIP32(l int) {
	a.fixups = append(a.fixups, fixup{at: len(a.buf), label: l, kind: fixRIP32})
	a.buf = append(a.buf, 0, 0, 0, 0)
}

// RIP32Imm32 reserves a 4-byte RIP-relative displacement to label l, followed
// by a 4-byte immediate.
//
// This exists because a RIP-relative displacement is measured from the end of
// the *instruction*, and `mov qword [rip+disp], imm32` puts an immediate after
// the displacement. Using RIP32 there would resolve the label four bytes too
// high and quietly turn the store into a store to the wrong address.
func (a *Assembler) RIP32Imm32(l int, imm int32) {
	a.fixups = append(a.fixups, fixup{at: len(a.buf), label: l, kind: fixRIP32, extra: 4})
	a.buf = binary.LittleEndian.AppendUint32(a.buf, 0)
	a.buf = binary.LittleEndian.AppendUint32(a.buf, uint32(imm))
}

// Rel8 reserves a 1-byte relative displacement to label l.
func (a *Assembler) Rel8(l int) {
	a.fixups = append(a.fixups, fixup{at: len(a.buf), label: l, kind: fixRel8})
	a.buf = append(a.buf, 0)
}

// Abs64 reserves an 8-byte absolute pointer to label l.
func (a *Assembler) Abs64(l int) {
	a.fixups = append(a.fixups, fixup{at: len(a.buf), label: l, kind: fixAbs64})
	a.buf = append(a.buf, 0, 0, 0, 0, 0, 0, 0, 0)
}

// RelToLabel reserves a 4-byte value that will be patched as (l - base).
func (a *Assembler) RelToLabel(l, base int) {
	a.fixups = append(a.fixups, fixup{at: len(a.buf), label: l, kind: fixRelToLabel, base: base})
	a.buf = append(a.buf, 0, 0, 0, 0)
}

// Align pads with pad until the offset is a multiple of n.
func (a *Assembler) Align(n int, pad byte) {
	if n <= 1 {
		return
	}
	for len(a.buf)%n != 0 {
		a.buf = append(a.buf, pad)
	}
}

// Bytes resolves every fixup and returns the final machine code.
//
// All labels must be bound; an unresolved displacement would silently point
// into the middle of unrelated code, so it is a hard error.
func (a *Assembler) Bytes() ([]byte, error) {
	out := make([]byte, len(a.buf))
	copy(out, a.buf)
	for _, f := range a.fixups {
		label, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("x86: unresolved label %d at offset %d", f.label, f.at)
		}
		switch f.kind {
		case fixRel32, fixRIP32:
			rel := int32(label - (f.at + 4 + f.extra))
			binary.LittleEndian.PutUint32(out[f.at:], uint32(rel))
		case fixRel8:
			rel := label - (f.at + 1)
			if rel < -128 || rel > 127 {
				return nil, fmt.Errorf("x86: rel8 fixup out of range (%d) at offset %d", rel, f.at)
			}
			out[f.at] = byte(int8(rel))
		case fixAbs64:
			binary.LittleEndian.PutUint64(out[f.at:], uint64(label))
		case fixRelToLabel:
			base, ok := a.labels[f.base]
			if !ok {
				return nil, fmt.Errorf("x86: unresolved base label %d at offset %d", f.base, f.at)
			}
			binary.LittleEndian.PutUint32(out[f.at:], uint32(int32(label-base)))
		default:
			return nil, fmt.Errorf("x86: unknown fixup kind %d", f.kind)
		}
	}
	return out, nil
}

// MustBytes is Bytes with a panic on error; for fixed, compile-time-known
// layouts inside stage emitters.
func (a *Assembler) MustBytes() []byte {
	b, err := a.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Instruction encodings
//
// Only the handful of forms this project emits are implemented. Each helper
// documents the encoding it produces so the output can be checked against
// objdump.
// ---------------------------------------------------------------------------

// rex builds a REX prefix, or nothing when the prefix would be 0x40.
func rex(w, r, x, b bool) []byte {
	v := byte(0x40)
	if w {
		v |= 0x08
	}
	if r {
		v |= 0x04
	}
	if x {
		v |= 0x02
	}
	if b {
		v |= 0x01
	}
	if v == 0x40 {
		return nil
	}
	return []byte{v}
}

// modrm builds a ModRM byte.
func modrm(mod, reg, rm byte) byte { return mod<<6 | (reg&7)<<3 | rm&7 }

// RegRM encodes "<opcode> reg, rm" in 64-bit operand size when w is true, with
// a register-direct ModRM (mod=11).
func RegRM(opcode byte, w bool, reg, rm int) []byte {
	out := rex(w, reg >= 8, false, rm >= 8)
	return append(out, opcode, modrm(3, byte(reg&7), byte(rm&7)))
}

// RegRMImm8 encodes "<opcode> reg, rm, imm8".
func RegRMImm8(opcode byte, w bool, reg, rm int, imm int8) []byte {
	out := RegRM(opcode, w, reg, rm)
	return append(out, byte(imm))
}

// RegRMImm32 encodes "<opcode> reg, rm, imm32".
func RegRMImm32(opcode byte, w bool, reg, rm int, imm int32) []byte {
	out := RegRM(opcode, w, reg, rm)
	out = binary.LittleEndian.AppendUint32(out, uint32(imm))
	return out
}

// RipRM emits an opcode with a RIP-relative ModRM (mod=00, rm=101). The four
// displacement bytes are zero here; the caller patches them via a fixup.
func RipRM(opcode byte, w bool, reg int) []byte {
	out := rex(w, reg >= 8, false, false)
	return append(out, opcode, modrm(0, byte(reg&7), 5))
}

// SIBIndexScaleRM emits "<opcode> reg, [base + index*scale]" (mod=00), used for
// the flattened dispatcher's jump-table lookup.
func SIBIndexScaleRM(opcode byte, w bool, reg, index, base, scale int) []byte {
	out := rex(w, reg >= 8, index >= 8, base >= 8)
	sc := byte(0)
	switch scale {
	case 2:
		sc = 1
	case 4:
		sc = 2
	case 8:
		sc = 3
	}
	out = append(out, opcode, modrm(0, byte(reg&7), 4), (sc<<6)|(byte(index&7)<<3)|byte(base&7))
	return out
}

// PushReg emits PUSH reg (64-bit operand size is the default in long mode).
func PushReg(reg int) []byte {
	out := rex(false, false, false, reg >= 8)
	return append(out, byte(0x50+(reg&7)))
}

// PopReg emits POP reg.
func PopReg(reg int) []byte {
	out := rex(false, false, false, reg >= 8)
	return append(out, byte(0x58+(reg&7)))
}

// MovRegImm32 emits "MOV reg64, imm32" (sign-extended, C7 /0).
func MovRegImm32(reg int, imm int32) []byte {
	return RegRMImm32(0xC7, true, 0, reg, imm)
}

// MovRegReg emits "MOV dst, src" in 64-bit operand size (89 /r).
func MovRegReg(dst, src int) []byte { return RegRM(0x89, true, src, dst) }

// MovLoadRegReg emits "MOV dst, src" in 32-bit operand size (89 /r), which
// zero-extends into the 64-bit register on x86-64.
func MovLoadRegReg32(dst, src int) []byte { return RegRM(0x89, false, src, dst) }

// MovRegImm64 emits "MOV reg64, imm64" (B8+rd), the one general-purpose move
// that can build an arbitrary 64-bit constant without touching memory.
func MovRegImm64(reg int, imm uint64) []byte {
	out := rex(true, false, false, reg >= 8)
	out = append(out, byte(0xB8+(reg&7)))
	return binary.LittleEndian.AppendUint64(out, imm)
}

// MemDisp8RM emits "<opcode> reg, [base + disp8]" (mod=01, SIB form).
//
// The SIB byte is always emitted, even when the base needs none, because that
// keeps one encoding valid for every base register including RSP and RBP.
func MemDisp8RM(opcode byte, w bool, reg, base int, disp int8) []byte {
	out := rex(w, reg >= 8, false, base >= 8)
	out = append(out, opcode, modrm(1, byte(reg&7), 4), 0x20|byte(base&7), byte(disp))
	return out
}

// JmpRel32 emits a five-byte relative jump.
func JmpRel32(a *Assembler, l int) {
	a.Emit(0xE9)
	a.Rel32(l)
}

// JmpRel8 emits a two-byte relative jump.
func JmpRel8(a *Assembler, l int) {
	a.Emit(0xEB)
	a.Rel8(l)
}

// Cond codes as used in the 0x0F 0x8x / 0x7x encodings.
const (
	CondO  = 0x0
	CondNO = 0x1
	CondB  = 0x2
	CondAE = 0x3
	CondE  = 0x4
	CondNE = 0x5
	CondBE = 0x6
	CondA  = 0x7
	CondS  = 0x8
	CondNS = 0x9
	CondP  = 0xA
	CondNP = 0xB
	CondL  = 0xC
	CondGE = 0xD
	CondLE = 0xE
	CondG  = 0xF
)

// JccRel32 emits a six-byte conditional branch.
func JccRel32(a *Assembler, cond byte, l int) {
	a.Emit(0x0F, 0x80|(cond&0x0F))
	a.Rel32(l)
}

// JccRel8 emits a two-byte conditional branch.
func JccRel8(a *Assembler, cond byte, l int) {
	a.Emit(0x70 | (cond & 0x0F))
	a.Rel8(l)
}
