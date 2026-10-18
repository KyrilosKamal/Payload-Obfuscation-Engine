package x86

import (
	"fmt"
	"math/rand/v2"
)

// CFFOptions controls control-flow flattening.
type CFFOptions struct {
	// MaxBlocks refuses to flatten payloads with more basic blocks than this
	// (0 = unlimited). Flattening multiplies code size, so a cap keeps the
	// result usable.
	MaxBlocks int
	// Shuffle randomises both the state numbering and the in-memory order of the
	// block bodies.
	Shuffle bool
}

// DefaultCFFOptions returns the tuned defaults.
func DefaultCFFOptions() CFFOptions { return CFFOptions{Shuffle: true} }

// CFFResult describes a flattening run.
type CFFResult struct {
	Blocks       int   `json:"blocks"`
	States       int   `json:"states"`
	OutputSize   int   `json:"output_size"`
	InputSize    int   `json:"input_size"`
	CodeSize     int   `json:"code_size"`
	EntryState   int   `json:"entry_state"`
	DispatchSize int   `json:"dispatch_size"`
	Order        []int `json:"block_order"`
}

// Flatten converts straight-line basic blocks into a dispatcher loop driven by a
// state variable, then scrambles the block order.
//
// The transformation is designed to be *semantically exact*, not approximate:
//
//   - The dispatcher preserves RAX, RBX, R14, R15 and EFLAGS around every
//     dispatch, and keeps the state and jump target in private memory rather
//     than in a live register or on the stack. Every original block therefore
//     begins with exactly the register, flag and stack state it would have had
//     in the original program.
//   - Block bodies are copied verbatim (relative calls are re-encoded), so the
//     only observable change is the order of bytes in the image.
//
// The price of that exactness is a precondition: the payload must be pure,
// position-independent code whose control flow is fully resolvable statically.
// Payloads that embed data among instructions, jump through a register, or
// reference embedded data RIP-relatively are refused with a reason instead of
// being silently mangled.
func Flatten(b []byte, rng *rand.Rand, opts CFFOptions) ([]byte, *CFFResult, error) {
	instrs := Disassemble(b)
	if ok, reason := Relocatable(instrs); !ok {
		return nil, nil, &NotRewritableError{Reason: reason}
	}
	for i := range instrs {
		kind, _, ok := relativeOperand(&instrs[i])
		if ok && kind == relRIP {
			return nil, nil, &NotRewritableError{
				Reason: fmt.Sprintf("instruction at %#x references embedded data RIP-relatively; "+
					"flattening only supports pure code", instrs[i].Off),
			}
		}
	}

	cfg := Analyze(instrs)
	blocks := cfg.Blocks
	if len(blocks) == 0 {
		return nil, nil, &NotRewritableError{Reason: "no basic blocks found"}
	}
	if opts.MaxBlocks > 0 && len(blocks) > opts.MaxBlocks {
		return nil, nil, &NotRewritableError{
			Reason: fmt.Sprintf("%d basic blocks exceeds the configured cap of %d", len(blocks), opts.MaxBlocks),
		}
	}

	// A block that falls off the end of the image has no well-defined successor
	// once the image grows a data section and a dispatcher.
	endOff := cfg.endOffset()
	lastBlock := &blocks[len(blocks)-1]
	lastInstr := &instrs[lastBlock.LastInstr()]
	if !lastInstr.Terminates() && !lastInstr.IsCond && lastInstr.FallThrough >= endOff {
		return nil, nil, &NotRewritableError{Reason: "payload does not end at a control-flow terminator"}
	}

	// State assignment. stateOf[block] is the value the dispatcher selects on;
	// order[s] is the block that state s resolves to, which also fixes the
	// on-disk order of the bodies.
	order := make([]int, len(blocks))
	for i := range order {
		order[i] = i
	}
	if opts.Shuffle {
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	stateOf := make([]int, len(blocks))
	for pos, blk := range order {
		stateOf[blk] = pos
	}

	// --- pre-flight: every successor must resolve, and no call may target a
	// instruction whose encoding we are about to replace.
	for bi := range blocks {
		b := &blocks[bi]
		li := &instrs[b.LastInstr()]
		switch {
		case li.IsCond:
			if _, ok := stateForOffset(cfg, stateOf, li.Target); !ok {
				return nil, nil, &NotRewritableError{
					Reason: fmt.Sprintf("conditional branch at %#x targets %#x outside the graph", li.Off, li.Target),
				}
			}
			if _, ok := stateForOffset(cfg, stateOf, li.FallThrough); !ok && li.FallThrough < endOff {
				return nil, nil, &NotRewritableError{
					Reason: fmt.Sprintf("conditional branch at %#x has no fallthrough block", li.Off),
				}
			}
		case li.IsJmp:
			if _, ok := stateForOffset(cfg, stateOf, li.Target); !ok {
				return nil, nil, &NotRewritableError{
					Reason: fmt.Sprintf("jump at %#x targets %#x outside the graph", li.Off, li.Target),
				}
			}
		case !li.Terminates():
			if li.FallThrough < endOff {
				if _, ok := stateForOffset(cfg, stateOf, li.FallThrough); !ok {
					return nil, nil, &NotRewritableError{
						Reason: fmt.Sprintf("fallthrough from %#x has no successor block", li.Off),
					}
				}
			}
		}
	}
	replaced := map[int]bool{}
	for bi := range blocks {
		b := &blocks[bi]
		li := &instrs[b.LastInstr()]
		if li.IsCond || li.IsJmp {
			replaced[li.Off] = true
		}
	}
	for i := range instrs {
		in := &instrs[i]
		if in.IsCall && in.HasTarget && replaced[in.Target] {
			return nil, nil, &NotRewritableError{
				Reason: fmt.Sprintf("call at %#x targets %#x, a branch being replaced by the dispatcher",
					in.Off, in.Target),
			}
		}
	}

	a := NewAssembler()
	lblDispatch := a.NewLabel()
	lblState := a.NewLabel()
	lblTarget := a.NewLabel()
	lblTable := a.NewLabel()
	blkLabel := make([]int, len(blocks))
	for i := range blkLabel {
		blkLabel[i] = a.NewLabel()
	}
	insLabel := make(map[int]int, len(instrs))
	for i := range instrs {
		insLabel[instrs[i].Off] = a.NewLabel()
	}

	entryState := stateOf[0]

	// --- entry stub: set the entry state and hand control to the dispatcher.
	a.EmitBytes(RipRM(0xC7, true, 0)) // mov qword [rip+state], imm32
	a.RIP32Imm32(lblState, int32(entryState))
	JmpRel32(a, lblDispatch)

	// --- dispatcher -------------------------------------------------------
	a.Bind(lblDispatch)
	dispatchStart := a.Len()
	emitDispatcher(a, lblState, lblTarget, lblTable)
	dispatchSize := a.Len() - dispatchStart

	// --- block bodies -----------------------------------------------------
	for _, bi := range order {
		b := &blocks[bi]
		a.Bind(blkLabel[bi])
		li := &instrs[b.LastInstr()]
		replaceTerminator := li.IsCond || li.IsJmp
		body := b.Instrs
		if replaceTerminator {
			body = body[:len(body)-1]
		}
		for _, ii := range body {
			in := &instrs[ii]
			a.Bind(insLabel[in.Off])
			if in.IsCall && in.HasTarget {
				tl, ok := insLabel[in.Target]
				if !ok {
					return nil, nil, fmt.Errorf("cff: call at %#x targets %#x with no label", in.Off, in.Target)
				}
				a.Emit(0xE8)
				a.Rel32(tl)
				continue
			}
			a.EmitBytes(in.Raw)
		}

		switch {
		case li.IsCond:
			fallState, _ := stateForOffset(cfg, stateOf, li.FallThrough)
			takenState, _ := stateForOffset(cfg, stateOf, li.Target)
			skip := a.NewLabel()
			JccRel8(a, li.Cond, skip)
			emitSetState(a, lblState, fallState)
			JmpRel32(a, lblDispatch)
			a.Bind(skip)
			emitSetState(a, lblState, takenState)
			JmpRel32(a, lblDispatch)
		case li.IsJmp:
			target, _ := stateForOffset(cfg, stateOf, li.Target)
			emitSetState(a, lblState, target)
			JmpRel32(a, lblDispatch)
		case li.Terminates():
			// ret / trap: a sink. The block simply ends here.
		default:
			if li.FallThrough < endOff {
				fall, _ := stateForOffset(cfg, stateOf, li.FallThrough)
				emitSetState(a, lblState, fall)
				JmpRel32(a, lblDispatch)
			}
		}
	}

	// --- private data: state slot, target slot, jump table ----------------
	//
	// Everything above this point is executable; everything below is data. The
	// split matters for the self-check: a linear disassembly of the *code* must
	// be exhaustive, because a decoder sweeping the flattened image has to stay
	// in sync, but the data section is intentionally not valid instructions.
	codeEnd := a.Len()
	a.Bind(lblState)
	a.Imm64(0)
	a.Bind(lblTarget)
	a.Imm64(0)
	a.Align(4, 0x90)
	a.Bind(lblTable)
	for s := 0; s < len(blocks); s++ {
		a.RelToLabel(blkLabel[order[s]], lblTable)
	}

	out, err := a.Bytes()
	if err != nil {
		return nil, nil, err
	}
	check := Disassemble(out[:codeEnd])
	if ok, bad := IsClean(check); !ok {
		return nil, nil, &NotRewritableError{
			Reason: fmt.Sprintf("flattened output has %d undecodable bytes; refusing to emit", bad),
		}
	}
	return out, &CFFResult{
		Blocks: len(blocks), States: len(blocks),
		OutputSize: len(out), InputSize: len(b), EntryState: entryState,
		DispatchSize: dispatchSize, Order: order, CodeSize: codeEnd,
	}, nil
}

// emitDispatcher emits the shared dispatch loop.
//
// Notably it does not depend on the stack pointer's value: it pushes and pops
// symmetrically, so a flattened block is free to rewrite RSP (a normal function
// prologue does exactly that).
func emitDispatcher(a *Assembler, lblState, lblTarget, lblTable int) {
	a.Emit(0x9C)                       // pushfq
	a.EmitBytes(PushReg(0))            // push rax
	a.EmitBytes(PushReg(3))            // push rbx
	a.EmitBytes(PushReg(14))           // push r14
	a.EmitBytes(PushReg(15))           // push r15
	a.EmitBytes(RipRM(0x8B, true, 15)) // mov r15, [rip+state]
	a.RIP32(lblState)
	a.EmitBytes(RipRM(0x8D, true, 14)) // lea r14, [rip+table]
	a.RIP32(lblTable)
	// movsxd rax, [r14 + r15*4]
	//
	// The table stores (block - table), which is negative for every block
	// because the table sits at the end of the image. A plain 32-bit load would
	// zero-extend that into a huge positive address, so the sign extension is
	// load-bearing.
	a.EmitBytes(SIBIndexScaleRM(0x63, true, 0, 15, 14, 4))
	a.EmitBytes(RegRM(0x01, true, 14, 0)) // add rax, r14
	a.EmitBytes(RipRM(0x89, true, 0))     // mov [rip+target], rax
	a.RIP32(lblTarget)
	a.EmitBytes(PopReg(15))            // pop r15
	a.EmitBytes(PopReg(14))            // pop r14
	a.EmitBytes(PopReg(3))             // pop rbx
	a.EmitBytes(PopReg(0))             // pop rax
	a.Emit(0x9D)                       // popfq
	a.EmitBytes(RipRM(0xFF, false, 4)) // jmp qword [rip+target]
	a.RIP32(lblTarget)
}

// emitSetState emits "mov qword [rip+state], imm32", which does not touch
// EFLAGS - important, because a conditional branch's flags must survive until
// the replacement Jcc has consumed them.
func emitSetState(a *Assembler, lblState, state int) {
	a.EmitBytes(RipRM(0xC7, true, 0))
	a.RIP32Imm32(lblState, int32(state))
}

// DispatcherSize reports the fixed overhead of the dispatch loop in bytes.
func DispatcherSize() int {
	a := NewAssembler()
	s, t, tb := a.NewLabel(), a.NewLabel(), a.NewLabel()
	start := a.Len()
	emitDispatcher(a, s, t, tb)
	return a.Len() - start
}

// stateForOffset returns the state id of the block containing off.
func stateForOffset(cfg *CFG, stateOf []int, off int) (int, bool) {
	idx, ok := cfg.Index[off]
	if !ok {
		return 0, false
	}
	bi := cfg.blockOf(idx)
	if bi < 0 {
		return 0, false
	}
	return stateOf[bi], true
}
