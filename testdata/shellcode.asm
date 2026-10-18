; shellcode.asm - shape fixture for the shellcode rules and the code stages.
;
; This is not shellcode and it does not do anything: it is a small, benign,
; position-independent routine that carries the instruction shapes the
; instruction-level rules and the metamorphic engine care about, so that both
; can be exercised end to end.
;
; What it deliberately contains, and why:
;
;   cld; and rsp, -16; call $+5   the stack-alignment prologue (FC 48 83 E4 F0)
;   pop rbx                       the call-pop getpc idiom (E8 00.. 5B)
;   mov rax, gs:[0x60]            the PEB read (65 48 8B 04 25 60 00 00 00)
;   sixteen NOPs                  a NOP sled (90 x16)
;   a counted loop                several basic blocks and a backward branch
;   ret                           a control-flow terminator, which is what
;                                 control-flow flattening requires to run
;
; What it deliberately omits: a syscall. SYSCALL is classified as a trap by the
; rewriter (flow stops there, so no block after it can be relocated), and this
; fixture exists to exercise the code stages, so it has to stay relocatable.
; The syscall rule is covered by the unit tests instead.
;
; The payload is code-only: no embedded data, no RIP-relative operands, and
; every branch target lands on an instruction boundary inside the image.
; Regenerate with: make fixtures

BITS 64

_start:
    cld
    and     rsp, -16
    call    .getpc
.getpc:
    pop     rbx
    mov     rax, [gs:0x60]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    xor     eax, eax
    mov     ecx, 8
.acc:
%rep 8
    add     eax, ecx
    imul    eax, eax, 3
    mov     edx, eax
    sub     edx, ecx
    xor     edx, ecx
    add     eax, edx
%endrep
    dec     ecx
    jnz     .acc

    mov     r8d, 0
    test    r8d, r8d
    jz      .skip
    add     eax, 1
.skip:
    add     rbx, rax
    mov     rax, rbx
    ret
