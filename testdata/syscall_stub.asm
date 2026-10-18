; syscall_stub.asm - a code fixture that contains a syscall.
;
; This is not shellcode and it does nothing: like shellcode.asm it is a small,
; benign, position-independent routine carrying the instruction shapes the
; code-level stages care about. Its one difference is the `syscall`.
;
; That matters because a real payload issues one, and the engine used to refuse
; any payload containing a syscall -- which is to say, essentially every real
; one. SYSCALL enters the kernel and returns to the *following* instruction, so
; it is fallthrough, not a terminator, and classifying it as a trap was simply
; wrong. This fixture exists so that regression cannot come back silently.
;
; The trailing `syscall; ret` also trips the shellcode_syscall_stub rule, which
; is what the fixture is detected by. Whether a stage then clears that rule
; depends on whether it happens to insert between the two instructions, which is
; seed-dependent, so nothing depends on it: the point of the fixture is that the
; code stages run at all, and that the instruction comes out unchanged.
;
; Constraints every code fixture must respect (see internal/x86/cff.go):
;   * pure code: no embedded data
;   * no RIP-relative operands
;   * every branch target is an instruction boundary inside the image
;   * the image ends at a control-flow terminator (ret)
;
; Regenerate with: make fixtures
BITS 64

_start:
    xor     eax, eax            ; acc = 0        (morphs to: mov eax, 0)
    mov     ecx, 8              ; i = 8
.loop:
    add     eax, ecx            ; acc += i
    dec     ecx                 ;                (morphs to: sub ecx, 1)
    jnz     .loop
    mov     eax, 60             ; sys_exit, as a shape rather than an effect
    xor     edi, edi            ;                (morphs to: mov edi, 0)
    syscall                     ; returns to the instruction after it
    ret
