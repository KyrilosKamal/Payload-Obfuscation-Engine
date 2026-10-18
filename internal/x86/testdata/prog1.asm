; prog1.asm - semantic-equivalence fixture for the x86 obfuscation stages.
;
; int compute(int n)   /  System V AMD64: edi = n, return value in eax
;
; Deliberately written to contain the instruction shapes the metamorphic table
; targets: the xor-zeroing idiom, test-vs-or, dec/inc, 32- and 64-bit moves, a
; backward branch (loop) and a forward conditional branch, plus a push/pop pair.
;
; Constraints the fixtures must respect (see internal/x86/cff.go):
;   * pure code: no embedded data
;   * no RIP-relative operands
;   * every branch target is an instruction boundary inside the image
;   * the image ends at a control-flow terminator (ret)
;
; Regenerate with: make fixtures
BITS 64

compute:
    xor     eax, eax            ; acc = 0            (morphs to: mov eax, 0)
    mov     ecx, edi            ; i = n
    test    ecx, ecx            ;                    (morphs to: or ecx, ecx)
    jle     .done
.loop:
    add     eax, ecx
    imul    eax, eax, 3
    dec     ecx                 ;                    (morphs to: sub ecx, 1)
    jnz     .loop
.done:
    push    rbx
    mov     ebx, eax
    mov     rax, rbx            ; 64-bit move        (morphs to: push rbx; pop rax)
    xor     edx, edx
    add     eax, edx
    pop     rbx
    nop
    ret
