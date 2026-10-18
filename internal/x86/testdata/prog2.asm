; prog2.asm - second semantic-equivalence fixture.
;
; int classify(int a, int b)   /  edi = a, esi = b, result in eax
;
; Exercises a two-way conditional and a forward unconditional jump, i.e. the
; cases where a size-changing morph must relocate two branch displacements and
; where flattening must rewrite both successors of a conditional block.
;
; Regenerate with: make fixtures
BITS 64

classify:
    mov     eax, edi
    imul    eax, esi            ; eax = a * b
    cmp     edi, esi
    jle     .else
    mov     ecx, edi
    sub     ecx, esi            ; a - b
    jmp     .join
.else:
    mov     ecx, esi
    sub     ecx, edi            ; b - a
.join:
    add     eax, ecx
    ret
