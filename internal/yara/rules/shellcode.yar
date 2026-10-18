/*
   Shellcode signatures.

   These rules describe byte patterns that appear in position-independent code
   regardless of who wrote it: the stack-alignment prologue every
   Metasploit/msfvenom x86-64 payload starts with, the call-pop getpc idiom that
   makes code position independent, direct-syscall stubs, PEB walking and long
   NOP sleds.

   They are deliberately narrow. Short generic patterns (a lone `0F 05`, a
   single `xor`) are useless as detectors because they fire on ordinary
   compiled code, so every rule here needs either an uncommon sequence or
   several co-occurring strings.
*/

rule shellcode_x64_common_prologue
{
    meta:
        description = "Classic x86-64 shellcode prologue: cld; and rsp, -16; getpc call"
        author      = "pobf"
        severity    = "high"
        category    = "shellcode"
    strings:
        $prologue = { FC 48 83 E4 F0 }
        $getpc    = { E8 00 00 00 00 5? }
    condition:
        any of them
}

rule shellcode_x86_getpc
{
    meta:
        description = "call-pop getpc idiom used by position-independent 32-bit code"
        author      = "pobf"
        severity    = "medium"
        category    = "shellcode"
    strings:
        $a = { E8 00 00 00 00 58 }
        $b = { E8 00 00 00 00 59 }
        $c = { E8 00 00 00 00 5A }
        $d = { E8 00 00 00 00 5B }
        $e = { E8 00 00 00 00 5E }
        $f = { E8 00 00 00 00 5F }
    condition:
        any of them
}

rule shellcode_syscall_stub
{
    meta:
        description = "Direct syscall immediately followed by a return or jump"
        author      = "pobf"
        severity    = "medium"
        category    = "shellcode"
    strings:
        $a = { 0F 05 C3 }
        $b = { 0F 05 C2 }
        $c = { 0F 05 EB }
        $d = { 0F 05 4C 89 }
    condition:
        any of them
}

rule shellcode_peb_access_x64
{
    meta:
        description = "Reads the PEB through gs:[0x60], the first step of dynamic API resolution"
        author      = "pobf"
        severity    = "high"
        category    = "shellcode"
    strings:
        $a = { 65 48 8B 04 25 60 00 00 00 }
        $b = { 65 4C 8B 04 25 60 00 00 00 }
        $c = { 64 48 8B 04 25 60 00 00 00 }
    condition:
        any of them
}

rule shellcode_nop_sled
{
    meta:
        description = "Sixteen or more consecutive single-byte NOPs: a sled or alignment padding"
        author      = "pobf"
        severity    = "low"
        category    = "shellcode"
    strings:
        $sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $sled
}
