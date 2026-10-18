; loader_table.asm - shape fixture for the API-name and command-string rules.
;
; A loader has to keep its import names and its command strings somewhere in the
; image, and those literals are what static detection actually finds. This
; fixture is exactly that: a data blob of the names the rules look for, in both
; ASCII and UTF-16LE, plus the command and PowerShell strings.
;
; Nothing here executes. It exists so the string stage can be measured against
; rules that it is supposed to defeat, and so the report can show the difference
; between masking a literal and removing the rule's evidence entirely.
;
; The instruction-level stages refuse this file, correctly: it is data, not a
; decodable instruction stream, and rewriting it would corrupt it.
;
; Regenerate with: make fixtures

BITS 64

names_ascii:
    db "VirtualAlloc", 0
    db "VirtualProtect", 0
    db "CreateRemoteThread", 0
    db "WriteProcessMemory", 0
    db "VirtualAllocEx", 0
    db "OpenProcess", 0
    db "SetThreadContext", 0
    db "GetProcAddress", 0
    db "LoadLibraryA", 0

sensors:
    db "AmsiScanBuffer", 0
    db "EtwEventWrite", 0
    db "amsi.dll", 0
    db "ntdll.dll", 0

commands:
    db "cmd.exe /c ", 0
    db "powershell -", 0
    db "-EncodedCommand ", 0
    db "FromBase64String", 0

; UTF-16LE copies, which is what a .NET or script-based loader would carry.
names_wide:
    dw `V`,`i`,`r`,`t`,`u`,`a`,`l`,`A`,`l`,`l`,`o`,`c`,0
    dw `C`,`r`,`e`,`a`,`t`,`e`,`R`,`e`,`m`,`o`,`t`,`e`,`T`,`h`,`r`,`e`,`a`,`d`,0
    dw `W`,`r`,`i`,`t`,`e`,`P`,`r`,`o`,`c`,`e`,`s`,`s`,`M`,`e`,`m`,`o`,`r`,`y`,0
    dw `V`,`i`,`r`,`t`,`u`,`a`,`l`,`P`,`r`,`o`,`t`,`e`,`c`,`t`,`E`,`x`,0
