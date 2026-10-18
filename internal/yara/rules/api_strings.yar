/*
   Suspicious API-name and command-string indicators.

   These are the strings that survive compilation into a binary whether the
   author links statically, dynamically or resolves at runtime: the import name
   has to exist somewhere in the image for the loader - or for a hand-rolled
   resolver - to find it.

   Two consequences worth knowing when reading the analysis report:

     * plural-string conditions (`3 of them`) mean defeating one string is not
       enough - the rule needs several to disappear at once;
     * `wide ascii` doubles the coverage, so a rule with both encodings is
       twice as hard to evade by changing the string encoding alone.
*/

rule suspicious_api_names
{
    meta:
        description = "Several memory-manipulation or remote-thread API names in one blob"
        author      = "pobf"
        severity    = "high"
        category    = "api"
    strings:
        $a = "VirtualAlloc"
        $b = "VirtualProtect"
        $c = "CreateRemoteThread"
        $d = "WriteProcessMemory"
        $e = "GetProcAddress"
        $f = "LoadLibraryA"
        $g = "WinExec"
        $h = "ShellExecuteA"
        $i = "NtCreateThreadEx"
        $j = "RtlMoveMemory"
    condition:
        3 of them
}

rule antimalware_interference
{
    meta:
        description = "Names of AMSI or ETW entry points, i.e. an attempt to blind the sensors"
        author      = "pobf"
        severity    = "high"
        category    = "api"
    strings:
        $a = "AmsiScanBuffer"
        $b = "AmsiInitialize"
        $c = "AmsiOpenSession"
        $d = "EtwEventWrite"
        $e = "amsi.dll"
        $f = "ntdll.dll"
    condition:
        2 of them
}

rule wide_suspicious_api_names
{
    meta:
        description = "Memory-manipulation API names in UTF-16LE, used by .NET and script droppers"
        author      = "pobf"
        severity    = "high"
        category    = "api"
    strings:
        $a = "VirtualAlloc" wide ascii
        $b = "CreateRemoteThread" wide ascii
        $c = "WriteProcessMemory" wide ascii
        $d = "VirtualProtectEx" wide ascii
    condition:
        2 of them
}

rule process_injection_api_set
{
    meta:
        description = "Co-occurrence of remote-process primitives typical of injection"
        author      = "pobf"
        severity    = "high"
        category    = "api"
    strings:
        $a = "VirtualAllocEx"
        $b = "NtUnmapViewOfSection"
        $c = "QueueUserAPC"
        $d = "SetThreadContext"
        $e = "CreateRemoteThread"
        $f = "OpenProcess"
        $g = "ZwMapViewOfSection"
    condition:
        2 of them
}

rule shell_command_strings
{
    meta:
        description = "Command interpreter invocation or a classic post-exploitation path"
        author      = "pobf"
        severity    = "medium"
        category    = "strings"
    strings:
        $a = "/bin/sh"
        $b = "/bin/bash"
        $c = "cmd.exe /c"
        $d = "powershell -"
        $e = "cmd.exe /C"
        $f = "certutil -urlcache"
    condition:
        any of them
}

rule powershell_encoded_command
{
    meta:
        description = "PowerShell reflection or encoded-command flags used to hide a script"
        author      = "pobf"
        severity    = "high"
        category    = "strings"
    strings:
        $a = "-EncodedCommand"
        $b = "FromBase64String"
        $c = "DownloadString"
        $d = "Invoke-Expression"
        $e = "-w hidden"
        $f = "-WindowStyle Hidden"
        $g = "IEX ("
    condition:
        any of them
}
