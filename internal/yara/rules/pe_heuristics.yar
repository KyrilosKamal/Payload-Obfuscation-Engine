/*
   PE-structure and entropy heuristics.

   These rules do not look for a known string or byte pattern; they look at
   shape. That makes them the hardest family to defeat with a payload-level
   transform, because every transform in this engine adds bytes and pushes the
   entropy of the result upward:

     * XOR with a random key turns plaintext structure into uniform noise, so
       entropy rises towards 8.0 bits/byte;
     * AES-256 does the same deliberately;
     * Base64 is the one transform that lowers entropy, because it restricts
       the alphabet to 64 symbols - which is itself a signature, and is caught
       by the canonical-alphabet rules in encoder_stubs.yar.

   The honest conclusion the analysis report is built to surface: entropy-based
   detection gets *worse* for every encoding stage except Base64, and no amount
   of decoder-stub work changes that.

   `import "math"` and `import "pe"` are repeated in every rule file that needs
   them, because YARA imports are per-file.
*/

import "math"
import "pe"

rule pe_high_entropy_body
{
    meta:
        description = "Whole-file entropy above 7.2 bits/byte, consistent with packed or encrypted content"
        author      = "pobf"
        severity    = "medium"
        category    = "entropy"
    condition:
        filesize > 1024 and math.entropy(0, filesize) > 7.2
}

rule pe_executable_section_high_entropy
{
    meta:
        description = "A PE section with entropy above 7.0 - the canonical packer heuristic"
        author      = "pobf"
        severity    = "high"
        category    = "entropy"
    condition:
        pe.is_pe and filesize > 1024 and
        (math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.0 or
         math.entropy(pe.sections[1].raw_data_offset, pe.sections[1].raw_data_size) > 7.0 or
         math.entropy(pe.sections[2].raw_data_offset, pe.sections[2].raw_data_size) > 7.0)
}

rule pe_injection_imports
{
    meta:
        description = "Imports allocation and remote-thread creation together"
        author      = "pobf"
        severity    = "high"
        category    = "pe"
    condition:
        pe.is_pe and pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

rule high_entropy_blob_without_pe_header
{
    meta:
        description = "Large, dense blob with no MZ header: raw shellcode or an encrypted stage"
        author      = "pobf"
        severity    = "medium"
        category    = "entropy"
    condition:
        not pe.is_pe and filesize >= 512 and math.entropy(0, filesize) > 7.4
}
