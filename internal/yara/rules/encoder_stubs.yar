/*
   Decoder-stub and encoding-container signatures.

   The point of this file is the uncomfortable half of payload obfuscation:
   whatever you XOR, encrypt or Base64-encode, you must ship a decoder with it,
   and the decoder is a much more distinctive artifact than the payload it
   protects. Every rule here targets a decoder shape rather than its data.

   Two families are covered:

     * instruction shapes - an in-place XOR loop, a table-driven Base64
       translate loop, a record-walking rebuild loop;
     * data shapes - a Base64 alphabet materialised as a literal, and a
       canonical Base64 blob.

   The canonical-Base64 rules are exactly what a custom alphabet defeats, which
   is why the analysis report can show a real detection drop for that stage
   while the instruction-shape rules keep firing.
*/

rule decoder_inplace_xor_loop_x64
{
    meta:
        description = "In-place XOR decode loop: xor [rsi], al with a 64-bit pointer increment"
        author      = "pobf"
        severity    = "high"
        category    = "decoder"
    strings:
        $xor   = { 30 06 }
        $incsi = { 48 FF C6 }
        $incdi = { 48 FF C7 }
    condition:
        $xor and ($incsi or $incdi)
}

rule decoder_base64_table_lookup
{
    meta:
        description = "Table-driven Base64 decode loop: movzx reg, byte [table + index]"
        author      = "pobf"
        severity    = "medium"
        category    = "decoder"
    strings:
        $a = { 0F B6 04 00 }
        $b = { 0F B6 14 10 }
        $c = { 0F B6 0C 08 }
        $d = { 0F B6 0C 03 }
    condition:
        2 of them
}

rule decoder_literal_rebuild_loop
{
    meta:
        description = "Walks a table of fixed-size records and rewrites the payload in place"
        author      = "pobf"
        severity    = "medium"
        category    = "decoder"
    strings:
        $xor  = { 44 30 10 }
        $adv9 = { 49 83 C0 09 }
    condition:
        $xor and $adv9
}

rule base64_canonical_alphabet_literal
{
    meta:
        description = "The standard Base64 alphabet appears as a literal, i.e. a shipped decoder table"
        author      = "pobf"
        severity    = "high"
        category    = "encoder"
    strings:
        $std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    condition:
        $std
}

rule base64_canonical_blob
{
    meta:
        description = "A long run of canonical Base64 characters with padding"
        author      = "pobf"
        severity    = "medium"
        category    = "encoder"
    strings:
        $blob = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        $blob
}
