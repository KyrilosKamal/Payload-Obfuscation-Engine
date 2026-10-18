package encode

import (
	"encoding/binary"
)

// peSig is the signature at the start of a PE/COFF header.
var peSig = [4]byte{'P', 'E', 0, 0}

// IsPE reports whether b starts with a DOS header whose e_lfanew points at a PE
// signature.
//
// A PE is a legitimate input to every stage, but what comes out is not a PE. It
// is a container: the payload has been replaced (xor, aes, base64) or rewritten
// in place (strings), and a decoder step has to run before the image can be
// loaded or mapped. For strings that is doubly true, because the bytes it masks
// are ones a PE's own loader reads -- the import table, the data directories --
// long before any stub of ours could run, so the container must be decoded back
// to the original file rather than executed in place.
//
// The check is shape-only on purpose: it does not validate the optional header,
// so a truncated or deliberately malformed PE is still reported as one. Naming
// the input honestly is the point; blessing it is not.
func IsPE(b []byte) bool {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	at := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if at < 0 || at+len(peSig) > len(b) {
		return false
	}
	for i := range peSig {
		if b[at+i] != peSig[i] {
			return false
		}
	}
	return true
}

// InputKind names the payload shape a stage was handed, for the report.
type InputKind string

const (
	InputRaw InputKind = "raw"
	InputPE  InputKind = "pe"
)

// PEContainerNote is the caveat that has to travel with any artefact built from
// a PE input. It lives here so the stage detail and the report headline cannot
// drift apart.
const PEContainerNote = "input is a PE image: the artefact is a container, not a loadable file -- " +
	"decode it to recover the original PE; do not execute or jump into the payload, which starts " +
	"with a PE header"

// ClassifyInput names the payload and, when the name changes what the artefact
// is, explains it.
//
// Saying this out loud is the difference between a tool that is honest about its
// output and one that reports "verified" on a file nobody can run: a PE input
// produces a container, and the container has to be decoded before the original
// image can be loaded, because the bytes a PE loader reads first are exactly the
// bytes the container replaced or masked.
func ClassifyInput(src []byte) (InputKind, string) {
	if !IsPE(src) {
		return InputRaw, ""
	}
	return InputPE, PEContainerNote
}
