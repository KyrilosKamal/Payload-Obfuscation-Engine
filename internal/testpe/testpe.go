// Package testpe builds minimal but structurally valid PE images for tests.
//
// The YARA rules in internal/yara/rules include four that only make sense for a
// real PE: `pe.is_pe`, the section-entropy heuristic and the two import checks.
// Without a PE fixture those rules would be dead weight that nothing exercises,
// and the cross-validation test against libyara would have nothing to agree
// about.
//
// The images produced here are hand-assembled headers plus a data directory
// pointing at an import table. They are not runnable programs: there is no
// entry-point code, no relocations and no checksum. They are runnable *enough*
// for a static analyser, which is the point.
package testpe

import (
	"encoding/binary"
	"math/rand"
)

const (
	fileAlign = 0x200
	secAlign  = 0x1000

	textRVA  = 0x1000
	textRaw  = 0x200
	rdataRVA = 0x2000
	rdataRaw = 0x400

	// Inside .rdata: descriptors, thunk arrays, the DLL name and the
	// IMAGE_IMPORT_BY_NAME records.
	impDescRVA  = rdataRVA + 0x000
	impThunkRVA = rdataRVA + 0x040
	dllNameRVA  = rdataRVA + 0x060
	iThunkRVA   = rdataRVA + 0x080
	namesRVA    = rdataRVA + 0x0C0
	nameStride  = 0x20
)

// DefaultImports is the import set that the YARA rules in this project look for:
// allocation plus remote-thread creation, which trips pe_injection_imports.
var DefaultImports = []string{"VirtualAlloc", "CreateRemoteThread", "LoadLibraryA", "GetProcAddress"}

// Build returns a PE32+ image with two sections (.text, .rdata) and one import
// descriptor for kernel32.dll.
//
// When dense is true the .text section is filled with pseudo-random bytes, which
// pushes its entropy to roughly 8 bits/byte and makes
// pe_executable_section_high_entropy fire. When dense is false it is mostly
// zeroes, which makes it fire on nothing.
func Build(dense bool) []byte { return BuildWith(DefaultImports, dense) }

// BuildWith is Build with an explicit import list.
func BuildWith(imports []string, dense bool) []byte {
	const (
		headerSize = 0x200
		total      = headerSize + textRaw + rdataRaw
	)
	img := make([]byte, total)

	// DOS header.
	copy(img[0:], "MZ")
	binary.LittleEndian.PutUint16(img[0x02:], 0x90) // e_cblp
	binary.LittleEndian.PutUint16(img[0x04:], 0x03) // e_cp
	binary.LittleEndian.PutUint16(img[0x18:], 0x40) // e_lfarlc
	binary.LittleEndian.PutUint32(img[0x3C:], 0x80) // e_lfanew
	binary.LittleEndian.PutUint32(img[0x40:], 0x80) // padding

	// COFF header at 0x80.
	const coff = 0x80
	copy(img[coff:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[coff+4:], 0x8664) // IMAGE_FILE_MACHINE_AMD64
	binary.LittleEndian.PutUint16(img[coff+6:], 2)      // NumberOfSections
	binary.LittleEndian.PutUint32(img[coff+8:], 0x5F5E1000)
	binary.LittleEndian.PutUint16(img[coff+20:], 0xF0)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(img[coff+22:], 0x0022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	// Optional header (PE32+) at 0x98.
	const opt = coff + 24
	binary.LittleEndian.PutUint16(img[opt+0:], 0x20B) // PE32+
	binary.LittleEndian.PutUint32(img[opt+4:], textRaw)
	binary.LittleEndian.PutUint32(img[opt+8:], rdataRaw)
	binary.LittleEndian.PutUint32(img[opt+16:], textRVA) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(img[opt+20:], textRVA) // BaseOfCode
	binary.LittleEndian.PutUint64(img[opt+24:], 0x140000000)
	binary.LittleEndian.PutUint32(img[opt+32:], secAlign)
	binary.LittleEndian.PutUint32(img[opt+36:], fileAlign)
	binary.LittleEndian.PutUint16(img[opt+40:], 6)      // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(img[opt+48:], 6)      // MajorSubsystemVersion
	binary.LittleEndian.PutUint32(img[opt+56:], 0x2000) // SizeOfImage
	binary.LittleEndian.PutUint32(img[opt+60:], headerSize)
	binary.LittleEndian.PutUint16(img[opt+68:], 3) // Subsystem: console
	binary.LittleEndian.PutUint64(img[opt+72:], 0x100000)
	binary.LittleEndian.PutUint64(img[opt+80:], 0x1000)
	binary.LittleEndian.PutUint64(img[opt+88:], 0x100000)
	binary.LittleEndian.PutUint64(img[opt+96:], 0x1000)
	binary.LittleEndian.PutUint32(img[opt+108:], 16) // NumberOfRvaAndSizes
	// Data directory 1 = import table.
	binary.LittleEndian.PutUint32(img[opt+112+8:], impDescRVA)
	binary.LittleEndian.PutUint32(img[opt+112+12:], 40)

	// Section table at 0x188.
	const sec = opt + 0xF0
	copy(img[sec:], ".text")
	binary.LittleEndian.PutUint32(img[sec+8:], textRaw)
	binary.LittleEndian.PutUint32(img[sec+12:], textRVA)
	binary.LittleEndian.PutUint32(img[sec+16:], textRaw)
	binary.LittleEndian.PutUint32(img[sec+20:], textRaw) // PointerToRawData
	binary.LittleEndian.PutUint32(img[sec+36:], 0x60000020)

	copy(img[sec+40:], ".rdata")
	binary.LittleEndian.PutUint32(img[sec+40+8:], rdataRaw)
	binary.LittleEndian.PutUint32(img[sec+40+12:], rdataRVA)
	binary.LittleEndian.PutUint32(img[sec+40+16:], rdataRaw)
	binary.LittleEndian.PutUint32(img[sec+40+20:], headerSize+textRaw)
	binary.LittleEndian.PutUint32(img[sec+40+36:], 0x40000040)

	// .text contents.
	text := img[textRaw : textRaw+textRaw]
	if dense {
		rand.New(rand.NewSource(0x5EED)).Read(text)
	} else {
		// A few instructions then zero padding: low entropy, no detection.
		copy(text, []byte{0x48, 0x31, 0xC0, 0xC3})
	}

	// Import directory.
	rvaToOff := func(rva uint32) int { return int(rva-rdataRVA) + headerSize + textRaw }
	put64 := func(rva uint32, v uint64) { binary.LittleEndian.PutUint64(img[rvaToOff(rva):], v) }
	put32 := func(rva uint32, v uint32) { binary.LittleEndian.PutUint32(img[rvaToOff(rva):], v) }

	put32(impDescRVA+0, impThunkRVA)
	put32(impDescRVA+12, dllNameRVA)
	put32(impDescRVA+16, iThunkRVA)
	// The second descriptor stays zero, terminating the array.

	copy(img[rvaToOff(dllNameRVA):], "kernel32.dll\x00")
	for i, name := range imports {
		rec := namesRVA + uint32(i)*nameStride
		put64(impThunkRVA+uint32(i)*8, uint64(rec))
		put64(iThunkRVA+uint32(i)*8, uint64(rec))
		off := rvaToOff(rec)
		binary.LittleEndian.PutUint16(img[off:], 0) // Hint
		copy(img[off+2:], name)
	}
	return img
}
