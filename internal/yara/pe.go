package yara

import (
	"encoding/binary"
	"math"
	"strings"
)

// The PE module is a heavily truncated version of YARA's: enough to write the
// rules that matter for a payload-obfuscation engine (is this a PE, how many
// sections, what does it import, how dense is each section) and no more.

type peSection struct {
	Name            string
	VirtualSize     uint32
	VirtualAddress  uint32
	RawSize         uint32
	RawPtr          uint32
	Characteristics uint32
}

type peImport struct {
	DLL  string
	Func string
}

type peFile struct {
	data        []byte
	valid       bool
	machine     uint16
	is64        bool
	numSects    uint32
	timestamp   uint32
	entryRVA    uint32
	sizeOfImage uint32

	sections []peSection
	imports  []peImport

	importByDLL map[string]map[string]bool
	importAny   map[string]bool
}

// parsePE decodes the headers that the pe.* references need. A file that is not
// a PE yields a peFile with valid=false rather than an error, because a rule
// referring to pe.* must still evaluate to false on shellcode.
func parsePE(data []byte) *peFile {
	pe := &peFile{data: data}
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return pe
	}
	eLfanew := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if eLfanew < 0x40 || eLfanew+24 > len(data) {
		return pe
	}
	if string(data[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		return pe
	}
	coff := eLfanew + 4
	if coff+20 > len(data) {
		return pe
	}
	pe.machine = binary.LittleEndian.Uint16(data[coff:])
	pe.numSects = uint32(binary.LittleEndian.Uint16(data[coff+2:]))
	pe.timestamp = binary.LittleEndian.Uint32(data[coff+4:])
	sizeOpt := int(binary.LittleEndian.Uint16(data[coff+16:]))
	opt := coff + 20
	if opt+sizeOpt > len(data) || sizeOpt < 96 {
		return pe
	}
	magic := binary.LittleEndian.Uint16(data[opt:])
	switch magic {
	case 0x10B:
		pe.is64 = false
	case 0x20B:
		pe.is64 = true
	default:
		return pe
	}
	pe.entryRVA = binary.LittleEndian.Uint32(data[opt+16:])
	pe.sizeOfImage = binary.LittleEndian.Uint32(data[opt+56:])

	ddOff := opt + 96
	ddCount := 16
	if pe.is64 {
		ddOff = opt + 112
	}
	if opt+92+4 <= len(data) {
		if n := binary.LittleEndian.Uint32(data[opt+92:]); pe.is64 {
			_ = n
		}
	}
	if pe.is64 && opt+108+4 <= len(data) {
		ddCount = int(binary.LittleEndian.Uint32(data[opt+108:]))
	}
	_ = ddCount

	secOff := opt + sizeOpt
	pe.sections = make([]peSection, 0, pe.numSects)
	for i := uint32(0); i < pe.numSects; i++ {
		off := secOff + int(i)*40
		if off+40 > len(data) {
			break
		}
		s := peSection{
			Name:            strings.TrimRight(string(data[off:off+8]), "\x00"),
			VirtualSize:     binary.LittleEndian.Uint32(data[off+8:]),
			VirtualAddress:  binary.LittleEndian.Uint32(data[off+12:]),
			RawSize:         binary.LittleEndian.Uint32(data[off+16:]),
			RawPtr:          binary.LittleEndian.Uint32(data[off+20:]),
			Characteristics: binary.LittleEndian.Uint32(data[off+36:]),
		}
		pe.sections = append(pe.sections, s)
	}

	// Import directory is data directory entry 1.
	if ddOff+16 <= len(data) {
		impRVA := binary.LittleEndian.Uint32(data[ddOff+8:])
		if impRVA != 0 {
			pe.parseImports(impRVA)
		}
	}

	pe.valid = true
	return pe
}

func (pe *peFile) rvaToOffset(rva uint32) (int, bool) {
	// A header RVA (below the first section) maps one-to-one.
	inAnySection := false
	for _, s := range pe.sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.RawSize {
			return int(s.RawPtr + (rva - s.VirtualAddress)), true
		}
		if rva >= s.VirtualAddress {
			inAnySection = true
		}
	}
	if !inAnySection && int(rva) < len(pe.data) {
		return int(rva), true
	}
	return 0, false
}

func (pe *peFile) parseImports(dirRVA uint32) {
	pe.importByDLL = map[string]map[string]bool{}
	pe.importAny = map[string]bool{}
	off, ok := pe.rvaToOffset(dirRVA)
	if !ok {
		return
	}
	thunkSize := 4
	if pe.is64 {
		thunkSize = 8
	}
	for i := 0; i < 4096; i++ {
		desc := off + i*20
		if desc+20 > len(pe.data) {
			return
		}
		origThunk := binary.LittleEndian.Uint32(pe.data[desc:])
		nameRVA := binary.LittleEndian.Uint32(pe.data[desc+12:])
		firstThunk := binary.LittleEndian.Uint32(pe.data[desc+16:])
		if origThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			return
		}
		dll := ""
		if no, ok := pe.rvaToOffset(nameRVA); ok {
			dll = readCString(pe.data, no)
		}
		thunkRVA := origThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}
		toff, ok := pe.rvaToOffset(thunkRVA)
		if !ok {
			continue
		}
		if dll != "" {
			if pe.importByDLL[dll] == nil {
				pe.importByDLL[dll] = map[string]bool{}
			}
		}
		for j := 0; j < 8192; j++ {
			p := toff + j*thunkSize
			if p+thunkSize > len(pe.data) {
				break
			}
			var val uint64
			if pe.is64 {
				val = binary.LittleEndian.Uint64(pe.data[p:])
			} else {
				val = uint64(binary.LittleEndian.Uint32(pe.data[p:]))
			}
			if val == 0 {
				break
			}
			ordinalFlag := uint64(1) << 31
			if pe.is64 {
				ordinalFlag = uint64(1) << 63
			}
			if val&ordinalFlag != 0 {
				pe.imports = append(pe.imports, peImport{DLL: dll, Func: ""})
				continue
			}
			no, ok := pe.rvaToOffset(uint32(val))
			if !ok {
				continue
			}
			fn := readCString(pe.data, no+2) // skip the two-byte hint
			if fn == "" {
				continue
			}
			pe.imports = append(pe.imports, peImport{DLL: dll, Func: fn})
			pe.importAny[strings.ToLower(fn)] = true
			if dll != "" {
				pe.importByDLL[strings.ToLower(dll)][strings.ToLower(fn)] = true
			}
		}
	}
}

func readCString(b []byte, off int) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
		if end-off > 512 {
			return ""
		}
	}
	return string(b[off:end])
}

// entropyOfRange returns the Shannon entropy of a byte range, in bits per byte.
func entropyOfRange(b []byte, off, size int) float64 {
	if off < 0 || size <= 0 || off >= len(b) {
		return 0
	}
	if off+size > len(b) {
		size = len(b) - off
	}
	var counts [256]int
	for _, c := range b[off : off+size] {
		counts[c]++
	}
	var h float64
	n := float64(size)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// SectionEntropy is intentionally absent: the reference implementation does not
// expose a section entropy field, and the portable way to write the rule is
// `math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size)`.
// Supporting a field libyara rejects would make the cross-validation test
// meaningless, so the gap is closed by the idiom instead.
