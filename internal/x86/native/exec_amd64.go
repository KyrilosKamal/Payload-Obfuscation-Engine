// Package native executes generated machine code so the obfuscation stages can
// be validated by behaviour rather than by inspection.
//
// Allocating writable+executable memory and jumping into it is exactly what a
// loader or an exploit does, so it is also the only honest way to test a
// decoder stub: either the stub decodes the payload or it does not.
//
// This package is deliberately limited to linux/amd64 and is used by tests and
// by the `poe exec` developer subcommand. Nothing in the obfuscation pipeline
// requires it.
package native

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Call4 invokes the machine code at f with the System V argument registers
// (rdi, rsi, rdx, rcx). It is implemented in exec_amd64.s.
//
// The callee must not clobber R14 (the Go runtime reserves it for the g
// pointer), must preserve RBX/RBP/R12-R15, and must not touch the FPU control
// state. Every stub this project generates satisfies those constraints, and
// TestSnippetsPreserveState verifies it.
//
//go:noescape
func Call4(f, a, b, n, k uintptr)

// Call5 is Call4 but returns the callee's RAX, which is how the tests read a
// payload's return value.
//
//go:noescape
func Call5(f, a, b, n, k uintptr) uintptr

// Call6 is Call5 with a fifth argument passed in R8, for the chunked decoder.
//
//go:noescape
func Call6(f, a, b, n, k, e uintptr) uintptr

// Region is a mapping of executable memory.
type Region struct {
	mem  []byte
	size int
}

// NewRegion copies code into a fresh executable mapping.
func NewRegion(code []byte) (*Region, error) {
	if len(code) == 0 {
		return nil, fmt.Errorf("native: empty code")
	}
	page := os.Getpagesize()
	size := (len(code) + page - 1) / page * page
	mem, err := syscall.Mmap(-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("native: mmap executable memory: %w", err)
	}
	copy(mem, code)
	return &Region{mem: mem, size: size}, nil
}

// Base returns the address of the first byte of the region.
func (r *Region) Base() uintptr { return uintptr(unsafe.Pointer(&r.mem[0])) }

// Bytes returns the region's memory, so a test can inspect what the code wrote.
func (r *Region) Bytes() []byte { return r.mem }

// Call invokes the region's entry point with the given arguments.
func (r *Region) Call(a, b, n, k uintptr) { Call4(r.Base(), a, b, n, k) }

// CallRet invokes the region's entry point and returns RAX.
func (r *Region) CallRet(a, b, n, k uintptr) uintptr { return Call5(r.Base(), a, b, n, k) }

// Call6 invokes the region's entry point with five arguments and returns RAX.
func (r *Region) Call6(a, b, n, k, e uintptr) uintptr { return Call6(r.Base(), a, b, n, k, e) }

// Free releases the mapping.
func (r *Region) Free() error {
	if r.mem == nil {
		return nil
	}
	err := syscall.Munmap(r.mem)
	r.mem = nil
	return err
}

// GrowStack forces the current goroutine's stack to grow before native code is
// called.
//
// Generated snippets push below RSP. Go's runtime can grow a stack only out of a
// prologue it generated, so a push that walks past the end of a small goroutine
// stack would fault on the guard page. Test functions run on the main goroutine
// (a multi-megabyte OS stack), but making the frame explicitly large keeps the
// harness safe if that ever changes.
//
//go:noinline
func GrowStack() {
	var pad [64 * 1024]byte
	pad[0] = 1
	pad[len(pad)-1] = 2
	stackSink ^= pad[0] ^ pad[len(pad)-1]
}

var stackSink byte
