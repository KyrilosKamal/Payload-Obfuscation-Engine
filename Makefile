# Payload Obfuscation Engine (pobf)
#
# The toolchain is not assumed to be on PATH. If `go` is installed somewhere
# else, point the build at it without touching this file:
#
#     make GO=$HOME/.local/go/bin/go
#
# Everything else (nasm for the fixtures) is a normal build dependency.

GO   ?= go
BIN  ?= bin/poe
NASM ?= nasm

# Assembly fixtures are the source of truth; the .bin files are generated.
FIXTURE_SRC := internal/x86/testdata/prog1.asm \
               internal/x86/testdata/prog2.asm \
               testdata/shellcode.asm \
               testdata/syscall_stub.asm \
               testdata/loader_table.asm
FIXTURE_BIN := $(FIXTURE_SRC:.asm=.bin)

# Any Go source change invalidates the binary. `find` keeps this honest without
# listing every file by hand; all of its output is relative, so a working
# directory containing spaces is fine.
GO_SRC := $(shell find . -name '*.go' -not -path './bin/*')

.PHONY: all build test vet fmt fmtcheck fixtures demo analyze benchmark clean help

all: build

## build: compile the CLI to bin/poe
build: $(BIN)

$(BIN): $(GO_SRC) go.mod go.sum
	@mkdir -p $(dir $(BIN))
	$(GO) build -o $(BIN) ./cmd/poe

## test: run the full test suite, including the native stub execution tests
test:
	$(GO) test ./...

## vet: run the standard static checks
vet:
	$(GO) vet ./...

## fmt: format every Go file in place
fmt:
	gofmt -w .

## fmtcheck: fail if any file is not gofmt-clean
fmtcheck:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

## fixtures: reassemble every committed payload fixture from its .asm source
fixtures: $(FIXTURE_BIN)

%.bin: %.asm
	$(NASM) -f bin -o $@ $<

## demo: the commands the README quotes, with a fixed seed so the numbers match
demo: build
	@echo '--- catalogue ---------------------------------------------------------'
	@$(BIN) stages
	@echo
	@echo '--- shellcode.bin: the whole recommended pipeline ----------------------'
	@$(BIN) analyze -i testdata/shellcode.bin --seed 7 --no-diff
	@echo
	@echo '--- loader_table.bin: the encoding half, on data with literals ---------'
	@$(BIN) analyze -i testdata/loader_table.bin -s strings,xor,base64 --seed 7 --no-diff
	@echo
	@echo '--- syscall_stub.bin: the code stages run on a payload with a syscall --'
	@$(BIN) analyze -i testdata/syscall_stub.bin -s polymorph,deadcode,cff --seed 7 --no-diff

## analyze: measure the recommended pipeline against the shipped shellcode fixture
analyze: build
	@$(BIN) analyze -i testdata/shellcode.bin

## benchmark: rank every pipeline permutation up to depth 2
benchmark: build
	@$(BIN) benchmark -i testdata/shellcode.bin --depth 2 --seed 7

## clean: remove build output
clean:
	rm -rf bin

## help: list the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
