# Payload Obfuscation Engine (`pobf`)

A layered payload obfuscation engine written in Go, built around a YARA ruleset
so that every claim it makes about evasion is **measured, per stage, before and
after**.

You feed it a payload and an ordered list of stages. It runs the stages, reports
what each one changed (size, entropy, instruction substitutions, bytes inserted,
basic blocks flattened, rules cleared), rescans the result, and tells you the
detection rate it started with and the detection rate it ended with. Stages that
cannot process a payload say so instead of silently passing it through.

```
$ poe analyze -i testdata/shellcode.bin --seed 7 --no-diff
pipeline:  polymorph -> deadcode -> cff -> strings -> xor -> base64
  detections         4  ->        1    of 20 rules  ( 20.0% ->   5.0%)
  evasion              75.0% of the firing rules cleared
```

---

## Ethics and legal boundaries

**This is a dual-use tool. Read this before you build it.**

Payload obfuscation exists to make malicious software harder to detect, and that
is exactly what this engine does to whatever bytes you hand it. The only reason
it is defensible is *where* it is pointed.

Permitted, and the only reason this code was written:

- Analysis on payloads **you own or authored**.
- Authorised security testing under a signed contract, statement of work, or an
  in-scope bug bounty / red-team engagement, **against systems you are
  explicitly authorised to test**.
- Defensive research: building and validating detection rules against
  obfuscated samples you generated yourself, and measuring how well a detector's
  ruleset holds up.
- Education: understanding why signature-based detection is fragile, and what
  the real cost/benefit of each obfuscation layer is.

Not permitted. Using this on any of these is a crime in most jurisdictions and
is not something this project will help with:

- Deploying anything produced by this tool against a system you do not own and
  have not been authorised to test.
- Evading a security product on someone else's infrastructure.
- Distributing malware, or producing samples intended for distribution to
  parties who will do so.
- Any use where the payload's effect is not something the operator is legally
  entitled to cause.

Concretely:

- **You are responsible for the payload and the target.** The tool has no notion
  of scope, consent, or authorisation, and it will happily obfuscate anything.
  That judgement is yours, and it is not a formality.
- **The tool ships no malware.** Every fixture in `testdata/` is hand-written,
  inert, and deliberately does nothing. `shellcode.bin` sets up a frame, reads
  the PEB, runs an arithmetic loop and returns: no `syscall` instruction, no
  network code, no file writes, no process manipulation, and no technique for
  resolving or calling an API. `loader_table.bin` is a block of API *names* with
  no code at all. `syscall_stub.bin` is the one fixture containing a `syscall`,
  and it exists purely as a classifier regression test — the instruction is the
  `exit` syscall number in a routine that is never executed by anything here.
  None of the three is a payload, a stager, or a sample.
- **It is not a weaponised toolchain.** There is no payload generator, no
  loader, no persistence, no C2, no process injection, and no code that would
  turn an obfuscated blob into a running implant. It transforms bytes and
  measures detection. Assembling those bytes into something that executes in a
  victim process is entirely out of scope and is not provided.
- **This is research code, not a product.** No warranty, no support, no
  guarantee that any output will evade any particular product. See
  [Limitations](#limitations-and-non-goals); some of them are deliberate.

If you are not sure whether your intended use is authorised, it is not.

---

## What it actually does

The engine is a chain of independent stages over one `[]byte`:

```go
// Obfuscator is the contract every stage satisfies.
type Obfuscator interface {
    Name() string
    Kind() Kind
    Apply([]byte) ([]byte, error)
}
```

Each stage is self-contained and orderable. Order matters — a polymorphic
rewriter placed after an encoding stage has nothing left to disassemble — so the
benchmark explores *ordered* combinations, not sets.

Seven stages are implemented, covering the requested layers:

| Stage | Kind | Reversible | What it does |
| --- | --- | --- | --- |
| `polymorph` | polymorphic | no | Rewrites instructions into equivalent encodings from a substitution table (`xor eax,eax` → `mov eax,0`, `dec` → `sub`, NOP widening, `jcc rel8` → `jcc rel32`, …), relocating every relative operand. |
| `deadcode` | deadcode | no | Injects inert sequences at instruction boundaries: NOP sleds, save/restore flag "sandwiches", opaque predicates (`jmp` over junk), and junk `call $+5` pairs. |
| `cff` | control-flow | no | Flattens basic blocks behind a shuffled state-machine dispatcher with a position-independent jump table. |
| `strings` | strings | yes | Masks printable literals in place with per-run keys and attaches an executable rebuild stub that restores them at run time. |
| `xor` | encryption | yes | XORs with a random per-run repeating key and ships an in-place machine-code decoder stub. |
| `aes` | encryption | yes | AES-256-CBC under a PBKDF2-HMAC-SHA256 key; ships a **loader descriptor**, not machine code (see below). |
| `base64` | encoding | yes | Re-encodes over a **per-run shuffled alphabet** and ships a table-driven machine-code decoder stub. |

Every encoding and encryption stage is a *container*: a fixed 24-byte `POBF`
header, the algorithm parameters, the decoder stub, then the encoded payload.
The payload is therefore self-describing and self-extracting — nothing outside
the image is needed to reverse it, and the analysis layer exploits that to prove
the round trip.

### Recommended order

```
polymorph → deadcode → cff → strings → xor → base64
```

The instruction-level stages run first because they need to see raw,
disassemblable code; once `xor`/`base64` wrap the payload, there is nothing left
to rewrite. `cff` runs before the trailing appends of `deadcode` would sit past
a terminator and block flattening. `strings` runs before the encoding stages so
that its in-place rewrite is then hidden behind an encryption layer.

---

## Quick start

Requires Go 1.27+ (`go.mod` pins `go 1.27.2`) and, for regenerating the assembly
fixtures, `nasm`. No cgo, no libyara, no root.

```sh
# build (the toolchain is not assumed to be on PATH)
make GO=$HOME/.local/go/bin/go build        # → bin/poe
export PATH="$PWD/bin:$PATH"                # or just call ./bin/poe

# what exists?
poe stages          # stage catalogue with capability flags
poe rules           # the 20 detection rules

# measure the recommended pipeline against the shipped shellcode fixture
poe analyze -i testdata/shellcode.bin

# write an artifact and keep the report on stderr
poe obfuscate -i testdata/shellcode.bin -o out.bin

# rank every ordered pipeline up to depth 2 by measured evasion
poe benchmark -i testdata/shellcode.bin --depth 2
```

Other useful targets: `make test`, `make vet`, `make fmtcheck`, `make fixtures`,
`make demo`.

---

## Measuring, not asserting

The YARA ruleset in `internal/yara/rules/` is 20 rules in four groups, written
to describe the classes of artefact an obfuscation pipeline is supposed to move:

| Group | Rules | Examples |
| --- | --- | --- |
| Shellcode shape | 5 | classic x64 prologue (`cld; and rsp,-16; getpc call`), `call`/pop getpc, PEB access via `gs:[0x60]`, syscall stubs, NOP sleds |
| Decoder stubs | 5 | XOR decode loop, table-driven Base64 loop, literal rebuild loop, canonical Base64 alphabet literal, canonical Base64 blob |
| API strings | 6 | suspicious API name sets, AMSI/ETW names, wide (UTF-16LE) API names, process-injection primitive sets, command-interpreter strings, PowerShell flags |
| PE heuristics | 4 | high-entropy body, high-entropy executable section, injection-related imports, high-entropy blob with no PE header |

The `base64_canonical_*` rules are the interesting negative case: they fire on a
*canonical* Base64 alphabet, so the engine's per-run shuffled alphabet has to
avoid them by construction, and a test asserts that it does. A ruleset that only
ever rewards "different" is not a measurement.

Two independent engines evaluate them:

- **A pure-Go YARA-subset engine** (`internal/yara`) is the default, so
  `go build ./...` and `go test ./...` need no C toolchain. It implements the
  subset the ruleset uses, including the parts that are easy to get subtly
  wrong: hex-string negation (`~5A`), overlapping match counts, `nocase`
  regex/string handling, and `pe.*` module fields.
- **Real libyara 4.5.4** (via `yara-python` in a virtualenv) is used during
  development to cross-check the pure-Go verdicts on every rule and every blob.
  A `go-yara` adapter is available behind the `goyara` build tag so the default
  build stays cgo-free.

Detection is measured as `fired / total` before and after **each** stage, so the
report shows not only the net effect but which stage did the work — and which
stage made things *worse*, which for this class of tool is a real and expected
outcome:

```
  1   strings    strings              628      +247    5.599    6->2     0.1  cleared 5, added 1, stub=machine-code
  2   xor        encryption           757      +129    7.620    2->2     0.1  cleared 2, added 2, stub=machine-code
  3   base64     encoding            1463      +706    6.100    2->1     0.0  cleared 2, added 1, stub=machine-code
```

`added N` is not hidden: a decoder stub is itself a signature, and the ruleset
contains rules for the stubs this engine emits. The report names the newly
matching rules, and the API emits a `detection rose…` warning when a stage is a
net loss.

---

## Results

Three shipped fixtures, with `--seed 7` so the numbers are reproducible.

### Pure code: `testdata/shellcode.bin` (172 bytes)

```
pipeline:  polymorph -> deadcode -> cff -> strings -> xor -> base64
  size             172 B ->     2271 B   (+1220.3%, x13.20)
  entropy        4.450  ->    6.175    (+1.726 bits/byte)
  detections         4  ->        1    of 20 rules  ( 20.0% ->   5.0%)
  evasion              75.0% of the firing rules cleared

  1   polymorph  polymorphic          206       +34    4.463    4->3     cleared 1
  2   deadcode   deadcode             488      +282    4.840    3->3
  3   cff        control-flow        1124      +636    5.081    3->2     cleared 1
  4   strings    strings             1236      +112    5.213    2->3     added 1
  5   xor        encryption          1365      +129    7.838    3->3     cleared 3, added 3
  6   base64     encoding            2271      +906    6.175    3->1     cleared 3, added 1
```

Cleared: the shellcode prologue, the getpc idiom, the PEB access, and the NOP
sled. The one rule still firing after the pipeline is
`decoder_base64_table_lookup` — the engine's own Base64 decode loop. That is the
honest result: at 20 rules, the floor for this fixture is the decoder stub.

### Data with literals: `testdata/loader_table.bin` (381 bytes)

API names, wide API names, AMSI names and command strings, with no code at all.
The instruction-level stages correctly refuse it; the encoding half is measured
on its own with `-s strings,xor,base64`:

```
  size             381 B ->     1463 B   (+284.0%, x3.84)
  detections         6  ->        1    of 20 rules  ( 30.0% ->   5.0%)
  evasion              83.3% of the firing rules cleared
  verified    true
```

Five string rules cleared by masking the literals in place; `strings`, `xor` and
`base64` each recover cleanly, so self-extraction verification is real here.

### Code with a syscall: `testdata/syscall_stub.bin` (23 bytes)

The smallest fixture, and the one that pins a fixed bug. `syscall` used to be
classified alongside `hlt` and `ud2` as a flow terminator, so every
instruction-level stage refused any payload containing one — which is to say,
essentially every real payload. It is fallthrough, so the stages now run on it:

```
pipeline:  polymorph -> deadcode -> cff
  size              23 B ->      216 B   (+839.1%, x9.39)
  detections         1  ->        0    of 20 rules  (  5.0% ->   0.0%)
  evasion             100.0% of the firing rules cleared

  1   polymorph  polymorphic           33       +10    1->1
  2   deadcode   deadcode              58       +25    1->0   cleared 1
  3   cff        control-flow         216      +158    0->0
```

The rule cleared is `shellcode_syscall_stub` — a direct syscall immediately
followed by a return. `deadcode` inserted between the two instructions, so the
adjacency the rule describes no longer exists. That particular clear is
seed-dependent, and nothing here promises to break a given adjacency; the two
things the fixture *is* for are not. The stages run, and the `0F 05` opcode comes
out unchanged.

### Benchmark: which stages actually matter

`poe benchmark -i testdata/shellcode.bin --depth 2 --seed 7` explores 49 ordered
candidates in under a second. The result is more interesting than "more stages
is better":

```
  rank pipeline                                         detect      size  growth
  1    strings->aes                                      0.0%       237    1.38
  5    aes->deadcode                                    0.0%       251    1.46
  6    aes                                               0.0%       237    1.38
 10   cff->aes                                          0.0%       461    2.68
 12   xor                                               5.0%       301    1.75
 16   polymorph->xor                                    5.0%       335    1.95
 25   xor->base64                                       5.0%       855    4.97
  ... 24 more
```

- The structural stages (`polymorph`, `deadcode`, `cff`) plateau at **15 %**
  (3/20 rules) when used alone: they change the instruction stream but the
  payload's *shape* survives, and shape is what the rules describe.
- AES reaches **0 %** — nothing textual is left to match — at a fraction of the
  size growth of the full pipeline. Plain `xor` only gets to **5 %** (1/20):
  its machine-code decoder stub is what is left to match, and the report names
  that rule rather than rounding it away.
- The strongest combination on this fixture is not the longest one. The
  closing table in the benchmark output reports average detection and growth per
  stage, which is the question the ranking alone cannot answer.

Reproduce all of it with `make demo`.

---

## CLI

```
poe obfuscate   run a pipeline over a payload and write the obfuscated artifact
poe analyze     run a pipeline and report what it did, without keeping the artifact
poe benchmark   rank pipeline permutations by measured evasion
poe serve       run the HTTP API
poe stages      list the registered stages and their capabilities
poe rules       list the detection rules
poe version     print the version
```

Conventions:

- **Artifacts go to stdout (or `--out`); reports go to stderr**, so a shell
  pipeline captures the payload and still shows the numbers. `analyze` has no
  artifact, so its report goes to stdout.
- `--in -` reads the payload from stdin.
- `--seed 0` (the default) picks a random seed and **reports it**; passing that
  seed back reproduces the run byte-for-byte.
- `--json FILE` writes the machine-readable report (`-` for stdout). With
  `analyze`, combine it with `--quiet` so the text report does not interleave.

```sh
# capture the artifact, keep the report visible
cat payload.bin | poe obfuscate -s polymorph,deadcode,cff,strings,xor > out.bin

# reproducible: same seed + same payload + same stage list = identical bytes
poe obfuscate -i in.bin -s xor,base64 --seed 7 -o out.bin

# machine-readable, and nothing else on stdout
poe analyze -i in.bin --quiet --json - | jq '.detection_rate_after'
```

Per-stage knobs: `--rounds`, `--passphrase`, `--min-string-len`,
`--max-insertions`, `--cfp-max-blocks`, `--allow-flag-clobber`, `--no-scan`,
`--no-verify`, `--diff N`, `--no-diff`, `--verbose`.

### Report anatomy

Beyond the summary, each report contains:

- **Shannon entropy** per payload and per stage, plus peak per-chunk entropy and
  the fraction of chunks that still look structured (`structured_chunk_ratio`).
  Entropy is a *symptom* metric — it is reported, not treated as evidence of
  anything on its own.
- **Size delta** per stage and in total.
- **Substitution counts** by rule (`polymorph`) and insertion counts by snippet
  kind (`deadcode`), plus per-block detail from `cff`.
- **Detection rate** before and after each stage, with the rules that were
  cleared and the rules that were added.
- **The payload kind**, shown as `input=PE` in the stage table when a container
  stage was handed a PE, with the "this artifact is a container, decode it before
  loading it" caveat repeated in the notes.
- **Self-extraction verification**, described below.
- **A byte-level diff** (first 128 bytes by default, `--diff N`), marking which
  byte lanes changed, plus a structural diff of per-chunk entropy.

### Reproducibility and self-extraction verification

`verified: true` means the pipeline actually proved the round trip: every
reversible stage that **ran** was run **in reverse** over the final artifact and
the recovered bytes match the original input exactly.

Because the encoding stages are self-contained containers, this is a genuine
end-to-end check — the analysis layer parses the real `POBF` header and runs the
stage's own `Decode`, it does not just compare lengths. When the pipeline
contains a non-reversible stage (`polymorph`, `deadcode`, `cff` are
semantics-preserving rewrites and have no inverse), when a reversible stage
declined the payload so there is no decoder in the stream to invert, or when no
reversible stage ran at all, `verified` is `false` and the notes explain
precisely why:

```
notes
  - base64: decoded via embedded stub
  - xor: decoded via embedded stub
  - strings: decoded via embedded stub
  - cff: not invertible (semantics-preserving transform)
  - self-extraction recovered 1124 bytes, input was 172
```

The engine refuses to report a vacuous "verified" on a pipeline that never
encoded anything.

---

## HTTP API

```sh
poe serve --addr 127.0.0.1:8080
```

Defaults to loopback on purpose. Endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | liveness plus the size of the stage and rule sets |
| `GET` | `/v1/stages` | stage catalogue with capability flags |
| `GET` | `/v1/rules` | the detection ruleset |
| `POST` | `/v1/obfuscate` | run a pipeline, return the artifact and the report |
| `POST` | `/v1/analyze` | run a pipeline, return the report only |
| `POST` | `/v1/benchmark` | rank permutations by measured evasion |

The three `POST` endpoints accept the payload in three shapes, all equivalent:

```sh
# 1. multipart: file part + JSON config
curl -F payload=@testdata/shellcode.bin \
     -F 'config={"stages":["polymorph","deadcode","cff","strings","xor","base64"],"seed":7}' \
     http://127.0.0.1:8080/v1/obfuscate

# 2. JSON with the payload inline
curl -H 'Content-Type: application/json' \
     -d "{\"payload_base64\":\"$(base64 -w0 testdata/loader_table.bin)\",\"stages\":[\"strings\",\"xor\",\"base64\"],\"seed\":7}" \
     http://127.0.0.1:8080/v1/analyze

# 3. raw body, configuration in the query string (query wins over config)
curl --data-binary @testdata/loader_table.bin \
     'http://127.0.0.1:8080/v1/obfuscate?stages=strings,xor,base64&seed=7'
```

`obfuscate` and `analyze` return the same envelope — the payload is under
`payload_base64` for `obfuscate` and omitted for `analyze`:

```json
{
  "label": "shellcode",
  "pipeline": ["polymorph", "deadcode", "cff", "strings", "xor", "base64"],
  "rounds": 1,
  "seed": 7,
  "input_size": 172,
  "input_sha256": "…",
  "output_size": 2271,
  "output_sha256": "…",
  "payload_base64": "…",
  "report": { "detection_rate_before": 0.2, "detection_rate_after": 0.05, "steps": [ … ] },
  "rendered": "payload:   shellcode\n…",
  "warnings": ["payload grew 13.2x (172 to 2271 bytes)",
               "rules newly matching: decoder_literal_rebuild_loop, …"]
}
```

So the metric lives under `report`:

```sh
curl -s --data-binary @testdata/loader_table.bin \
     'http://127.0.0.1:8080/v1/analyze?stages=strings,xor,base64&seed=7' \
  | jq '.report.detection_rate_after'
# 0.05
```

`benchmark` returns `{pool, depth, candidates, ranked[], rendered}`, where each
entry carries `stages`, `detection_rate`, `size_bytes`, `growth` and `ms`.

Operational behaviour is deliberate rather than generic:

- **Payload limit** (default 16 MiB) → `413`.
- **Too many concurrent runs** (default 4) → `429` with `Retry-After`. It
  refuses rather than queues, because an obfuscation run is CPU-bound and a
  queue only converts load into latency.
- **Oversized benchmark** → `400` "narrow the request", with the candidate limit
  in the message.
- **Unknown stage, bad round count, malformed config** → `400` naming the
  offending field.
- **`405` with an `Allow` header** on a known path with the wrong method, and
  `404` elsewhere.

The integration tests in `internal/api` assert the headline property directly:
upload a fixture, obfuscate it, **independently rescan the returned artifact**
with the same ruleset, and require the detection rate to land at or below 10 %.

---

## What is executable, and what is a descriptor

Not every "decoder stub" is machine code, and the tool does not pretend
otherwise. Each stage reports `stub_kind`:

- **`machine-code`** — `xor`, `base64`, `strings`. Execution starts at real
  x86-64 (per the header's `EntryOffset`) that performs the decode when run.
  These stubs are validated by *executing* them, not by reading them: the test
  suite maps the stub into memory with `PROT_EXEC`, calls it through a Go
  assembly trampoline, and checks the recovered bytes against the input.
- **`loader-descriptor`** — `aes`. AES-256-CBC with PBKDF2 key derivation cannot
  be expressed in a few hundred bytes of hand-written machine code, so this
  stage ships a **parameter block** (algorithm, key material, IV, lengths) and
  the decode is performed by `internal/encode`'s `Decode` or by a loader that
  understands the header. The bytes are genuinely encrypted, and the round trip
  is genuinely verified — but there is no AES decryption routine embedded in the
  output, and you should not expect the artifact to decrypt itself on a bare
  CPU. `stub_kind` is in the JSON report so this is never a surprise.

The container layout is uniform across all four:

```
[ 24-byte POBF header ][ algorithm parameters ][ decoder stub ][ encoded payload ]
```

with `EntryOffset` saying where execution starts and `DataOffset`/`PayloadLen`
saying what to decode. A stub reads its parameters through RIP-relative
references at negative offsets from its own entry point, which is what keeps the
image position-independent.

---

## Limitations and non-goals

These are known, deliberate, and documented rather than hidden.

- **`strings` masks in place, so a PE input comes back as a container.** It
  rewrites printable runs where they are and prepends a rebuild stub that
  restores them. The masked bytes are recoverable exactly — `DecodeStringImage`
  is checked byte for byte against the original on a PE fixture — so a PE is a
  supported input. But the artifact is **not** a PE: the Windows loader reads the
  import table and the data directories before any stub of ours could run, so the
  artifact has to be decoded back to the original image before it is loaded or
  mapped, and it must never be entered at its start. The report states this
  explicitly when the input is a PE (the stage table shows `input=PE` and the
  notes spell out the requirement), because a bare `verified: true` printed next
  to a file nobody can load is a lie by omission.
- **Instruction-level stages refuse PE files.** `polymorph`, `deadcode` and
  `cff` require pure, decodable code with resolvable branch targets and no
  embedded data. A linked PE hits its first data region within a few hundred
  bytes and is refused with a precise reason (`undecodable byte at offset 0xc0
  (data regions cannot be relocated)`). The `deadcode` stage degrades to an
  append-only insertion past the last section when the payload is not
  relocatable, which is load-safe by construction. Making these stages PE-aware
  is a real piece of work — a recursive-descent CFG so data inside `.text` is
  never touched, plus a section/data-directory rewrite — and it is not attempted
  here rather than attempted badly.
- **`SYSCALL` and `SYSENTER` are rewritten; the rest of the trap family is not.**
  `syscall` enters the kernel and returns to the *following* instruction, so
  control flow continues linearly and everything after it stays relocatable.
  Classifying it as a terminator was a bug: it made every instruction-level stage
  refuse any payload containing a syscall, which is to say essentially every real
  payload. `testdata/syscall_stub.asm` is a 23-byte fixture that exists to keep
  that fixed, and the test suite checks that all three code stages run on it and
  that the `0F 05` opcode comes out unchanged. Instructions that genuinely leave
  the module — `sysret`, `sysexit`, `hlt`, `ud2`, `int`, `int3` — are still
  treated as terminators and still refuse the payload, conservatively: they
  transfer control to a handler or a saved RIP that a static CFG cannot see.
- **Short branches are a hard constraint.** Inserting bytes between a `jcc rel8`
  and its target eventually overflows the 8-bit displacement, and the encoder
  cannot widen the branch in place (that would move the target's bytes by two,
  which is the layout being computed). Every byte-adding stage therefore spends
  a `BranchBudget` first: it computes, per instruction boundary, how much room
  each rel8 branch still has, and skips sites it cannot afford. A displacement
  overflow is treated as a refusal (a logged skip), never as a truncated
  artifact.
- **`deadcode` and `polymorph` are semantics-preserving, not semantics-proved.**
  The dead-code planner only emits sequences that restore any flags they touch,
  and the substitution table is gated on EFLAGS liveness (`--allow-flag-clobber`
  exists for when you have judged that the flag dependency does not matter to
  your payload): the engine will not apply a substitution that changes flags
  while the following instruction reads them. It does not attempt to prove
  semantic equivalence in general, and it does not model self-modifying code.
- **CFF requires a well-behaved shape**: pure position-independent code,
  resolvable control flow, no RIP-relative operands, and a terminator at the
  end. It refuses anything else with a reason.
- **Detection rates are against *this* ruleset.** 20 hand-written rules are a
  measuring stick, not a model of any commercial product. "0 % detection" here
  means "nothing in these 20 rules matched", and the benchmark table is honest
  about the fact that the structural stages never reach it.
- **Entropy is not evasion.** A high entropy number is a consequence of
  encryption, and is just as easily a detection signal as an evasion one. The
  report shows entropy because you asked it to; the detection measurement is the
  part that means something.
- **Not provided, by design**: no loader, no injection, no persistence, no
  sandbox-aware behaviour, no syscall/API resolution, no anti-debug of any kind,
  and no payload generation. The engine transforms bytes and measures the
  result.

---

## How it is verified

`make test` runs the whole suite. The parts worth knowing about:

- **Native execution of every stub.** `internal/x86/native` builds an
  mmap'd `PROT_EXEC` region and calls into it through hand-written Go assembly
  trampolines (`Call4`/`Call5`/`Call6`). The XOR, Base64 and literal-rebuild
  stubs, the inserted dead-code snippets, and the metamorphic substitutions are
  all checked by *running* them and comparing results, not by pattern-matching
  the bytes. (The Go ABI reserves `R14` for the `g` pointer; snippets that grow
  the stack use a shared `GrowStack` trampoline.)
- **Semantic equivalence fixtures.** `internal/x86/testdata/prog{1,2}.asm`
  compute real values and are deliberately built from the instruction shapes the
  substitution table targets. Objdump and executed-register comparisons run
  before and after each transform.
- **Short-branch budget tests.** A synthetic payload with a nearly-full `rel8`
  backward branch is pushed through `polymorph` and `deadcode` across hundreds of
  seeds; the output must stay decodable and relocatable, the budget must report
  sites it refused, and total growth inside the branch must not exceed its
  slack. This is a regression test for a real bug: insertion used to overflow the
  displacement and abort the whole pass.
- **A syscall regression test.** `TestSyscallIsFallthroughNotATrap` pins the
  classification of `SYSCALL`, checks that `sysret`/`hlt`/`ud2` still refuse, and
  pushes a syscall-bearing payload through all three code stages asserting the
  `0F 05` opcode survives. The end-to-end fixture test reruns the same payload
  through the real pipeline.
- **A "what did I just produce" test.** `TestReportsThatAPEInputProducesAContainer`
  runs a PE through `strings,base64`, then decodes the artefact back with the
  public `encode` API and compares it to the original byte for byte, and asserts
  the report carries the container caveat. The point is that the warning and the
  byte-exact recovery are checked together: the tool is allowed to wrap a PE, but
  only while being explicit that the result is not one.
- **Vacuous-verification tests.** A pipeline that emitted no decoder, and a
  pipeline whose only reversible stage declined the payload, must both report
  `verified: false` with an explanatory note rather than dressing a byte-identical
  pass-through up as a proof.
- **Cross-validation against real libyara.** Every rule and a set of synthetic
  blobs are evaluated by both the pure-Go engine and libyara 4.5.4; the verdicts
  must agree. The reference side is driven through `yara-python`, and the test
  **skips** (rather than fails) when no interpreter with the `yara` module is
  available, so the suite stays runnable on a machine with no libyara. Point
  `POE_LIBYARA_PYTHON` at such an interpreter to enable it. The rules are written
  in the subset the two agree on by construction, and the divergences that are
  easy to get wrong are pinned by tests: `\` is division (not an escape), `~5A`
  negates a hex byte, string/regex/hex matching counts *overlapping* occurrences,
  hex matchers take the first grammar-order end, `pe.entry_point` is a raw file
  offset, `pe.is_64bit()` needs its parentheses, and `pe.imports` is
  two-argument-only.
- **End-to-end fixture test.** The shipped payloads are pushed through their
  real pipelines and the resulting artifact is rescanned independently; the
  detection rate must fall below 10 %, the stages that are supposed to run must
  run, and the stages that are supposed to refuse must refuse.
- **HTTP integration tests.** 19 tests covering the detection-threshold proof,
  byte-for-byte reproducibility, request-shape equivalence, error paths, and
  429 backpressure.

```
$ make test
ok  pobf/internal/analysis   10.76s
ok  pobf/internal/api         5.11s
ok  pobf/internal/encode      0.01s
ok  pobf/internal/x86         0.51s
ok  pobf/internal/yara        2.15s
```

---

## Repository layout

```
cmd/poe/            CLI: obfuscate, analyze, benchmark, serve, stages, rules
internal/pipeline/  Obfuscator interface, stage registry, run context, DecodeAll
internal/stages/    the seven stages, registered by name
internal/x86/       disassembler, metamorphic table, dead-code planner, CFF,
                    branch budget, and the emitted decoder stubs
internal/x86/native mmap/PROT_EXEC region + assembly trampolines for stub tests
internal/encode/    the POBF container, XOR/AES/Base64/Strings codecs and Decode
internal/entropy/   Shannon entropy, chunking, chi-square
internal/yara/      pure-Go YARA-subset engine, and the 20 rules in rules/
internal/analysis/  per-stage measurement, report rendering, benchmarking
internal/api/       net/http server, request shapes, limits, integration tests
internal/testpe/    a hand-built PE32+ fixture for the structural rules
internal/rng/       labelled, seed-derived random streams
testdata/           hand-written inert fixtures (.asm + assembled .bin)
Makefile            build, test, vet, fmtcheck, fixtures, demo
```

The random stream is derived per stage from a single seed with a label
(`stage/xor`, `stage/cff`, …), so changing one stage's consumption does not
disturb another's, and a run is reproducible from the seed printed in its report.

---

## License

MIT — see [LICENSE](LICENSE).

The license grants the legal right to use this code. It does not grant the right
to point it at a system you are not authorised to test. Those are different
questions, and the first section of this document is the answer to the second.

