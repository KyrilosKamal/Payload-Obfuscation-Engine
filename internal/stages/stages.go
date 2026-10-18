// Package stages binds the low-level transforms (internal/x86, internal/encode)
// to the pipeline's Stage interface and registers them by name.
//
// Every stage follows the same contract:
//
//   - Apply is pure: it never mutates its input and may be called repeatedly.
//   - Details reports structured metadata about the most recent Apply, which is
//     what the analysis layer renders into the report.
//   - A stage that cannot legally touch a payload (a data blob offered to the
//     instruction rewriter, say) reports that as a skip via ErrSkipped rather
//     than failing the run. Refusing is a correct outcome; corrupting the
//     payload is not.
package stages

import (
	"errors"
	"fmt"

	"pobf/internal/encode"
	"pobf/internal/entropy"
	"pobf/internal/pipeline"
	"pobf/internal/x86"
)

// ErrSkipped wraps the reason a stage declined to transform a payload. The
// pipeline records the skip and continues; it does not treat it as a failure.
type ErrSkipped struct{ Reason string }

func (e *ErrSkipped) Error() string { return "skipped: " + e.Reason }

// skip converts a "this payload cannot be rewritten" error into a skip. A stage
// that refuses is a normal outcome on data-shaped input, and reporting it is the
// point of the exercise; a stage that fails is not.
func skip(err error) error {
	var nre *x86.NotRewritableError
	if errors.As(err, &nre) {
		return &ErrSkipped{Reason: nre.Reason}
	}
	// A displacement overflow is also a refusal: the payload has a branch shape
	// the layout planner could not accommodate, and emitting it anyway would
	// produce a stream that no longer works.
	var de *x86.DisplacementError
	if errors.As(err, &de) {
		return &ErrSkipped{Reason: "refusing to emit: " + de.Error()}
	}
	return err
}

// entropyOf is a small readability helper used in Details payloads.
func entropyOf(b []byte) float64 { return entropy.Shannon(b) }

// containerDetails assembles the report payload for a container stage.
//
// It exists because the four container stages disagree about PE input in a way
// the operator has to be told about: xor, aes and base64 round-trip a PE byte
// for byte and are perfectly reasonable things to do to one, but the artefact is
// then a container that must be decoded, not a loadable file. Leaving that to be
// inferred is how a tool ends up reporting "verified" on something nobody can
// run, so the payload kind is named explicitly.
func containerDetails(in []byte, img *encode.Image, extra map[string]any) map[string]any {
	kind, note := encode.ClassifyInput(in)
	notes := append([]string(nil), img.Notes...)
	if note != "" {
		notes = append(notes, note)
	}
	out := map[string]any{
		"payload_kind":  string(kind),
		"stub_kind":     string(img.Kind),
		"stub_size":     img.Container.DataOffset - img.Container.EntryOffset,
		"entropy_after": entropyOf(img.Bytes),
		"notes":         notes,
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func init() {
	pipeline.Register("base64", newBase64)
	pipeline.Register("xor", newXOR)
	pipeline.Register("aes", newAES)
	pipeline.Register("polymorph", newPolymorph)
	pipeline.Register("deadcode", newDeadCode)
	pipeline.Register("strings", newStrings)
	pipeline.Register("cff", newCFF)
}

// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

type base64Stage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newBase64(ctx *pipeline.Context) (pipeline.Stage, error) { return &base64Stage{ctx: ctx}, nil }

func (s *base64Stage) Name() string        { return "base64" }
func (s *base64Stage) Kind() pipeline.Kind { return pipeline.KindEncoding }
func (s *base64Stage) Description() string {
	return "re-encode the payload as Base64 over a per-run shuffled alphabet, with an in-place machine-code decoder stub"
}

func (s *base64Stage) Apply(in []byte) ([]byte, error) {
	s.last = nil
	opts := encode.DefaultBase64Options()
	img, info, err := encode.BuildBase64Image(in, s.ctx.Derive("stage/base64"), opts)
	if err != nil {
		return nil, err
	}
	s.last = containerDetails(in, img, map[string]any{
		"alphabet":     info.Alphabet,
		"pad":          info.Pad,
		"groups":       info.Groups,
		"padded_bytes": info.PaddedBytes,
		"params_size":  len(img.Container.Params),
	})
	return img.Bytes, nil
}

func (s *base64Stage) Details() map[string]any { return s.last }

// Applied reports whether the most recent Apply produced an image. The
// verification step uses it so a stage that declined the payload is not
// asked to invert a transform it never performed.
func (s *base64Stage) Applied() bool { return s.last != nil }

func (s *base64Stage) Decode(in []byte) ([]byte, error) { return encode.DecodeBase64Image(in) }

// ---------------------------------------------------------------------------
// xor
// ---------------------------------------------------------------------------

type xorStage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newXOR(ctx *pipeline.Context) (pipeline.Stage, error) { return &xorStage{ctx: ctx}, nil }

func (s *xorStage) Name() string        { return "xor" }
func (s *xorStage) Kind() pipeline.Kind { return pipeline.KindEncryption }
func (s *xorStage) Description() string {
	return "XOR the payload with a random repeating key (optionally chained) and attach an in-place machine-code decoder stub"
}

func (s *xorStage) Apply(in []byte) ([]byte, error) {
	s.last = nil
	opts := encode.DefaultXOROptions()
	img, info, err := encode.BuildXORImage(in, s.ctx.Derive("stage/xor"), opts)
	if err != nil {
		return nil, err
	}
	s.last = containerDetails(in, img, map[string]any{
		"key_len":      info.KeyLen,
		"key_check":    encode.KeyCheck(string(info.Key)),
		"chained":      info.Chained,
		"jump_to_tail": info.SelfTerm,
		"params_size":  len(img.Container.Params),
	})
	return img.Bytes, nil
}

func (s *xorStage) Details() map[string]any { return s.last }

// Applied reports whether the most recent Apply produced an image. The
// verification step uses it so a stage that declined the payload is not
// asked to invert a transform it never performed.
func (s *xorStage) Applied() bool { return s.last != nil }

func (s *xorStage) Decode(in []byte) ([]byte, error) { return encode.DecodeXORImage(in) }

// ---------------------------------------------------------------------------
// aes
// ---------------------------------------------------------------------------

type aesStage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newAES(ctx *pipeline.Context) (pipeline.Stage, error) { return &aesStage{ctx: ctx}, nil }

func (s *aesStage) Name() string        { return "aes" }
func (s *aesStage) Kind() pipeline.Kind { return pipeline.KindEncryption }
func (s *aesStage) Description() string {
	return "encrypt the payload with AES-256-CBC under a PBKDF2-HMAC-SHA256 passphrase; ships a loader descriptor (not machine code)"
}

func (s *aesStage) Apply(in []byte) ([]byte, error) {
	s.last = nil
	opts := encode.DefaultAESOptions()
	if s.ctx.Options.Passphrase != "" {
		opts.Passphrase = s.ctx.Options.Passphrase
	}
	img, info, err := encode.BuildAESImage(in, s.ctx.Derive("stage/aes"), opts, opts.Passphrase)
	if err != nil {
		return nil, err
	}
	s.last = containerDetails(in, img, map[string]any{
		"passphrase":    info.Passphrase,
		"passphrase_id": encode.KeyCheck(info.Passphrase),
		"iterations":    info.Iterations,
		"key_bits":      info.KeyBits,
		"salt":          info.Salt,
		"iv":            info.IV,
		"params_size":   len(img.Container.Params),
	})
	return img.Bytes, nil
}

func (s *aesStage) Details() map[string]any { return s.last }

// Applied reports whether the most recent Apply produced an image. The
// verification step uses it so a stage that declined the payload is not
// asked to invert a transform it never performed.
func (s *aesStage) Applied() bool { return s.last != nil }

// Decode undoes the stage using the passphrase recorded by the most recent
// Apply.
//
// This is the honest shape of the AES stage: the payload does not contain the
// key, so the *engine* can invert its own transform while an observer holding
// only the bytes cannot. The pipeline's self-extraction check therefore reports
// AES as "decoded with run-held key material" rather than pretending the image
// is self-contained.
func (s *aesStage) Decode(in []byte) ([]byte, error) {
	if s.last == nil {
		return nil, fmt.Errorf("%w: Apply has not run", errDecodeNeedsKey)
	}
	pass, _ := s.last["passphrase"].(string)
	if pass == "" {
		return nil, fmt.Errorf("%w: no passphrase recorded", errDecodeNeedsKey)
	}
	return encode.DecodeAESImage(in, pass)
}

// errDecodeNeedsKey marks the one stage whose decode cannot be driven by the
// image alone; the analysis layer reports it as "requires key material" instead
// of as a failure.
var errDecodeNeedsKey = errors.New("AES decode requires the passphrase")

// ---------------------------------------------------------------------------
// string obfuscation
// ---------------------------------------------------------------------------

type stringStage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newStrings(ctx *pipeline.Context) (pipeline.Stage, error) { return &stringStage{ctx: ctx}, nil }

func (s *stringStage) Name() string        { return "strings" }
func (s *stringStage) Kind() pipeline.Kind { return pipeline.KindStrings }
func (s *stringStage) Description() string {
	return "mask printable literals in place with per-run keys and attach an executable rebuild stub"
}

func (s *stringStage) Apply(in []byte) ([]byte, error) {
	s.last = nil
	opts := encode.DefaultStringOptions()
	if s.ctx.Options.MinStringLen > 0 {
		opts.MinLength = s.ctx.Options.MinStringLen
	}
	img, info, err := encode.BuildStringImage(in, s.ctx.Derive("stage/strings"), opts)
	if err != nil {
		// "Nothing printable to mask" is a legitimate outcome for a payload with
		// no literals, not a failure.
		return nil, &ErrSkipped{Reason: err.Error()}
	}
	var masked []string
	for _, run := range info.Runs {
		masked = append(masked, run.Text)
	}
	s.last = containerDetails(in, img, map[string]any{
		"runs":           len(info.Runs),
		"masked_bytes":   info.MaskedBytes,
		"total_literals": info.TotalLiterals,
		"min_length":     info.MinLength,
		"literals":       masked,
	})
	return img.Bytes, nil
}

func (s *stringStage) Details() map[string]any { return s.last }

// Applied reports whether the most recent Apply produced an image. The
// verification step uses it so a stage that declined the payload is not
// asked to invert a transform it never performed.
func (s *stringStage) Applied() bool { return s.last != nil }

func (s *stringStage) Decode(in []byte) ([]byte, error) { return encode.DecodeStringImage(in) }

// ---------------------------------------------------------------------------
// polymorphic rewriting
// ---------------------------------------------------------------------------

type polymorphStage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newPolymorph(ctx *pipeline.Context) (pipeline.Stage, error) {
	return &polymorphStage{ctx: ctx}, nil
}

func (s *polymorphStage) Name() string        { return "polymorph" }
func (s *polymorphStage) Kind() pipeline.Kind { return pipeline.KindPolymorphic }
func (s *polymorphStage) Description() string {
	return "rewrite instructions into equivalent encodings drawn from a substitution table, relocating all relative operands"
}

func (s *polymorphStage) Apply(in []byte) ([]byte, error) {
	opts := x86.DefaultPolymorphicOptions()
	opts.AllowFlagClobber = s.ctx.Options.AllowFlagClobber
	out, log, _, err := x86.Rewrite(in, s.ctx.Derive("stage/polymorph"), opts)
	if err != nil {
		return nil, skip(err)
	}
	byRule := map[string]int{}
	for _, m := range log {
		byRule[m.Rule]++
	}
	s.last = map[string]any{
		"substitutions": len(log),
		"by_rule":       byRule,
		"rules_used":    len(byRule),
		"size_delta":    len(out) - len(in),
		"entropy_after": entropyOf(out),
	}
	return out, nil
}

func (s *polymorphStage) Details() map[string]any { return s.last }

// ---------------------------------------------------------------------------
// dead code
// ---------------------------------------------------------------------------

type deadCodeStage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newDeadCode(ctx *pipeline.Context) (pipeline.Stage, error) { return &deadCodeStage{ctx: ctx}, nil }

func (s *deadCodeStage) Name() string        { return "deadcode" }
func (s *deadCodeStage) Kind() pipeline.Kind { return pipeline.KindDeadCode }
func (s *deadCodeStage) Description() string {
	return "inject inert instruction sequences (NOP sleds, flag sandwiches, opaque predicates, junk calls) at instruction boundaries"
}

func (s *deadCodeStage) Apply(in []byte) ([]byte, error) {
	opts := x86.DefaultDeadCodeOptions()
	// Trailing injection keeps the stage useful on payloads whose control flow
	// cannot be resolved statically, which is the common case for anything a
	// previous stage has already encoded.
	opts.Trailing = true
	if s.ctx.Options.MaxInsertions > 0 {
		opts.MaxInsertions = s.ctx.Options.MaxInsertions
	}
	out, stats, err := x86.DeadCode(in, s.ctx.Derive("stage/deadcode"), opts)
	if err != nil {
		return nil, skip(err)
	}
	s.last = map[string]any{
		"insertions":    stats.Insertions,
		"bytes_added":   stats.BytesAdded,
		"by_kind":       stats.ByKind,
		"append_only":   stats.AppendOnly,
		"reason":        stats.Reason,
		"sites":         stats.Sites,
		"entropy_after": entropyOf(out),
	}
	return out, nil
}

func (s *deadCodeStage) Details() map[string]any { return s.last }

// ---------------------------------------------------------------------------
// control-flow flattening
// ---------------------------------------------------------------------------

type cffStage struct {
	ctx  *pipeline.Context
	last map[string]any
}

func newCFF(ctx *pipeline.Context) (pipeline.Stage, error) { return &cffStage{ctx: ctx}, nil }

func (s *cffStage) Name() string        { return "cff" }
func (s *cffStage) Kind() pipeline.Kind { return pipeline.KindControlFlow }
func (s *cffStage) Description() string {
	return "flatten basic blocks behind a shuffled state-machine dispatcher with a position-independent jump table"
}

func (s *cffStage) Apply(in []byte) ([]byte, error) {
	opts := x86.DefaultCFFOptions()
	opts.MaxBlocks = s.ctx.Options.CFPMaxBlocks
	out, res, err := x86.Flatten(in, s.ctx.Derive("stage/cff"), opts)
	if err != nil {
		return nil, skip(err)
	}
	s.last = map[string]any{
		"blocks":        res.Blocks,
		"states":        res.States,
		"entry_state":   res.EntryState,
		"dispatch_size": res.DispatchSize,
		"code_size":     res.CodeSize,
		"block_order":   res.Order,
		"size_delta":    len(out) - len(in),
		"entropy_after": entropyOf(out),
	}
	return out, nil
}

func (s *cffStage) Details() map[string]any { return s.last }
