// Package tee is the execution core of a TokenHive enclave: it takes a job,
// decides whether the provider's policy permits it, performs the request with
// the shared credential, and returns a signed receipt describing what happened.
//
// The package owns no network code. Outbound HTTP lives behind the Transport
// interface so that the parts of the system with security meaning — ordering
// of checks, credential isolation, response attestation — can be reasoned
// about and tested without a socket.
//
// # The order of checks
//
// Execute runs its checks in a fixed order, and the order is the design:
//
//  1. submitter identity (optional, see Config.SubmitterVerifier)
//  2. spec structure and expiry
//  3. body binding — the body must hash to the spec's committed digest
//  4. policy authorisation
//  5. body size against the policy cap
//  6. credential resolution
//  7. sequence allocation (see Config.Seq)
//
// Steps 2 and 3 establish that the job is internally consistent; only then is
// it meaningful to ask whether it is permitted. Authorising a request whose
// body does not match its own description would spend a credential on a
// question nobody asked.
//
// Step 7 is last because it is the only step that mutates state. Every check
// that can refuse a job runs first, so a refused job never consumes a sequence
// number and never leaves a hole in the provider's series.
//
// # When a receipt exists
//
// A receipt is produced if and only if the request was actually put on the
// wire. Jobs refused earlier — malformed, unauthorised, or lacking a
// credential — return an error and no receipt, because there is nothing to
// attest to and handing out a signature would only say "an enclave saw this",
// which helps nobody.
//
// Once a request is sent, every outcome is signed, including failure. A
// receipt that says CompletionFailed is the proof the Hub needs in order not
// to charge for a response that never arrived; without it, a dropped stream
// and a successful one would be indistinguishable to the verifier.
package tee

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Configuration errors, all of which mean the service was built wrong rather
// than that a job was bad.
var (
	ErrNoPolicySet     = errors.New("no policy set configured")
	ErrNoCredentials   = errors.New("no credential source configured")
	ErrNoSigner        = errors.New("no receipt signer configured")
	ErrCredentialClash = errors.New("job already sets the header the credential occupies")
	ErrBodyTooLarge    = errors.New("request body exceeds the policy limit")
)

// ErrBodyMismatch means the supplied request body does not hash to the digest
// committed in the spec.
//
// This is not an authorisation failure. The job may be perfectly permissible;
// it is simply not the job it claims to be. It is the guard against two
// concurrent executions having their payloads crossed, and against a body
// truncated in transit being sent under a spec that described the whole thing.
var ErrBodyMismatch = errors.New("request body does not match the hash committed in the job spec")

// Job is a request to execute: the spec plus the body it commits to.
//
// The body travels alongside the spec rather than inside it because the spec
// is hashed and cited in receipts while the body may be large and is only ever
// needed at execution time. Spec.BodyHash is what ties them together.
type Job struct {
	Spec jobs.Spec
	Body []byte
}

// Result is the outcome of an executed job.
//
// Receipt is always present when Execute returns a result, including when it
// also returns an error: a job that failed mid-flight still has something to
// prove.
type Result struct {
	// Receipt is the signed execution proof. Verify it with proof.Verify.
	Receipt proof.SignedReceipt

	// StatusCode is what the provider returned. Zero when the exchange never
	// produced a response.
	StatusCode uint32

	// ChunkCount and ResponseBytes describe what was received. They are also
	// inside the signed receipt; they are surfaced here for callers that relay
	// the body and want to cross-check their own counters.
	ChunkCount    uint64
	ResponseBytes uint64

	// StreamHash is the response digest. Also inside the receipt.
	StreamHash [32]byte

	// Truncated reports that the response was cut short, either by the size
	// cap or by the connection dropping.
	Truncated bool

	// PolicyHash names the policy revision that authorised the job.
	PolicyHash []byte

	// ProviderSeq is this execution's place in the provider's series. Also
	// inside the signed receipt; surfaced here so a server can log it without
	// decoding the receipt it just emitted.
	ProviderSeq uint64
}

// Config assembles a Service.
//
// Every field but Clock and SubmitterVerifier is mandatory. A service that
// cannot authorise, authenticate, execute, or attest must not be constructible
// — the failure should surface at wiring time, not on the first job.
type Config struct {
	// Policies decides whether a job may spend a provider's credential.
	Policies *policy.Set

	// Credentials supplies the secrets. Never logged, never signed.
	Credentials CredentialSource

	// Transport performs the outbound request.
	Transport Transport

	// Signer issues execution receipts from an attested key.
	Signer *proof.Signer

	// Seq assigns the per-provider monotonic sequence number signed into every
	// receipt. Mandatory, and deliberately not defaulted: see ErrNoSeqStore.
	Seq SeqStore

	// Clock is the service's time source. Defaults to time.Now. Injected
	// because receipt timestamps are part of what gets signed, and tests need
	// to pin them.
	Clock func() time.Time

	// RequestTimeout bounds a single provider exchange. Zero means no
	// service-level deadline beyond the caller's context.
	RequestTimeout time.Duration

	// SubmitterVerifier, when set, is consulted before anything else. It
	// answers "may this caller submit jobs at all".
	//
	// It is deliberately a bare function and deliberately optional. Transport
	// level mutual TLS is the intended first deployment, since it identifies
	// the Hub without introducing a key registry; this hook is where an
	// application-level scheme (a Hub signature over the spec) can be added
	// later without changing the shape of Execute.
	SubmitterVerifier func(ctx context.Context, spec jobs.Spec) error
}

// Service executes jobs inside the enclave. It is safe for concurrent use.
type Service struct {
	policies        *policy.Set
	credentials     CredentialSource
	transport       Transport
	signer          *proof.Signer
	seq             SeqStore
	clock           func() time.Time
	requestTimeout  time.Duration
	submitterVerify func(ctx context.Context, spec jobs.Spec) error
}

// NewService validates a configuration and returns a ready service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Policies == nil {
		return nil, ErrNoPolicySet
	}
	if cfg.Credentials == nil {
		return nil, ErrNoCredentials
	}
	if cfg.Transport == nil {
		return nil, ErrNoTransport
	}
	if cfg.Signer == nil {
		return nil, ErrNoSigner
	}
	if cfg.Seq == nil {
		return nil, ErrNoSeqStore
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		policies:        cfg.Policies,
		credentials:     cfg.Credentials,
		transport:       cfg.Transport,
		signer:          cfg.Signer,
		seq:             cfg.Seq,
		clock:           clock,
		requestTimeout:  cfg.RequestTimeout,
		submitterVerify: cfg.SubmitterVerifier,
	}, nil
}

// Execute runs one job and returns its signed receipt.
//
// onChunk receives response bytes as they arrive and may be nil. Returning an
// error from it stops the exchange; the receipt still describes everything
// received up to that point, marked truncated.
//
// An error is returned only for refusals — jobs that were never put on the
// wire. Once the request is sent, the outcome arrives as a Result whose
// Receipt.Completion reports what happened, and the error is nil even when the
// exchange failed.
//
// That inversion is deliberate. The receipt is worth most exactly when the
// exchange went wrong: it is the evidence that lets a Hub avoid charging for a
// response that never arrived, or prove a provider cut a stream short. Handing
// back a non-nil error in that case would invite the usual
// `if err != nil { return }` and take the evidence with it. The invariant is
// therefore that error is non-nil if and only if Result is nil.
func (s *Service) Execute(ctx context.Context, job Job, onChunk ChunkFunc) (*Result, error) {
	now := s.clock()

	if s.submitterVerify != nil {
		if err := s.submitterVerify(ctx, job.Spec); err != nil {
			return nil, fmt.Errorf("submitter rejected: %w", err)
		}
	}

	// Structure and freshness first: an unusable spec is not worth authorising.
	if err := job.Spec.ValidateAt(now); err != nil {
		return nil, err
	}

	// The body must be the body the spec describes. This is what catches two
	// concurrent jobs having their payloads crossed, or a truncated body
	// arriving under another job's authorisation.
	if !job.Spec.MatchesBody(job.Body) {
		return nil, ErrBodyMismatch
	}

	decision, err := s.policies.AuthorizeAt(job.Spec, now)
	if err != nil {
		return nil, err
	}

	if uint64(len(job.Body)) > decision.MaxBodyBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d",
			ErrBodyTooLarge, len(job.Body), decision.MaxBodyBytes)
	}

	headers, err := s.injectCredential(ctx, job.Spec, decision)
	if err != nil {
		return nil, err
	}

	specHash, err := job.Spec.Hash()
	if err != nil {
		return nil, err
	}

	// The last thing before the wire, and the only thing here that mutates
	// state. A failure to allocate is a refusal, not a receipt: better to
	// decline a job than to execute one whose place in the provider's series
	// cannot be recorded.
	//
	// The allocation is conservative in the other direction too. If the
	// exchange happens but signing then fails, the number is spent with no
	// receipt to show for it, and the provider sees a gap where nothing was
	// hidden. That is the right way round — a gap invites a question, while a
	// number reused after a crash would let a hidden receipt pass as accounted
	// for.
	seq, err := s.seq.Next([]byte(job.Spec.Provider))
	if err != nil {
		return nil, fmt.Errorf("allocate provider sequence: %w", err)
	}

	request := Request{
		Method:           job.Spec.Method,
		Host:             job.Spec.Host,
		Path:             job.Spec.Path,
		Query:            job.Spec.Query,
		Headers:          headers,
		Body:             job.Body,
		Stream:           job.Spec.Stream,
		MaxResponseBytes: decision.MaxResponseBytes,
		Timeout:          s.requestTimeout,
	}

	return s.perform(ctx, request, job.Spec, specHash, decision, seq, onChunk)
}

// injectCredential merges the caller's headers with the provider's secret,
// returning the exact header set to put on the wire.
func (s *Service) injectCredential(ctx context.Context, spec jobs.Spec, decision policy.Decision) (map[string]string, error) {
	headers := make(map[string]string, len(spec.Headers)+1)
	for name, value := range spec.Headers {
		headers[name] = value
	}

	// A policy with no credential header describes a provider that needs no
	// authentication. Nothing to inject.
	if decision.Credential.Header == "" {
		return headers, nil
	}

	// The job must not already occupy the header the credential goes in.
	// jobs.Validate rejects the reserved headers, so reaching here means that
	// check was bypassed — refuse rather than silently overwrite, which would
	// turn a guard into a no-op and leave no trace.
	if headerSet(headers, decision.Credential.Header) {
		return nil, fmt.Errorf("%w: %q", ErrCredentialClash, decision.Credential.Header)
	}

	secret, ok := s.credentials.Credential(ctx, spec.Provider)
	if !ok {
		return nil, missingCredential(spec.Provider)
	}

	// Rendering the header is the policy package's job. It owns the validation
	// a secret must pass before it can be written — no control characters, no
	// surrounding whitespace — and duplicating those rules here would give the
	// two copies room to drift apart.
	name, value, err := decision.Credential.Inject(secret)
	if err != nil {
		return nil, err
	}
	headers[name] = value
	return headers, nil
}

// perform sends the request, digests the response as it arrives, and signs the
// receipt. It is the only path that produces a receipt, which is why it is
// separated from the checks above: everything before it can refuse a job
// outright, everything inside it has already committed to executing.
func (s *Service) perform(
	ctx context.Context,
	request Request,
	spec jobs.Spec,
	specHash [32]byte,
	decision policy.Decision,
	seq uint64,
	onChunk ChunkFunc,
) (*Result, error) {
	hasher := proof.NewStreamingHasher(spec.JobID)
	truncated := false

	// Digest before relaying. If the relay fails — the Hub hung up, the
	// consumer is gone — the receipt still owes the verifier an honest account
	// of what the provider actually sent. Relaying first would let a consumer
	// error silently shrink the attested transcript.
	relay := func(chunk []byte) error {
		if err := hasher.WriteChunk(chunk); err != nil {
			return err
		}
		// Bytes past the cap are still counted. The receipt then says "this
		// many arrived, that was too many, we stopped", which a verifier can
		// check; trimming the count to fit the cap would make the transcript
		// disagree with the bytes the provider sent.
		if hasher.BytesWritten() > request.MaxResponseBytes {
			truncated = true
			return ErrResponseBodyTooLarge
		}
		if onChunk == nil {
			return nil
		}
		if err := onChunk(chunk); err != nil {
			// The provider stream is fine; the consumer stopped taking it.
			// The response is partial from the caller's point of view even
			// though the exchange itself completed.
			truncated = true
			return err
		}
		return nil
	}

	startedAt := s.clock().Unix()
	response, err := s.transport.Do(ctx, request, relay)
	finishedAt := s.clock().Unix()

	completion := proof.CompletionComplete
	switch {
	case err != nil && hasher.BytesWritten() == 0:
		completion = proof.CompletionFailed
	case err != nil, truncated:
		completion = proof.CompletionTruncated
	}

	// A status is trustworthy only once a response actually began. Clearing it
	// after bytes arrived would erase a real 200 that merely ran long, and
	// that status is part of what the Hub needs to be able to prove.
	statusCode := response.StatusCode
	if err != nil && hasher.BytesWritten() == 0 {
		statusCode = 0
	}

	streamHash := hasher.Sum()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         spec.JobID,
		JobSpecHash:   specHash[:],
		Provider:      spec.Provider,
		Method:        spec.Method,
		Host:          spec.Host,
		Path:          spec.Path,
		StatusCode:    statusCode,
		StreamHash:    streamHash[:],
		ChunkCount:    hasher.ChunkCount(),
		ResponseBytes: hasher.BytesWritten(),
		Completion:    completion,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		PolicyHash:    decision.PolicyHash,

		// The request side of the exchange. The size was already computed to
		// check it against the policy cap; signing it costs nothing and is the
		// only attested record of how much was sent, since the body itself
		// appears in the receipt only as a hash.
		RequestBytes: uint64(len(request.Body)),

		// Where this execution sits in the provider's series. A provider
		// holding a receipt numbered N knows it was used at least N times,
		// which is what turns a pile of individually-valid receipts into a
		// ledger whose completeness can be checked.
		ProviderSeq: seq,
	}

	signed, err := s.signer.Sign(receipt)
	if err != nil {
		return nil, fmt.Errorf("sign receipt: %w", err)
	}

	result := &Result{
		Receipt:       signed,
		StatusCode:    statusCode,
		ChunkCount:    hasher.ChunkCount(),
		ResponseBytes: hasher.BytesWritten(),
		StreamHash:    streamHash,
		// Derived from the completion state rather than tracked separately:
		// a result that says truncated while reporting a complete receipt, or
		// the reverse, would leave the caller guessing which to believe. The
		// relay's own flag is folded in to cover a transport that swallows a
		// consumer error and returns success anyway.
		Truncated:   truncated || completion == proof.CompletionTruncated,
		PolicyHash:  decision.PolicyHash,
		ProviderSeq: seq,
	}
	return result, nil
}

// headerSet reports whether a header map already contains name, ignoring case.
func headerSet(headers map[string]string, name string) bool {
	for existing := range headers {
		if strings.EqualFold(existing, name) {
			return true
		}
	}
	return false
}
