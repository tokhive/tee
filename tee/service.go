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
	"io"
	"strings"
	"sync"
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

// ErrNoSessionSupport means the configured transport can run request/response
// exchanges but not streaming sessions. It is a wiring mismatch surfaced lazily
// when a session is requested, because a request/response-only transport is
// legitimate and a Hub may simply never need streaming.
var ErrNoSessionSupport = errors.New("transport does not support streaming sessions")

// ErrSessionBody means a streaming session job carried a request body. A
// session is opened by a handshake, not a payload: it commits to an empty body,
// and the body hash must be the digest of zero bytes.
var ErrSessionBody = errors.New("streaming session must carry an empty body")

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
		Provider:         job.Spec.Provider,
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
	// Total bytes/chunks the provider actually sent, counted even past the
	// cap. The StreamHash below covers only what was relayed (so the Hub can
	// verify the prefix it forwarded), while these totals honestly record how
	// much arrived — a provider cannot later claim it sent less than it did.
	var totalBytes, totalChunks uint64

	// Digest before relaying. If the relay fails — the Hub hung up, the
	// consumer is gone — the receipt still owes the verifier an honest account
	// of what the provider actually sent. Relaying first would let a consumer
	// error silently shrink the attested transcript.
	relay := func(chunk []byte) error {
		totalBytes += uint64(len(chunk))
		totalChunks++
		// Enforce the cap before the bytes enter the hash. If we hashed first
		// and checked after, the over-cap chunk would be counted in the
		// StreamHash but never relayed, so the receipt's hash could never
		// agree with the bytes the Hub actually forwarded — every truncated
		// response would then fail the Hub's stream check. Stopping first
		// keeps the hash equal to the relayed prefix; the overflow lives in
		// ResponseBytes/ChunkCount instead.
		if hasher.BytesWritten()+uint64(len(chunk)) > request.MaxResponseBytes {
			truncated = true
			return ErrResponseBodyTooLarge
		}
		if err := hasher.WriteChunk(chunk); err != nil {
			return err
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
		ChunkCount:    totalChunks,
		ResponseBytes: totalBytes,
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
		ChunkCount:    totalChunks,
		ResponseBytes: totalBytes,
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

// Session is a metered, attested transparent tunnel to a provider, opened by
// Service.OpenSession. It runs the same refusal checks a normal execution does,
// then turns the transport's session connection into a byte pipe whose every
// byte is counted (uplink → RequestBytes, downlink → ResponseBytes) and whose
// downlink plaintext is streamed into the receipt digest. Frame and payload
// semantics are never touched here — the caller owns them, which is the whole
// point of the design: the TEE only moves, counts, and digests bytes.
type Session struct {
	svc      *Service
	spec     jobs.Spec
	specHash [32]byte
	decision policy.Decision
	seq      uint64
	conn     SessionConn

	hasher  *proof.StreamingHasher
	started int64

	mu             sync.Mutex
	requestBytes   uint64
	responseBytes  uint64
	chunkCount     uint64
	finishedAt     int64
	truncated      bool
	receiptEmitted bool
	cachedRes      *Result
	cachedErr      error
}

// OpenSession establishes a streaming session to the provider. It runs the same
// refusal checks as Execute — submitter, spec structure and expiry, body
// binding, policy authorisation, credential resolution, sequence allocation —
// then performs the Upgrade handshake and returns a Session the caller drives
// with Read/Write and finishes with Receipt.
//
// A session job must carry an empty body and set Spec.Session. The body hash
// binding still applies: the writer commits to a hash of zero bytes, which is
// how a session and a stray request are told apart even before the transport
// sees them.
func (s *Service) OpenSession(ctx context.Context, job Job) (*Session, error) {
	now := s.clock()

	if s.submitterVerify != nil {
		if err := s.submitterVerify(ctx, job.Spec); err != nil {
			return nil, fmt.Errorf("submitter rejected: %w", err)
		}
	}
	if err := job.Spec.ValidateAt(now); err != nil {
		return nil, err
	}
	if !job.Spec.MatchesBody(job.Body) {
		return nil, ErrBodyMismatch
	}
	if len(job.Body) != 0 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrSessionBody, len(job.Body))
	}
	if !job.Spec.Session {
		return nil, fmt.Errorf("%w: Spec.Session is false", ErrSessionBody)
	}

	decision, err := s.policies.AuthorizeAt(job.Spec, now)
	if err != nil {
		return nil, err
	}
	headers, err := s.injectCredential(ctx, job.Spec, decision)
	if err != nil {
		return nil, err
	}
	specHash, err := job.Spec.Hash()
	if err != nil {
		return nil, err
	}
	seq, err := s.seq.Next([]byte(job.Spec.Provider))
	if err != nil {
		return nil, fmt.Errorf("allocate provider sequence: %w", err)
	}

	opener, ok := s.transport.(SessionOpener)
	if !ok {
		return nil, ErrNoSessionSupport
	}

	// A session is a GET handshake with no body; the transport adds the
	// Upgrade headers itself. MaxResponseBytes is deliberately not applied to
	// the tunnel: it is bidirectional and unbounded, so the only honest metering
	// is counting and digesting everything the provider sends.
	request := Request{
		Method:   job.Spec.Method,
		Provider: job.Spec.Provider,
		Host:     job.Spec.Host,
		Path:     job.Spec.Path,
		Query:    job.Spec.Query,
		Headers:  headers,
		Stream:   true,
		Timeout:  s.requestTimeout,
	}
	conn, err := opener.OpenSession(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}

	return &Session{
		svc:      s,
		spec:     job.Spec,
		specHash: specHash,
		decision: decision,
		seq:      seq,
		conn:     conn,
		hasher:   proof.NewStreamingHasher(job.Spec.JobID),
		started:  now.Unix(),
	}, nil
}

// Write sends bytes uplink to the provider and counts them toward RequestBytes
// in the eventual receipt.
func (s *Session) Write(p []byte) (int, error) {
	n, err := s.conn.Write(p)
	if n > 0 {
		s.mu.Lock()
		s.requestBytes += uint64(n)
		s.mu.Unlock()
	}
	return n, err
}

// Read receives downlink bytes from the provider, counts them toward
// ResponseBytes, and digests them into the receipt's StreamHash. The bytes are
// opaque — frame interpretation is entirely the caller's.
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.conn.Read(p)
	if n > 0 {
		s.hasher.WriteChunk(p[:n])
		s.mu.Lock()
		s.responseBytes += uint64(n)
		s.chunkCount++
		// A provider that drops the socket mid-session — anything but a clean
		// EOF — leaves the transcript partial, and the receipt must say so.
		if err != nil && !errors.Is(err, io.EOF) {
			s.truncated = true
		}
		s.mu.Unlock()
	}
	return n, err
}

// Close tears down the underlying provider connection. Pending Reads on the
// same Session return once the socket is closed.
func (s *Session) Close() error { return s.conn.Close() }

// Receipt signs the session's execution receipt. It is idempotent: the first
// call signs, and later calls return the same result. Call it once the session
// is over. The receipt carries StatusCode 101 (the successful upgrade),
// RequestBytes equal to the uplink total, and ResponseBytes/ChunkCount/
// StreamHash describing the downlink — the same response-digest contract a
// normal execution receipt uses.
func (s *Session) Receipt() (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receiptEmitted {
		return s.cachedRes, s.cachedErr
	}
	s.finishedAt = s.svc.clock().Unix()

	completion := proof.CompletionComplete
	if s.truncated {
		completion = proof.CompletionTruncated
	}
	streamHash := s.hasher.Sum()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         s.spec.JobID,
		JobSpecHash:   s.specHash[:],
		Provider:      s.spec.Provider,
		Method:        s.spec.Method,
		Host:          s.spec.Host,
		Path:          s.spec.Path,
		StatusCode:    101,
		StreamHash:    streamHash[:],
		ChunkCount:    s.chunkCount,
		ResponseBytes: s.responseBytes,
		Completion:    completion,
		StartedAt:     s.started,
		FinishedAt:    s.finishedAt,
		PolicyHash:    s.decision.PolicyHash,
		RequestBytes:  s.requestBytes,
		ProviderSeq:   s.seq,
	}
	signed, err := s.svc.signer.Sign(receipt)
	result := &Result{
		Receipt:       signed,
		StatusCode:    101,
		ChunkCount:    s.chunkCount,
		ResponseBytes: s.responseBytes,
		StreamHash:    streamHash,
		Truncated:     completion == proof.CompletionTruncated,
		PolicyHash:    s.decision.PolicyHash,
		ProviderSeq:   s.seq,
	}
	s.receiptEmitted = true
	s.cachedRes = result
	s.cachedErr = err
	return result, err
}
