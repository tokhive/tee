// Package jobs defines the TokenHive job specification: the request
// description the Hub constructs and hands to the TEE, which validates it
// before it ever touches a provider credential.
//
// A Spec is the unit of dispatched intent. It is canonically encoded and
// hashed, and that hash is what the execution receipt binds to — so a verifier
// can later prove which request a response belongs to.
//
// Trust model. The User trusts the Hub by default, so a Spec carries no User
// signature: the Hub is its author, not merely its courier. The Spec is what
// constrains the Hub on behalf of the Provider, via the provider policy and
// the signed receipt, not what protects the User from the Hub.
//
// Consequence: this package authenticates nothing. It checks that a Spec is
// well formed, unexpired, and bound to the bytes that will actually be sent.
// Deciding whether the submitter is a legitimate Hub is a transport concern,
// deliberately left open — see the TEE service design notes.
package jobs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
)

// Encoding and identity constants.
const (
	// VersionV1 is the only JobSpec version the runtime accepts.
	VersionV1 = 1

	// JobSpecHashDomain is the prefix of the job spec hash. It keeps a spec
	// digest from colliding with a digest computed for another purpose, so a
	// receipt cannot be replayed as, say, a policy hash.
	JobSpecHashDomain = "TokenHive.JobSpec.v1"

	// BodyHashDomain separates request body digests from other digests.
	BodyHashDomain = "TokenHive.RequestBody.v1"

	// JobIDLength is the size of a random job identifier.
	JobIDLength = 16

	// BodyHashLength is the size of a SHA-256 request body digest.
	BodyHashLength = 32

	// NonceLength bounds keep a spec hash unambiguous while leaving room for
	// the Hub's own nonce scheme.
	MinNonceLength = 8
	MaxNonceLength = 64

	MaxHeaders      = 32
	MaxPathLength   = 2048
	MaxQueryLength  = 4096
	MaxHostLength   = 253
	MaxProviderName = 64
)

// Validation errors. Callers can match these with errors.Is to map them onto
// transport-level status codes.
var (
	ErrUnsupportedVersion = errors.New("unsupported job spec version")
	ErrInvalidJobID       = errors.New("invalid job ID")
	ErrInvalidProvider    = errors.New("invalid provider")
	ErrInvalidMethod      = errors.New("invalid HTTP method")
	ErrInvalidHost        = errors.New("invalid host")
	ErrInvalidPath        = errors.New("invalid path")
	ErrInvalidQuery       = errors.New("invalid query")
	ErrInvalidHeaders     = errors.New("invalid headers")
	ErrInvalidBodyHash    = errors.New("invalid body hash")
	ErrInvalidNonce       = errors.New("invalid nonce")
	ErrInvalidExpiry      = errors.New("invalid expiry")
	ErrInvalidLimit       = errors.New("invalid response size limit")
	ErrExpired            = errors.New("job spec has expired")
	ErrNonceEmpty         = errors.New("nonce must not be empty")
)

// Spec is a request the Hub asks the TEE to perform with a provider credential.
//
// The field order here is not significant — canonical CBOR sorts by the integer
// key — but the keys themselves are part of the wire format and must never be
// renumbered or reused once a version ships.
//
// Key 14 was UserKeyID. It was removed with the User signature and is retired
// rather than reassigned: a decoder that still emits it would otherwise be
// read as a different field. No future field may use 14 in VersionV1.
type Spec struct {
	Version          uint32            `cbor:"1,keyasint"`
	JobID            []byte            `cbor:"2,keyasint"`
	Provider         string            `cbor:"3,keyasint"`
	Method           string            `cbor:"4,keyasint"`
	Host             string            `cbor:"5,keyasint"`
	Path             string            `cbor:"6,keyasint"`
	Query            string            `cbor:"7,keyasint"`
	Headers          map[string]string `cbor:"8,keyasint"`
	BodyHash         []byte            `cbor:"9,keyasint"`
	Nonce            []byte            `cbor:"10,keyasint"`
	ExpiresAt        int64             `cbor:"11,keyasint"`
	MaxResponseBytes uint64            `cbor:"12,keyasint"`
	Stream           bool              `cbor:"13,keyasint"`
}

// SupportedMethods are the HTTP methods a job may request. HEAD is excluded:
// a HEAD response has no body to attest to, which would make the execution
// receipt meaningless.
var SupportedMethods = map[string]bool{
	"GET":    true,
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

// EncodeCanonical returns the deterministic CBOR encoding of the spec. Two
// logically identical specs always encode to the same bytes.
func (s Spec) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(s)
}

// Hash returns the job spec hash: SHA-256 over the domain prefix and the
// canonical encoding.
//
// This is the value the execution receipt binds to. Nothing signs it any
// more — the Hub authors the spec — but it is still the anchor that ties a
// response to the request that produced it, and the value a provider compares
// against its policy when auditing how a credential was spent.
func (s Spec) Hash() ([32]byte, error) {
	var zero [32]byte

	encoded, err := s.EncodeCanonical()
	if err != nil {
		return zero, err
	}

	h := sha256.New()
	h.Write([]byte(JobSpecHashDomain))
	h.Write(encoded)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// HashBody computes the request body digest referenced by Spec.BodyHash. The
// request body is never part of the canonical spec encoding itself; it is
// committed to by hash so a large body does not inflate the signed structure.
func HashBody(body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(BodyHashDomain))
	h.Write(body)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Validate checks structural correctness. It does not check expiry; use
// ValidateAt for that, so a caller can report the two classes of failure
// distinctly.
func (s Spec) Validate() error {
	if s.Version != VersionV1 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, s.Version)
	}
	if len(s.JobID) != JobIDLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidJobID, len(s.JobID), JobIDLength)
	}
	if err := ValidateProviderName(s.Provider); err != nil {
		return err
	}
	if !SupportedMethods[s.Method] {
		return fmt.Errorf("%w: %q", ErrInvalidMethod, s.Method)
	}
	if err := validateHost(s.Host); err != nil {
		return err
	}
	if err := validatePath(s.Path); err != nil {
		return err
	}
	if len(s.Query) > MaxQueryLength {
		return fmt.Errorf("%w: length %d exceeds %d", ErrInvalidQuery, len(s.Query), MaxQueryLength)
	}
	if err := validateHeaders(s.Headers); err != nil {
		return err
	}
	if len(s.BodyHash) != BodyHashLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidBodyHash, len(s.BodyHash), BodyHashLength)
	}
	if len(s.Nonce) < MinNonceLength || len(s.Nonce) > MaxNonceLength {
		return fmt.Errorf("%w: length %d outside [%d,%d]",
			ErrInvalidNonce, len(s.Nonce), MinNonceLength, MaxNonceLength)
	}
	if s.ExpiresAt <= 0 {
		return fmt.Errorf("%w: %d", ErrInvalidExpiry, s.ExpiresAt)
	}
	if s.MaxResponseBytes == 0 {
		return fmt.Errorf("%w: must be greater than zero", ErrInvalidLimit)
	}
	return nil
}

// ValidateAt performs structural validation plus the expiry check relative to
// now. Expiry is inclusive-free: a spec expiring exactly now is already dead.
func (s Spec) ValidateAt(now time.Time) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if now.Unix() >= s.ExpiresAt {
		return fmt.Errorf("%w: expired at %d, now %d",
			ErrExpired, s.ExpiresAt, now.Unix())
	}
	return nil
}

// MatchesBody reports whether body hashes to Spec.BodyHash.
func (s Spec) MatchesBody(body []byte) bool {
	computed := HashBody(body)
	if len(s.BodyHash) != BodyHashLength {
		return false
	}
	return subtleEqual(computed[:], s.BodyHash)
}

// ValidateProviderName checks the shape of a provider identifier.
//
// It is exported so that provider policies, which are keyed by the same
// identifier, apply exactly the same rule instead of drifting into their own.
func ValidateProviderName(provider string) error {
	if provider == "" || len(provider) > MaxProviderName {
		return fmt.Errorf("%w: %q", ErrInvalidProvider, provider)
	}
	for _, r := range provider {
		isLower := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if !isLower && !isDigit && r != '-' && r != '_' {
			return fmt.Errorf("%w: %q contains unsupported character %q",
				ErrInvalidProvider, provider, r)
		}
	}
	return nil
}

func validateHost(host string) error {
	if host == "" || len(host) > MaxHostLength {
		return fmt.Errorf("%w: %q", ErrInvalidHost, host)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidHost, host)
	}
	// A job targets one absolute host:port. Anything carrying a scheme, path,
	// or userinfo is a sign that the Hub passed through an attacker-controlled
	// URL instead of matching against a provider policy.
	if strings.Contains(host, "/") || strings.Contains(host, "@") || strings.Contains(host, "?") {
		return fmt.Errorf("%w: %q must be host or host:port", ErrInvalidHost, host)
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		// No port is acceptable; the TLS layer defaults to 443.
		hostname = host
		port = ""
	}
	if port != "" && !isDigits(port) {
		return fmt.Errorf("%w: %q has a non-numeric port", ErrInvalidHost, host)
	}
	if hostname == "" {
		return fmt.Errorf("%w: %q has an empty hostname", ErrInvalidHost, host)
	}
	// Reject IPv6 literals and trailing separators, which SplitHostPort
	// otherwise tolerates in ways that complicate policy matching.
	if strings.Contains(hostname, ":") || strings.HasSuffix(hostname, ".") {
		return fmt.Errorf("%w: %q is not a plain DNS name", ErrInvalidHost, host)
	}
	return nil
}

func validatePath(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: %q must be absolute", ErrInvalidPath, path)
	}
	if len(path) > MaxPathLength {
		return fmt.Errorf("%w: length %d exceeds %d", ErrInvalidPath, len(path), MaxPathLength)
	}
	// Block traversal sequences before they ever reach a provider policy
	// matcher; normalisation differences between components are a recurring
	// source of authz bypasses.
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." || segment == "." {
			return fmt.Errorf("%w: %q contains a traversal segment", ErrInvalidPath, path)
		}
	}
	if strings.ContainsAny(path, " \t\r\n") {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidPath, path)
	}
	return nil
}

// validateHeaders enforces the shape of caller-supplied headers. The TEE strips
// and rebuilds security-sensitive headers, so rejecting them here is defence in
// depth rather than the primary control.
func validateHeaders(headers map[string]string) error {
	if len(headers) > MaxHeaders {
		return fmt.Errorf("%w: %d entries exceeds %d", ErrInvalidHeaders, len(headers), MaxHeaders)
	}
	for name, value := range headers {
		if name == "" {
			return fmt.Errorf("%w: empty header name", ErrInvalidHeaders)
		}
		if !isToken(name) {
			return fmt.Errorf("%w: %q is not a valid header name", ErrInvalidHeaders, name)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%w: %q contains a control character", ErrInvalidHeaders, name)
		}
		if IsForbiddenHeader(name) {
			return fmt.Errorf("%w: %q is controlled by the TEE", ErrInvalidHeaders, name)
		}
	}
	return nil
}

// forbiddenHeaders are headers the TEE owns: the injected credential, the
// framing of the request, and anything that could smuggle a second request.
var forbiddenHeaders = []string{
	"authorization",
	"host",
	"content-length",
	"transfer-encoding",
	"connection",
	"proxy-authorization",
	"te",
	"upgrade",
}

// IsForbiddenHeader reports whether the TEE owns a header and a caller is
// therefore never allowed to set it.
//
// It is exported so that provider policies, which whitelist the headers a
// caller may set, cannot accidentally whitelist one of these.
func IsForbiddenHeader(name string) bool {
	for _, forbidden := range forbiddenHeaders {
		if strings.EqualFold(name, forbidden) {
			return true
		}
	}
	return false
}

// HeaderNames returns the sorted header names, useful for building a request in
// a stable order.
func (s Spec) HeaderNames() []string {
	names := make([]string, 0, len(s.Headers))
	for name := range s.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > 127 {
			return false
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// subtleEqual is a constant-time comparison for digests. Digests are public,
// but a body hash is attacker-influenced and constant-time comparison costs
// nothing at this size.
func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
