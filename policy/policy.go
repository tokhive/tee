// Package policy defines the TokenHive provider policy: the signed,
// provider-authored rules that bound what a job may ask an AI provider to do
// with a shared credential.
//
// A job spec describes what to do with a credential. It says nothing about what
// that credential is allowed to be used for — and since the Hub authors every
// spec, nothing else in the system does either. Without a policy, the Hub could
// send a provider's credential to any host, and the TEE would happily attest to
// the result.
//
// The policy is therefore not defence in depth. It is the only thing that
// stands between the Hub and a credential the Hub is not allowed to see, and
// the only constraint on the Hub that survives the User trusting it. It is
// written by whoever contributes the credential, signed by them, and loaded
// into the TEE, which then refuses any job that steps outside it.
//
// Policies are canonically encoded and hashed like every other signed
// TokenHive structure, so a policy hash is a stable reference a receipt or an
// audit log can point at.
package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

const (
	// VersionV1 is the only policy version the runtime accepts.
	VersionV1 = 1

	// PolicySigningDomain separates provider signatures on a policy from every
	// other signature the TokenHive stack produces.
	PolicySigningDomain = "TokenHive.ProviderPolicy.v1"

	MaxHosts          = 16
	MaxRules          = 64
	MaxAllowedHeaders = 64
	MaxQueryKeys      = 64
	MaxDisplayName    = 128
	MaxPlaceholderLen = 32

	MinNonceLength = 8
	MaxNonceLength = 64
)

// Policy validation errors.
var (
	ErrUnsupportedVersion = errors.New("unsupported policy version")
	ErrNoHosts            = errors.New("policy allows no hosts")
	ErrNoRules            = errors.New("policy declares no rules")
	ErrInvalidHost        = errors.New("invalid host in policy")
	ErrInvalidPathRule    = errors.New("invalid path rule")
	ErrInvalidMethods     = errors.New("invalid method list in policy")
	ErrInvalidCredential  = errors.New("invalid credential injection")
	ErrInvalidLimits      = errors.New("invalid policy limits")
	ErrInvalidQueryKey    = errors.New("invalid query key in policy")
	ErrInvalidHeaderName  = errors.New("invalid header name in policy")
	ErrInvalidNonce       = errors.New("invalid policy nonce")
	ErrInvalidTimeRange   = errors.New("invalid policy validity window")
	ErrInvalidSigningKey  = errors.New("invalid provider signing key")
	ErrPolicyExpired      = errors.New("policy has expired")
	ErrPolicyNotYetValid  = errors.New("policy is not yet valid")
)

// Policy is the signed statement of what a shared credential may be used for.
//
// The field order is not significant — canonical CBOR sorts by integer key —
// but the keys are part of the wire format and must never be renumbered or
// reused once a version ships.
type Policy struct {
	Version     uint32     `cbor:"1,keyasint"`
	Provider    string     `cbor:"2,keyasint"`
	DisplayName string     `cbor:"3,keyasint,omitempty"`
	Hosts       []string   `cbor:"4,keyasint"`
	Rules       []Rule     `cbor:"5,keyasint"`
	Credential  Credential `cbor:"6,keyasint"`
	Limits      Limits     `cbor:"7,keyasint"`
	IssuedAt    int64      `cbor:"8,keyasint"`
	ExpiresAt   int64      `cbor:"9,keyasint"`
	ProviderKey []byte     `cbor:"10,keyasint"`

	// Nonce lets a provider reissue an otherwise identical policy so that
	// rotations produce a different policy hash. Optional.
	Nonce []byte `cbor:"11,keyasint,omitempty"`
}

// Rule permits one family of requests: a path pattern crossed with the methods
// allowed on it.
type Rule struct {
	Methods       []string `cbor:"1,keyasint"`
	Path          string   `cbor:"2,keyasint"`
	AllowStream   bool     `cbor:"3,keyasint,omitempty"`
	QueryKeys     []string `cbor:"4,keyasint,omitempty"`
	AllowAnyQuery bool     `cbor:"5,keyasint,omitempty"`
}

// Credential describes how the TEE injects the shared credential. The secret
// itself never appears here: a policy is signed, distributed, and logged, so
// it may only describe the shape of the header, not its value.
type Credential struct {
	// Header is the request header the credential is placed in.
	Header string `cbor:"1,keyasint"`
	// Scheme is a prefix such as "Bearer". Empty means the token is the entire
	// header value.
	Scheme string `cbor:"2,keyasint,omitempty"`
}

// Limits are the bounds a job must stay inside. The TEE applies the stricter
// of the job's own limit and the policy's.
type Limits struct {
	// MaxResponseBytes caps the attested response size.
	MaxResponseBytes uint64 `cbor:"1,keyasint"`
	// MaxBodyBytes caps the request body size. Zero forbids a request body.
	MaxBodyBytes uint64 `cbor:"2,keyasint"`
	// AllowedHeaders is the whitelist of caller-settable header names.
	AllowedHeaders []string `cbor:"3,keyasint"`
}

// EncodeCanonical returns the deterministic CBOR encoding of the policy.
func (p Policy) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(p)
}

// Hash returns the policy hash: SHA-256 over the domain prefix and the
// canonical encoding. This is what the provider signs and what external
// systems cite when referring to a policy version.
func (p Policy) Hash() ([32]byte, error) {
	var zero [32]byte

	encoded, err := p.EncodeCanonical()
	if err != nil {
		return zero, err
	}

	h := sha256.New()
	h.Write([]byte(PolicySigningDomain))
	h.Write(encoded)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// Validate checks structural correctness, including that the embedded signing
// key is a usable P-256 public key. It does not check the validity window (use
// ValidateAt) or the signature (use VerifySignedPolicy).
func (p Policy) Validate() error {
	if p.Version != VersionV1 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, p.Version)
	}
	if err := jobs.ValidateProviderName(p.Provider); err != nil {
		return err
	}
	if len(p.DisplayName) > MaxDisplayName {
		return fmt.Errorf("%w: display name length %d exceeds %d",
			ErrInvalidLimits, len(p.DisplayName), MaxDisplayName)
	}

	if len(p.Hosts) == 0 {
		return ErrNoHosts
	}
	if len(p.Hosts) > MaxHosts {
		return fmt.Errorf("%w: %d entries exceeds %d", ErrNoHosts, len(p.Hosts), MaxHosts)
	}
	seenHosts := make(map[string]bool, len(p.Hosts))
	for _, host := range p.Hosts {
		if err := validatePolicyHost(host); err != nil {
			return err
		}
		normalised := strings.ToLower(host)
		if seenHosts[normalised] {
			return fmt.Errorf("%w: duplicate host %q", ErrInvalidHost, host)
		}
		seenHosts[normalised] = true
	}

	if len(p.Rules) == 0 {
		return ErrNoRules
	}
	if len(p.Rules) > MaxRules {
		return fmt.Errorf("%w: %d entries exceeds %d", ErrNoRules, len(p.Rules), MaxRules)
	}
	for i, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}

	if err := p.Credential.Validate(); err != nil {
		return err
	}
	if err := p.Limits.Validate(); err != nil {
		return err
	}

	if p.IssuedAt <= 0 || p.ExpiresAt <= p.IssuedAt {
		return fmt.Errorf("%w: issued %d, expires %d", ErrInvalidTimeRange, p.IssuedAt, p.ExpiresAt)
	}
	if len(p.Nonce) > 0 && (len(p.Nonce) < MinNonceLength || len(p.Nonce) > MaxNonceLength) {
		return fmt.Errorf("%w: length %d outside [%d,%d]",
			ErrInvalidNonce, len(p.Nonce), MinNonceLength, MaxNonceLength)
	}
	if err := validateSigningKey(p.ProviderKey); err != nil {
		return err
	}
	return nil
}

// ValidateAt performs structural validation plus the validity window check.
// A policy is not valid before IssuedAt and is already dead at ExpiresAt.
func (p Policy) ValidateAt(now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if now.Unix() < p.IssuedAt {
		return fmt.Errorf("%w: valid from %d, now %d", ErrPolicyNotYetValid, p.IssuedAt, now.Unix())
	}
	if now.Unix() >= p.ExpiresAt {
		return fmt.Errorf("%w: expired at %d, now %d", ErrPolicyExpired, p.ExpiresAt, now.Unix())
	}
	return nil
}

func (r Rule) Validate() error {
	if len(r.Methods) == 0 {
		return fmt.Errorf("%w: rule declares no methods", ErrInvalidMethods)
	}
	seenMethods := make(map[string]bool, len(r.Methods))
	for _, method := range r.Methods {
		if !jobs.SupportedMethods[method] {
			return fmt.Errorf("%w: %q", ErrInvalidMethods, method)
		}
		if seenMethods[method] {
			return fmt.Errorf("%w: duplicate method %q", ErrInvalidMethods, method)
		}
		seenMethods[method] = true
	}
	if err := validatePathRule(r.Path); err != nil {
		return err
	}
	if len(r.QueryKeys) > MaxQueryKeys {
		return fmt.Errorf("%w: %d entries exceeds %d", ErrInvalidQueryKey, len(r.QueryKeys), MaxQueryKeys)
	}
	seenKeys := make(map[string]bool, len(r.QueryKeys))
	for _, key := range r.QueryKeys {
		if !isQueryKey(key) {
			return fmt.Errorf("%w: %q", ErrInvalidQueryKey, key)
		}
		if seenKeys[key] {
			return fmt.Errorf("%w: duplicate key %q", ErrInvalidQueryKey, key)
		}
		seenKeys[key] = true
	}
	return nil
}

// Inject returns the header name and value that carry the credential.
//
// The token is validated rather than trusted: a credential that reaches the
// header writer with a CR/LF would let a secret leak into the request as a
// smuggled header line, and the TEE is the last component that can stop it.
func (c Credential) Inject(token string) (string, string, error) {
	if err := c.Validate(); err != nil {
		return "", "", err
	}
	if token == "" {
		return "", "", fmt.Errorf("%w: empty credential", ErrInvalidCredential)
	}
	if strings.ContainsAny(token, "\r\n\x00") {
		return "", "", fmt.Errorf("%w: credential contains a control character", ErrInvalidCredential)
	}
	if strings.TrimSpace(token) != token {
		return "", "", fmt.Errorf("%w: credential has surrounding whitespace", ErrInvalidCredential)
	}
	if c.Scheme == "" {
		return c.Header, token, nil
	}
	return c.Header, c.Scheme + " " + token, nil
}

func (c Credential) Validate() error {
	if !isToken(c.Header) {
		return fmt.Errorf("%w: %q is not a valid header name", ErrInvalidCredential, c.Header)
	}
	if isReservedInjectionHeader(c.Header) {
		return fmt.Errorf("%w: %q must not be injected", ErrInvalidCredential, c.Header)
	}
	if c.Scheme != "" && !isToken(c.Scheme) {
		return fmt.Errorf("%w: %q is not a valid scheme", ErrInvalidCredential, c.Scheme)
	}
	return nil
}

func (l Limits) Validate() error {
	if l.MaxResponseBytes == 0 {
		return fmt.Errorf("%w: MaxResponseBytes must be greater than zero", ErrInvalidLimits)
	}
	if len(l.AllowedHeaders) > MaxAllowedHeaders {
		return fmt.Errorf("%w: %d headers exceeds %d",
			ErrInvalidLimits, len(l.AllowedHeaders), MaxAllowedHeaders)
	}
	seen := make(map[string]bool, len(l.AllowedHeaders))
	for _, name := range l.AllowedHeaders {
		if !isToken(name) {
			return fmt.Errorf("%w: %q is not a valid header name", ErrInvalidHeaderName, name)
		}
		// Whitelisting a TEE-controlled header here would be self-defeating:
		// the job layer rejects those headers outright.
		if jobs.IsForbiddenHeader(name) {
			return fmt.Errorf("%w: %q is controlled by the TEE", ErrInvalidHeaderName, name)
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return fmt.Errorf("%w: duplicate header %q", ErrInvalidHeaderName, name)
		}
		seen[lower] = true
	}
	return nil
}

// validateSigningKey requires a P-256 SPKI key up front, so that a policy
// which could never verify a signature is rejected at load time rather than at
// the first job.
func validateSigningKey(publicKeyDER []byte) error {
	if len(publicKeyDER) == 0 {
		return fmt.Errorf("%w: empty key", ErrInvalidSigningKey)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: type %T, want ECDSA", ErrInvalidSigningKey, parsed)
	}
	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("%w: curve %q, want P-256", ErrInvalidSigningKey, publicKey.Curve.Params().Name)
	}
	return nil
}

// reservedInjectionHeaders are headers the credential must never be injected
// into. They either describe the framing the TEE itself controls, or they
// change how the proxy-hop is interpreted.
var reservedInjectionHeaders = []string{
	"host",
	"content-length",
	"transfer-encoding",
	"connection",
	"upgrade",
	"te",
	"trailer",
	"proxy-authorization",
}

func isReservedInjectionHeader(name string) bool {
	for _, reserved := range reservedInjectionHeaders {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

func validatePolicyHost(host string) error {
	if host == "" || len(host) > jobs.MaxHostLength {
		return fmt.Errorf("%w: %q", ErrInvalidHost, host)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidHost, host)
	}
	if strings.ContainsAny(host, "/@?") {
		return fmt.Errorf("%w: %q must be host or host:port", ErrInvalidHost, host)
	}
	hostname, port := splitHostPort(host)
	if port != "" && !isDigits(port) {
		return fmt.Errorf("%w: %q has a non-numeric port", ErrInvalidHost, host)
	}
	if hostname == "" {
		return fmt.Errorf("%w: %q has an empty hostname", ErrInvalidHost, host)
	}
	if strings.Contains(hostname, ":") || strings.HasSuffix(hostname, ".") {
		return fmt.Errorf("%w: %q is not a plain DNS name", ErrInvalidHost, host)
	}
	return nil
}

// validatePathRule checks a rule path. Segments are either literal or a
// single-segment placeholder of the form {name}.
func validatePathRule(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: %q must be absolute", ErrInvalidPathRule, path)
	}
	if len(path) > jobs.MaxPathLength {
		return fmt.Errorf("%w: length %d exceeds %d", ErrInvalidPathRule, len(path), jobs.MaxPathLength)
	}
	if strings.ContainsAny(path, " \t\r\n") {
		return fmt.Errorf("%w: %q contains whitespace", ErrInvalidPathRule, path)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if strings.ContainsAny(segment, "{}") {
			// A segment that mentions braces at all must be a well-formed
			// placeholder; partial or mixed forms are a parsing bug waiting to
			// become an authz bug.
			if !isPlaceholderSegment(segment) {
				return fmt.Errorf("%w: %q is not a valid placeholder", ErrInvalidPathRule, path)
			}
			continue
		}
		// Literal segments must not contain characters that would make the
		// match ambiguous against a percent-encoded or normalised path.
		if strings.ContainsAny(segment, "\\%") {
			return fmt.Errorf("%w: %q contains a reserved character", ErrInvalidPathRule, path)
		}
	}
	return nil
}

func isPlaceholder(segment string) bool {
	return len(segment) > 2 &&
		strings.HasPrefix(segment, "{") &&
		strings.HasSuffix(segment, "}")
}

// isPlaceholderSegment reports whether a segment is a well-formed
// single-segment placeholder such as {model}.
func isPlaceholderSegment(segment string) bool {
	if !isPlaceholder(segment) {
		return false
	}
	name := segment[1 : len(segment)-1]
	if name == "" || len(name) > MaxPlaceholderLen {
		return false
	}
	return isPlaceholderNameValid(name)
}

func isPlaceholderNameValid(name string) bool {
	for _, r := range name {
		isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if !isAlpha && !isDigit && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// isQueryKey restricts query parameter names to a conservative character set.
// Percent-encoding and bracket syntax are rejected: they are the usual way a
// filter gets bypassed through a second, equivalent spelling of a key.
func isQueryKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	for _, r := range key {
		isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if !isAlpha && !isDigit && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
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

// splitHostPort splits on the last colon. It is used instead of
// net.SplitHostPort because a host without a port is valid here, and because
// an unbracketed IPv6 literal must be rejected rather than silently accepted
// as a host with a very odd port.
func splitHostPort(host string) (string, string) {
	separator := strings.LastIndex(host, ":")
	if separator < 0 {
		return host, ""
	}
	return host[:separator], host[separator+1:]
}

// parseQueryKeys extracts and sorts the keys of a query string.
//
// Parsing happens here rather than by string-splitting so that the policy sees
// the same keys the provider's server will. A malformed query is rejected:
// anything the TEE cannot parse, it cannot bound.
func parseQueryKeys(query string) ([]string, error) {
	if query == "" {
		return nil, nil
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a valid query string", ErrQueryNotAllowed, query)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if key == "" {
			return nil, fmt.Errorf("%w: query has an empty parameter name", ErrQueryNotAllowed)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}
