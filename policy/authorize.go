package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// Authorization errors. Every one of them means "the job is well-formed but
// the credential owner did not permit it". Callers can match these with
// errors.Is to map them onto transport-level status codes, and because they are
// distinct from the validation errors in policy.go, a caller can tell a broken
// job apart from a forbidden one.
var (
	ErrProviderMismatch = errors.New("policy provider does not match the job")
	ErrHostNotAllowed   = errors.New("host is not allowed by policy")
	ErrPathNotAllowed   = errors.New("path is not allowed by policy")
	ErrMethodNotAllowed = errors.New("method is not allowed by policy")
	ErrHeaderNotAllowed = errors.New("header is not allowed by policy")
	ErrQueryNotAllowed  = errors.New("query parameter is not allowed by policy")
	ErrStreamNotAllowed = errors.New("streaming is not allowed by policy")
	ErrLimitExceeded    = errors.New("job exceeds a policy limit")
	ErrUnknownProvider  = errors.New("no policy for provider")
)

// Decision is the outcome of an allowed job: the rule that admitted it and the
// limits that now apply.
//
// The limits are already resolved — the TEE does not need to remember to take
// the minimum of the job's request and the policy's cap.
type Decision struct {
	Provider         string
	Rule             Rule
	Credential       Credential
	MaxResponseBytes uint64
	MaxBodyBytes     uint64

	// PolicyHash identifies the exact policy revision this decision was made
	// under. The TEE copies it into the execution receipt so a provider can
	// later tell which revision of its own rules authorised a spend.
	//
	// It is resolved as part of the decision rather than looked up afterwards
	// because a policy can be rotated at any moment: asking for the hash
	// separately could name a revision that was never applied to this job.
	PolicyHash []byte
}

// AllowStream reports whether the admitted job may use a streamed response.
func (d Decision) AllowStream() bool { return d.Rule.AllowStream }

// Authorize checks a job spec against the policy: host, path, method, headers,
// query, streaming, and size limits.
//
// The spec is validated first. A policy is a gate on well-formed jobs, not a
// substitute for parsing them — an unvalidated spec must never reach rule
// matching, or matching results become meaningless.
func (p Policy) Authorize(spec jobs.Spec) (Decision, error) {
	if err := spec.Validate(); err != nil {
		return Decision{}, err
	}
	if err := p.Validate(); err != nil {
		return Decision{}, err
	}
	return p.authorize(spec)
}

// AuthorizeAt is Authorize plus both validity windows: the policy must be in
// effect and the job must not have expired.
func (p Policy) AuthorizeAt(spec jobs.Spec, now time.Time) (Decision, error) {
	if err := p.ValidateAt(now); err != nil {
		return Decision{}, err
	}
	if err := spec.ValidateAt(now); err != nil {
		return Decision{}, err
	}
	return p.authorize(spec)
}

func (p Policy) authorize(spec jobs.Spec) (Decision, error) {
	var empty Decision

	if p.Provider != spec.Provider {
		return empty, fmt.Errorf("%w: policy %q, job %q",
			ErrProviderMismatch, p.Provider, spec.Provider)
	}
	if !p.HostAllowed(spec.Host) {
		return empty, fmt.Errorf("%w: %q", ErrHostNotAllowed, spec.Host)
	}

	rule, err := p.findRule(spec)
	if err != nil {
		return empty, err
	}
	if err := p.checkHeaders(spec); err != nil {
		return empty, err
	}
	if err := checkQuery(spec, rule); err != nil {
		return empty, err
	}
	if spec.Stream && !rule.AllowStream {
		return empty, fmt.Errorf("%w: %q on %q", ErrStreamNotAllowed, spec.Method, spec.Path)
	}

	maxResponseBytes := spec.MaxResponseBytes
	if p.Limits.MaxResponseBytes < maxResponseBytes {
		maxResponseBytes = p.Limits.MaxResponseBytes
	}
	if spec.MaxResponseBytes > p.Limits.MaxResponseBytes {
		return empty, fmt.Errorf("%w: job asks for %d response bytes, policy caps at %d",
			ErrLimitExceeded, spec.MaxResponseBytes, p.Limits.MaxResponseBytes)
	}

	// Resolved on the success path only: a refusal has no policy version to
	// report, and failing to compute the hash is itself a refusal, since a job
	// whose authorising revision cannot be identified must not be executed.
	hash, err := p.Hash()
	if err != nil {
		return empty, err
	}

	return Decision{
		Provider:         p.Provider,
		Rule:             rule,
		Credential:       p.Credential,
		MaxResponseBytes: maxResponseBytes,
		MaxBodyBytes:     p.Limits.MaxBodyBytes,
		PolicyHash:       hash[:],
	}, nil
}

// HostAllowed reports whether the policy admits a host, comparing
// case-insensitively and treating an omitted port as the default HTTPS port.
func (p Policy) HostAllowed(host string) bool {
	for _, allowed := range p.Hosts {
		if hostMatches(allowed, host) {
			return true
		}
	}
	return false
}

// findRule returns the rule admitting the spec's path and method.
//
// The two-pass scan exists to produce a useful error: if a path is known but
// the method is not, "method not allowed" is far more actionable than "path not
// allowed", and the distinction tells a legitimate caller they are one word
// away from a working request rather than entirely outside the policy.
func (p Policy) findRule(spec jobs.Spec) (Rule, error) {
	pathMatched := false
	for _, rule := range p.Rules {
		if !matchPathRule(rule.Path, spec.Path) {
			continue
		}
		pathMatched = true
		if rule.MethodAllowed(spec.Method) {
			return rule, nil
		}
	}
	if pathMatched {
		return Rule{}, fmt.Errorf("%w: %s %s", ErrMethodNotAllowed, spec.Method, spec.Path)
	}
	return Rule{}, fmt.Errorf("%w: %s", ErrPathNotAllowed, spec.Path)
}

// MethodAllowed reports whether a rule permits an HTTP method.
func (r Rule) MethodAllowed(method string) bool {
	for _, allowed := range r.Methods {
		if allowed == method {
			return true
		}
	}
	return false
}

func (p Policy) checkHeaders(spec jobs.Spec) error {
	for _, name := range spec.HeaderNames() {
		if !p.Limits.HeaderAllowed(name) {
			return fmt.Errorf("%w: %q", ErrHeaderNotAllowed, name)
		}
	}
	return nil
}

// HeaderAllowed reports whether a caller may set a header.
func (l Limits) HeaderAllowed(name string) bool {
	for _, allowed := range l.AllowedHeaders {
		if strings.EqualFold(allowed, name) {
			return true
		}
	}
	return false
}

func checkQuery(spec jobs.Spec, rule Rule) error {
	keys, err := parseQueryKeys(spec.Query)
	if err != nil {
		return err
	}
	if rule.AllowAnyQuery {
		return nil
	}
	allowed := make(map[string]bool, len(rule.QueryKeys))
	for _, key := range rule.QueryKeys {
		allowed[key] = true
	}
	for _, key := range keys {
		if !allowed[key] {
			return fmt.Errorf("%w: %q", ErrQueryNotAllowed, key)
		}
	}
	return nil
}

// hostMatches compares a policy host with a requested one.
//
// A bare host and the same host carrying the default HTTPS port are the same
// destination, so they are treated as equal; any other port must match exactly.
// Comparison is case-insensitive because DNS is.
func hostMatches(allowed, requested string) bool {
	normalise := func(host string) string {
		host = strings.ToLower(strings.TrimSpace(host))
		if strings.Contains(host, ":") {
			return host
		}
		return host + ":443"
	}
	return normalise(allowed) == normalise(requested)
}

// matchPathRule reports whether a request path falls under a rule path.
//
// Matching is segment-wise and prefix-scoped: every rule segment must match the
// corresponding request segment, and extra trailing request segments are
// allowed. Matching on segment boundaries rather than raw string prefixes is
// what stops a rule for /v1/chat from also admitting /v1/chat-backdoor.
func matchPathRule(rulePath, requestPath string) bool {
	ruleSegments := strings.Split(strings.TrimPrefix(rulePath, "/"), "/")
	requestSegments := strings.Split(strings.TrimPrefix(requestPath, "/"), "/")

	if len(ruleSegments) > len(requestSegments) {
		return false
	}
	for i, ruleSegment := range ruleSegments {
		requestSegment := requestSegments[i]
		if isPlaceholderSegment(ruleSegment) {
			// A placeholder matches exactly one non-empty segment. Empty would
			// mean a "//" in the path, which is not a real resource.
			if requestSegment == "" {
				return false
			}
			continue
		}
		if ruleSegment != requestSegment {
			return false
		}
	}
	// Trailing segments beyond the rule are allowed, but an empty one means the
	// path ended in a slash. "/v1/chat/" is a different resource from
	// "/v1/chat", and treating them as the same would let a rule reach a
	// directory-style route it was never written to cover.
	for _, extra := range requestSegments[len(ruleSegments):] {
		if extra == "" {
			return false
		}
	}
	return true
}
