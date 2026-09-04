package tee

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidSecret means a resolved credential is structurally unusable: an
// empty token behind a declared header, an unsafe header name, or control
// characters that could smuggle a header line. Such a credential must never
// reach the wire — it is validated as the envelope is opened, before the
// request is sent.
var ErrInvalidSecret = errors.New("invalid credential secret")

// Secret is everything the TEE needs to authenticate one provider's upstream
// request: the token itself plus the header it is presented in. It arrives on
// every job inside spec.Credential — sealed to the TEE's inbox key by the
// provider's agent, relayed as ciphertext by the Hub, decrypted here per
// request — and never lives in the TEE between jobs.
//
// The three fields cover every major AI service's auth shape:
//
//   - OpenAI and most others: Header "authorization", Scheme "Bearer" →
//     "Authorization: Bearer <token>".
//   - Anthropic:              Header "x-api-key", Scheme "" →
//     "x-api-key: <token>".
//   - Anything custom:        any header name, optional scheme prefix.
//
// A zero Secret (empty header, token, scheme) means the provider needs no
// authentication: nothing is injected. A declared header with an empty token
// is invalid — a header that would carry nothing is a misconfiguration, and
// silently sending it would make a later 401 look like a provider problem.
type Secret struct {
	// Token is the raw credential value (e.g. the API key).
	Token string
	// Header names the request header the token is placed in, e.g.
	// "authorization" or "x-api-key". Empty means no authentication.
	Header string
	// Scheme is a prefix such as "Bearer". Empty means the token is the whole
	// header value (e.g. Anthropic's "x-api-key").
	Scheme string
}

// Validate checks the shape of a credential secret. It runs inside the TEE as
// an envelope is opened, so an unsafe header can never reach the wire.
func (s Secret) Validate() error {
	if s.Header == "" {
		if s.Token != "" || s.Scheme != "" {
			return fmt.Errorf("%w: token or scheme without a header", ErrInvalidSecret)
		}
		return nil // no authentication
	}
	if !isHeaderToken(s.Header) {
		return fmt.Errorf("%w: %q is not a valid header name", ErrInvalidSecret, s.Header)
	}
	if isReservedInjectionHeader(s.Header) {
		return fmt.Errorf("%w: %q must not be injected", ErrInvalidSecret, s.Header)
	}
	if s.Scheme != "" && !isHeaderToken(s.Scheme) {
		return fmt.Errorf("%w: %q is not a valid scheme", ErrInvalidSecret, s.Scheme)
	}
	if s.Token == "" {
		return fmt.Errorf("%w: empty token behind header %q", ErrInvalidSecret, s.Header)
	}
	if err := validateTokenValue(s.Token); err != nil {
		return err
	}
	return nil
}

// Render returns the header name and value to put on the wire.
func (s Secret) Render() (string, string, error) {
	if err := s.Validate(); err != nil {
		return "", "", err
	}
	if s.Scheme == "" {
		return s.Header, s.Token, nil
	}
	return s.Header, s.Scheme + " " + s.Token, nil
}

// validateTokenValue rejects a token that could tamper with the request
// framing: control characters would smuggle a header line, and surrounding
// whitespace would change the header value the upstream parses.
func validateTokenValue(token string) error {
	if strings.ContainsAny(token, "\r\n\x00") {
		return fmt.Errorf("%w: token contains a control character", ErrInvalidSecret)
	}
	if strings.TrimSpace(token) != token {
		return fmt.Errorf("%w: token has surrounding whitespace", ErrInvalidSecret)
	}
	return nil
}

// reservedInjectionHeaders are headers a secret must never be injected into.
// They either describe the framing the TEE itself controls (host,
// content-length, transfer-encoding, connection, upgrade, te) or they change
// how the proxy-hop is interpreted (proxy-authorization, trailer). The
// regular job headers the caller may set are a separate list enforced by jobs;
// this list only bounds the credential's own placement.
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

func isHeaderToken(s string) bool {
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
