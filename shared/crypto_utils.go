package shared

import (
	"crypto/rand"
	"math"
	"strings"
	"time"
)

const (
	initialBackoffDelay = 100 * time.Millisecond
	maxBackoffDelay     = 10 * time.Second
)

// calculateBackoff implements exponential backoff with crypto-secure jitter
func calculateBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return initialBackoffDelay
	}

	// Exponential backoff: 2^(attempt-1) * initialDelay
	delay := min(time.Duration(float64(initialBackoffDelay)*math.Pow(2, float64(attempt-1))), maxBackoffDelay)

	// Add crypto-secure jitter (10% of delay)
	jitter := cryptoJitter(float64(delay) * 0.1)
	return delay + jitter
}

// cryptoJitter generates cryptographically secure random jitter to prevent timing attacks
func cryptoJitter(maxJitter float64) time.Duration {
	if maxJitter <= 0 {
		return 0
	}

	// Generate 8 random bytes for secure jitter calculation
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to zero jitter if crypto/rand fails
		return 0
	}

	// Convert bytes to uint64
	var n uint64
	for i, b := range bytes {
		n |= uint64(b) << (8 * i)
	}

	// Convert to duration: (random / max_uint64) * maxJitter
	ratio := float64(n) / float64(^uint64(0))
	return time.Duration(ratio * maxJitter)
}

// isNonRetryableError determines if an error should not be retried
func isNonRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// List of error patterns that should not be retried
	nonRetryablePatterns := []string{
		"invalid input",
		"unsupported operation",
		"authentication failed",
		"authorization failed",
		"access denied",
		"permission denied",
		"invalid key",
		"key not found",
		"malformed request",
		"bad request",
		"invalid argument",
		"invalid parameter",
	}

	for _, pattern := range nonRetryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// isRetryableError determines if an error is worth retrying
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry non-retryable errors
	if isNonRetryableError(err) {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// List of error patterns that are typically retryable
	retryablePatterns := []string{
		"connection",
		"timeout",
		"temporary",
		"network",
		"unavailable",
		"throttled",
		"rate limit",
		"service temporarily unavailable",
		"internal server error",
		"bad gateway",
		"gateway timeout",
		"circuit breaker",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Default to retryable for unknown errors (conservative approach)
	return true
}

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxAttempts       int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
	JitterPercent     float64
}

// DefaultRetryConfig returns sensible defaults for retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:       5,
		InitialDelay:      initialBackoffDelay,
		MaxDelay:          maxBackoffDelay,
		BackoffMultiplier: 2.0,
		JitterPercent:     10.0,
	}
}

// RetryWithBackoff executes a function with exponential backoff retry logic
func RetryWithBackoff(config *RetryConfig, operation func() error) error {
	if config == nil {
		config = DefaultRetryConfig()
	}

	var lastErr error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Don't retry non-retryable errors
		if !isRetryableError(err) {
			return err
		}

		// Don't wait after last attempt
		if attempt == config.MaxAttempts {
			break
		}

		// Calculate delay with jitter
		delay := calculateBackoff(attempt)
		time.Sleep(delay)
	}

	// Return the last error if all attempts failed
	return lastErr
}
