package shared

import (
	"os"
	"sync"

	"go.uber.org/zap"
)

// TerminationReason represents the reason for session termination
type TerminationReason string

const (
	// Critical cryptographic failures that compromise protocol integrity
	ReasonCryptoTagVerificationFailed  TerminationReason = "crypto_tag_verification_failed"
	ReasonCryptoCommitmentFailed       TerminationReason = "crypto_commitment_verification_failed"
	ReasonCryptoKeyGenerationFailed    TerminationReason = "crypto_key_generation_failed"
	ReasonCryptoTagComputationFailed   TerminationReason = "crypto_tag_computation_failed"
	ReasonCryptoSigningFailed          TerminationReason = "crypto_signing_failed"
	ReasonCryptoStreamGenerationFailed TerminationReason = "crypto_stream_generation_failed"
	ReasonCryptoHMACVerificationFailed TerminationReason = "crypto_hmac_verification_failed"

	// Session state corruption
	ReasonSessionStateCorrupted TerminationReason = "session_state_corrupted"
	ReasonSessionManagerFailure TerminationReason = "session_manager_failure"
	ReasonSessionIDMismatch     TerminationReason = "session_id_mismatch"
	ReasonSessionNotFound       TerminationReason = "session_not_found"

	// Protocol violations - ZERO TOLERANCE
	ReasonMessageParsingFailed  TerminationReason = "message_parsing_failed"
	ReasonUnknownMessageType    TerminationReason = "unknown_message_type"
	ReasonMissingSessionID      TerminationReason = "missing_session_id"
	ReasonProtocolViolation     TerminationReason = "protocol_violation"
	ReasonTooManyProtocolErrors TerminationReason = "too_many_protocol_errors"
	ReasonInvalidMessageOrder   TerminationReason = "invalid_message_order"
	ReasonUnexpectedMessageType TerminationReason = "unexpected_message_type"
	ReasonMissingRequiredData   TerminationReason = "missing_required_data"
	ReasonInvalidDataFormat     TerminationReason = "invalid_data_format"

	// Network and connectivity failures
	ReasonNetworkFailure   TerminationReason = "network_failure"
	ReasonConnectionLost   TerminationReason = "connection_lost"
	ReasonWebSocketFailure TerminationReason = "websocket_failure"

	// Security violations - ZERO TOLERANCE
	ReasonSecurityViolation      TerminationReason = "security_violation"
	ReasonAuthenticationFailed   TerminationReason = "authentication_failed"
	ReasonUnauthorizedAccess     TerminationReason = "unauthorized_access"
	ReasonDataIntegrityViolation TerminationReason = "data_integrity_violation"
	ReasonReplayAttackDetected   TerminationReason = "replay_attack_detected"

	// Operational failures
	ReasonInternalError      TerminationReason = "internal_error"
	ReasonResourceExhaustion TerminationReason = "resource_exhaustion"
	ReasonTimeoutExceeded    TerminationReason = "timeout_exceeded"

	// TEE+MPC Protocol Specific Errors - ZERO TOLERANCE
	ReasonHandshakeVerificationFailed   TerminationReason = "handshake_verification_failed"
	ReasonRequestValidationFailed       TerminationReason = "request_validation_failed"
	ReasonResponseValidationFailed      TerminationReason = "response_validation_failed"
	ReasonTranscriptGenerationFailed    TerminationReason = "transcript_generation_failed"
	ReasonAttestationVerificationFailed TerminationReason = "attestation_verification_failed"
	ReasonRedactionVerificationFailed   TerminationReason = "redaction_verification_failed"
	ReasonTagComputationFailed          TerminationReason = "tag_computation_failed"
	ReasonStreamReconstructionFailed    TerminationReason = "stream_reconstruction_failed"

	// MPC OPRF Protocol Errors - ZERO TOLERANCE
	ReasonOPRFProtocolFailed TerminationReason = "oprf_protocol_failed"

	// Handler errors - ZERO TOLERANCE
	ReasonHandlerFailed TerminationReason = "handler_failed"
)

// TerminationSeverity indicates how critical the termination reason is
type TerminationSeverity int

const (
	// SeverityLow - recoverable errors, log and continue
	SeverityLow TerminationSeverity = iota
	// SeverityMedium - should terminate session but can continue service
	SeverityMedium
	// SeverityHigh - critical security/crypto failure, terminate session immediately
	SeverityHigh
	// SeverityCritical - service-level failure, should shutdown entire service
	SeverityCritical
)

// GetSeverity returns the severity level for a termination reason
func (r TerminationReason) GetSeverity() TerminationSeverity {
	switch r {
	// Critical crypto failures - always high severity
	case ReasonCryptoTagVerificationFailed,
		ReasonCryptoCommitmentFailed,
		ReasonCryptoTagComputationFailed,
		ReasonCryptoSigningFailed,
		ReasonCryptoStreamGenerationFailed,
		ReasonCryptoHMACVerificationFailed:
		return SeverityHigh

	// Key generation failure - critical in enclave mode, medium in dev mode
	case ReasonCryptoKeyGenerationFailed:
		return SeverityCritical

	// Session state corruption - medium severity
	case ReasonSessionStateCorrupted,
		ReasonSessionManagerFailure,
		ReasonSessionIDMismatch,
		ReasonSessionNotFound:
		return SeverityMedium

	// Protocol violations - ZERO TOLERANCE: All protocol violations are high severity
	case ReasonMessageParsingFailed,
		ReasonUnknownMessageType,
		ReasonMissingSessionID,
		ReasonProtocolViolation,
		ReasonInvalidMessageOrder,
		ReasonUnexpectedMessageType,
		ReasonMissingRequiredData,
		ReasonInvalidDataFormat:
		return SeverityHigh

	// Too many protocol errors - high severity (escalated from low)
	case ReasonTooManyProtocolErrors:
		return SeverityHigh

	// Security violations - ZERO TOLERANCE: All security violations are high severity
	case ReasonSecurityViolation,
		ReasonAuthenticationFailed,
		ReasonUnauthorizedAccess,
		ReasonDataIntegrityViolation,
		ReasonReplayAttackDetected:
		return SeverityHigh

	// Network errors - usually low severity unless repeated
	case ReasonNetworkFailure,
		ReasonConnectionLost,
		ReasonWebSocketFailure:
		return SeverityLow

	// Operational failures - medium severity
	case ReasonInternalError,
		ReasonResourceExhaustion,
		ReasonTimeoutExceeded:
		return SeverityMedium

	// TEE+MPC Protocol Specific Errors - ZERO TOLERANCE: All are high severity
	case ReasonHandshakeVerificationFailed,
		ReasonRequestValidationFailed,
		ReasonResponseValidationFailed,
		ReasonTranscriptGenerationFailed,
		ReasonAttestationVerificationFailed,
		ReasonRedactionVerificationFailed,
		ReasonTagComputationFailed,
		ReasonStreamReconstructionFailed,
		ReasonOPRFProtocolFailed,
		ReasonHandlerFailed:
		return SeverityHigh

	default:
		return SeverityMedium
	}
}

// SessionTerminator handles session termination logic
type SessionTerminator struct {
	logger      *Logger
	errorCounts map[string]int // Track error counts per session
	errorMutex  sync.RWMutex
	maxErrors   int // Max protocol errors before termination
}

// NewSessionTerminator creates a new session terminator
func NewSessionTerminator(logger *Logger) *SessionTerminator {
	return &SessionTerminator{
		logger:      logger,
		errorCounts: make(map[string]int),
		maxErrors:   3, // Default: 3 protocol errors before termination
	}
}

// SetMaxErrors sets the maximum number of protocol errors before termination
func (st *SessionTerminator) SetMaxErrors(max int) {
	st.maxErrors = max
}

// ShouldTerminate determines if a session should be terminated based on the error
func (st *SessionTerminator) ShouldTerminate(sessionID string, reason TerminationReason, err error) bool {
	severity := reason.GetSeverity()

	// For critical severity (e.g., crypto key generation failure in enclave mode),
	// terminate the entire process to maintain TEE security guarantees
	if severity == SeverityCritical {
		st.logger.Critical("Critical cryptographic failure detected - terminating process",
			zap.String("session_id", sessionID),
			zap.String("reason", string(reason)),
			zap.String("severity", "critical"),
			zap.Error(err))

		// In TEE environments, critical crypto failures must terminate the entire process
		// to prevent potential security breaches or compromised cryptographic state
		os.Exit(1)
	}

	// ZERO TOLERANCE POLICY: Always terminate for high severity (protocol violations, security violations, crypto failures)
	if severity == SeverityHigh {
		st.logger.SessionTerminated(sessionID, string(reason),
			zap.String("severity", "high"),
			zap.String("policy", "zero_tolerance"),
			zap.Error(err))
		return true
	}

	// For medium severity, terminate immediately
	if severity == SeverityMedium {
		st.logger.SessionTerminated(sessionID, string(reason),
			zap.String("severity", "medium"),
			zap.Error(err))
		return true
	}

	// For low severity (network errors), track error count and terminate if threshold exceeded
	if severity == SeverityLow {
		st.errorMutex.Lock()
		st.errorCounts[sessionID]++
		count := st.errorCounts[sessionID]
		st.errorMutex.Unlock()

		if count >= st.maxErrors {
			st.logger.SessionTerminated(sessionID, string(ReasonTooManyProtocolErrors),
				zap.String("severity", "escalated"),
				zap.Int("error_count", count),
				zap.String("original_reason", string(reason)),
				zap.Error(err))
			return true
		}

		// Log the error but don't terminate yet
		st.logger.WithSession(sessionID).Warn("Network error (counted)",
			zap.String("reason", string(reason)),
			zap.Int("count", count),
			zap.Int("max_errors", st.maxErrors),
			zap.Error(err))
		return false
	}

	return false
}

// CleanupSession removes error tracking for a session
func (st *SessionTerminator) CleanupSession(sessionID string) {
	st.errorMutex.Lock()
	delete(st.errorCounts, sessionID)
	st.errorMutex.Unlock()
}

// GetErrorCount returns the current error count for a session
func (st *SessionTerminator) GetErrorCount(sessionID string) int {
	st.errorMutex.RLock()
	count := st.errorCounts[sessionID]
	st.errorMutex.RUnlock()
	return count
}

// CriticalError logs a critical error and returns true if it should terminate the session
func (st *SessionTerminator) CriticalError(sessionID string, reason TerminationReason, err error, fields ...zap.Field) bool {
	allFields := append(fields,
		zap.String("session_id", sessionID),
		zap.String("reason", string(reason)),
		zap.Error(err))

	st.logger.Critical("Critical error occurred", allFields...)
	return st.ShouldTerminate(sessionID, reason, err)
}

// SecurityViolation logs a security violation and returns true if it should terminate the session
func (st *SessionTerminator) SecurityViolation(sessionID string, reason TerminationReason, err error, fields ...zap.Field) bool {
	allFields := append(fields,
		zap.String("session_id", sessionID),
		zap.String("reason", string(reason)),
		zap.String("policy", "zero_tolerance"),
		zap.Error(err))

	st.logger.Security("Security violation detected - terminating session", allFields...)
	return st.ShouldTerminate(sessionID, reason, err)
}

// ProtocolError logs a protocol error and returns true if it should terminate the session
func (st *SessionTerminator) ProtocolError(sessionID string, reason TerminationReason, err error, fields ...zap.Field) bool {
	allFields := append(fields,
		zap.String("session_id", sessionID),
		zap.String("reason", string(reason)),
		zap.Error(err))

	if st.ShouldTerminate(sessionID, reason, err) {
		return true
	}

	// If not terminating, log as warning
	st.logger.WithSession(sessionID).Warn("Protocol error",
		append(allFields, zap.Bool("session_continuing", true))...)
	return false
}

// Helper functions for common error patterns

// IsCryptoError checks if the termination reason is related to cryptographic operations
func (r TerminationReason) IsCryptoError() bool {
	switch r {
	case ReasonCryptoTagVerificationFailed,
		ReasonCryptoCommitmentFailed,
		ReasonCryptoKeyGenerationFailed,
		ReasonCryptoTagComputationFailed,
		ReasonCryptoSigningFailed,
		ReasonCryptoStreamGenerationFailed,
		ReasonCryptoHMACVerificationFailed:
		return true
	default:
		return false
	}
}

// IsSessionError checks if the termination reason is related to session management
func (r TerminationReason) IsSessionError() bool {
	switch r {
	case ReasonSessionStateCorrupted,
		ReasonSessionManagerFailure,
		ReasonSessionIDMismatch,
		ReasonSessionNotFound:
		return true
	default:
		return false
	}
}

// IsSecurityError checks if the termination reason is related to security
func (r TerminationReason) IsSecurityError() bool {
	switch r {
	case ReasonSecurityViolation,
		ReasonAuthenticationFailed,
		ReasonUnauthorizedAccess:
		return true
	default:
		return false
	}
}

// IsProtocolError checks if the termination reason is related to protocol violations
func (r TerminationReason) IsProtocolError() bool {
	switch r {
	case ReasonMessageParsingFailed,
		ReasonUnknownMessageType,
		ReasonMissingSessionID,
		ReasonProtocolViolation,
		ReasonInvalidMessageOrder,
		ReasonUnexpectedMessageType,
		ReasonMissingRequiredData,
		ReasonInvalidDataFormat,
		ReasonTooManyProtocolErrors:
		return true
	default:
		return false
	}
}

// IsTEEProtocolError checks if the termination reason is related to TEE+MPC protocol violations
func (r TerminationReason) IsTEEProtocolError() bool {
	switch r {
	case ReasonHandshakeVerificationFailed,
		ReasonRequestValidationFailed,
		ReasonResponseValidationFailed,
		ReasonTranscriptGenerationFailed,
		ReasonAttestationVerificationFailed,
		ReasonRedactionVerificationFailed,
		ReasonTagComputationFailed,
		ReasonStreamReconstructionFailed,
		ReasonOPRFProtocolFailed:
		return true
	default:
		return false
	}
}

// ZeroToleranceError logs a zero-tolerance error and always terminates the session
func (st *SessionTerminator) ZeroToleranceError(sessionID string, reason TerminationReason, err error, fields ...zap.Field) bool {
	allFields := append(fields,
		zap.String("session_id", sessionID),
		zap.String("reason", string(reason)),
		zap.String("policy", "zero_tolerance"),
		zap.Error(err))

	st.logger.Critical("Zero-tolerance policy violation - terminating session", allFields...)
	return st.ShouldTerminate(sessionID, reason, err)
}

// ProtocolViolation logs a protocol violation and always terminates the session
func (st *SessionTerminator) ProtocolViolation(sessionID string, reason TerminationReason, err error, fields ...zap.Field) bool {
	allFields := append(fields,
		zap.String("session_id", sessionID),
		zap.String("reason", string(reason)),
		zap.String("policy", "zero_tolerance"),
		zap.Error(err))

	st.logger.Security("Protocol violation detected - terminating session", allFields...)
	return st.ShouldTerminate(sessionID, reason, err)
}
