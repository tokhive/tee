package shared

// MaxWebSocketMessageSize is the repository-wide WebSocket read ceiling.
// Existing TEE endpoints use 30 MiB so that 100,000-OT KOS initialization,
// online garbled-circuit payloads, attestations, and batched TLS messages fit.
const MaxWebSocketMessageSize = 30 * 1024 * 1024
