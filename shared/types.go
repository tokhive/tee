package shared

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Control connection liveness parameters. Both TEE_K and TEE_T use these to
// detect a dead peer via bidirectional WebSocket ping/pong on the long-lived
// control channel. ControlPingPeriod must be less than ControlPongWait.
const (
	ControlPongWait   = 30 * time.Second
	ControlPingPeriod = (ControlPongWait * 9) / 10
	ControlWriteWait  = 10 * time.Second
)

// Connection abstraction for WebSocket connections
type Connection interface {
	Close() error
	RemoteAddr() string
}

// WebSocket connection adapter
type WSConnection struct {
	conn  *websocket.Conn
	mutex sync.Mutex
}

func NewWSConnection(conn *websocket.Conn) *WSConnection {
	return &WSConnection{conn: conn}
}

func (w *WSConnection) Close() error {
	return w.conn.Close()
}

func (w *WSConnection) RemoteAddr() string {
	return w.conn.RemoteAddr().String()
}

// GetWebSocketConn returns the underlying websocket.Conn for compatibility
func (w *WSConnection) GetWebSocketConn() *websocket.Conn {
	return w.conn
}

// WSWriteDeadline bounds how long a single WriteMessage may block before
// returning. Sized for mobile networks (radio handoff can pause writes
// for seconds) — anything beyond this is a wedged consumer, not a slow link.
const WSWriteDeadline = 30 * time.Second

// WriteWSBinary calls conn.WriteMessage with WSWriteDeadline applied.
// Callers MUST still hold their own write mutex for concurrent-write safety
// (gorilla/websocket panics on concurrent writes). The helper only bundles
// the deadline so we can't forget it at a call site.
func WriteWSBinary(conn *websocket.Conn, data []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(WSWriteDeadline)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// WriteMessage writes a message to the WebSocket connection with thread safety
// and a write deadline that prevents a slow/dead peer from blocking the writer
// goroutine forever (which would hold session locks indefinitely).
func (w *WSConnection) WriteMessage(messageType int, data []byte) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if err := w.conn.SetWriteDeadline(time.Now().Add(WSWriteDeadline)); err != nil {
		return err
	}
	return w.conn.WriteMessage(messageType, data)
}

// ReadMessage reads a message from the WebSocket connection
// Note: Reading does not require mutex protection as WebSocket reads are typically
// done by a single goroutine, but write synchronization is handled by WriteMessage
func (w *WSConnection) ReadMessage() (messageType int, p []byte, err error) {
	return w.conn.ReadMessage()
}

// SetReadDeadline sets the read deadline on the underlying connection
func (w *WSConnection) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

// StartControlHeartbeat wires bidirectional WebSocket ping/pong on a long-lived
// control connection so each side can detect a dead peer. It sets an initial
// read deadline, installs Ping/Pong handlers that refresh the deadline on every
// inbound control frame, and launches a goroutine that emits a PingMessage every
// ControlPingPeriod. The goroutine exits when WriteControl fails (e.g., when
// the connection is closed), so it is safe to call once per established
// connection without explicit teardown.
func (w *WSConnection) StartControlHeartbeat(logger *Logger) {
	conn := w.conn
	_ = conn.SetReadDeadline(time.Now().Add(ControlPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(ControlPongWait))
	})
	conn.SetPingHandler(func(message string) error {
		_ = conn.SetReadDeadline(time.Now().Add(ControlPongWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(ControlWriteWait))
		if err == websocket.ErrCloseSent {
			return nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		return err
	})
	go func() {
		ticker := time.NewTicker(ControlPingPeriod)
		defer ticker.Stop()
		for range ticker.C {
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(ControlWriteWait)); err != nil {
				if logger != nil {
					logger.Debug("Control heartbeat ping failed, exiting", zap.Error(err))
				}
				return
			}
		}
	}()
}

// Message types for websocket communication
type MessageType string

const (
	// Client to TEE_K messages
	MsgRequestConnection MessageType = "request_connection"
	MsgTCPData           MessageType = "tcp_data"
	MsgTCPReady          MessageType = "tcp_ready"

	// TEE_K to Client messages
	MsgConnectionReady   MessageType = "connection_ready"
	MsgSendTCPData       MessageType = "send_tcp_data"
	MsgHandshakeComplete MessageType = "handshake_complete"

	// Phase 2: Split AEAD messages
	// TEE_K to TEE_T messages
	MsgKeyShareRequest MessageType = "key_share_request"

	// Phase 3: Client to TEE_T messages
	MsgRedactedRequest MessageType = "redacted_request"

	// Session management messages
	MsgSessionCreated MessageType = "session_created"
	MsgSessionReady   MessageType = "session_ready"

	// Additional message types
	MsgError            MessageType = "error"
	MsgRedactionStreams MessageType = "redaction_streams"

	// Single Session Mode message types
	MsgFinished      MessageType = "finished"
	MsgRedactionSpec MessageType = "redaction_spec"
)

const (
	MsgBatchedEncryptedResponses MessageType = "batched_encrypted_responses"
	MsgBatchedResponseLengths    MessageType = "batched_response_lengths"
	MsgBatchedTagSecrets         MessageType = "batched_tag_secrets"
	MsgBatchedTagVerifications   MessageType = "batched_tag_verifications"
	MsgBatchedDecryptionStreams  MessageType = "batched_decryption_streams"
	MsgBatchedEncryptedRequest   MessageType = "batched_encrypted_request"
	MsgBatchedTLSRecords         MessageType = "batched_tls_records"
)

// Message represents a protocol message with session context
type Message struct {
	Type      MessageType `json:"type"`
	SessionID string      `json:"session_id,omitempty"`
	Data      any         `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// UnmarshalData unmarshals the Data field into the provided interface
func (m *Message) UnmarshalData(v any) error {
	if v == nil {
		return fmt.Errorf("nil destination")
	}
	if m == nil {
		return fmt.Errorf("nil message")
	}
	// Fast-path: if Data is nil
	if m.Data == nil {
		return fmt.Errorf("no data in message")
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("destination must be non-nil pointer")
	}
	dv := reflect.ValueOf(m.Data)
	// Allow assignment when types match or are assignable
	if dv.Type().AssignableTo(rv.Elem().Type()) {
		rv.Elem().Set(dv)
		return nil
	}
	return fmt.Errorf("type mismatch: cannot assign %s to %s", dv.Type().String(), rv.Elem().Type().String())
}

// SessionState represents the current state of a session
type SessionState string

const (
	SessionStateNew    SessionState = "new"
	SessionStateActive SessionState = "active"
	SessionStateClosed SessionState = "closed"
)

// OPRFSessionState represents the state of MPC OPRF processing for a session
type OPRFSessionState int32

const (
	OPRFStateNone       OPRFSessionState = 0
	OPRFStateInProgress OPRFSessionState = 1
	OPRFStateComplete   OPRFSessionState = 2
	OPRFStateFailed     OPRFSessionState = 3
)

func (s OPRFSessionState) String() string {
	switch s {
	case OPRFStateNone:
		return ""
	case OPRFStateInProgress:
		return "in_progress"
	case OPRFStateComplete:
		return "complete"
	case OPRFStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// MPC OPRF error reasons
const (
	ReasonOPRFEvaluationFailed = "oprf_evaluation_failed"
)

// Input size limits to prevent memory exhaustion attacks
const (
	MaxRedactionRanges         = 1000
	MaxHTTPRequestSize         = 1 * 1024 * 1024
	MaxEncryptedFragments      = 500
	MaxResponseRedactionRanges = 1000
	MaxOPRFRangesPerSession    = 20
)

// OPRFResult holds the result of MPC OPRF computation for a single range
type OPRFResult struct {
	RangeIndex int      // Index in the OPRFRanges slice
	TLSStart   int      // Start position in TLS stream
	TLSLength  int      // Length in TLS stream
	CMACOutput [16]byte // 16-byte AES-CMAC output
	HashOutput [32]byte // 32-byte SHA256(CMAC) output
}

// FinalSignatureState is the one-way lifecycle of the final TEE_K output.
// A failed in-progress attempt is intentionally not retryable: the owning
// session must terminate because the client-write outcome can be ambiguous.
type FinalSignatureState uint32

const (
	FinalSignaturePending FinalSignatureState = iota
	FinalSignatureInProgress
	FinalSignatureSent
)

// Session represents a complete client session across both TEE_K and TEE_T
type Session struct {
	ID           string
	ClientConn   Connection
	TEEKConn     Connection
	TEETConn     Connection   // Per-session connection to TEE_T
	ConnMutex    sync.RWMutex // Protects connection field assignments
	CreatedAt    time.Time
	LastActiveAt time.Time
	State        SessionState

	// Protocol state per session
	RedactionState *RedactionSessionState
	ResponseState  *ResponseSessionState
	ConnectionData *RequestConnectionData // Store connection request data

	// Per-session transcript storage
	TranscriptData      [][]byte   `json:"-"` // Collect all data for transcript signing
	TranscriptDataTypes []string   `json:"-"` // Parallel slice describing data types
	TranscriptMutex     sync.Mutex // Protect transcript collection

	// Per-session finished state tracking
	TEEKFinished       bool       // Whether TEE_K has sent finished message
	FinishedStateMutex sync.Mutex // Protect finished state

	// Master signature generation
	RedactedStreams               []SignedRedactedDecryptionStream `json:"-"` // Collect streams for master signature
	ConsolidatedResponseKeystream []byte                           `json:"-"` // Consolidated response keystream for simplified verification
	CertificateInfo               *teeproto.CertificateInfo        `json:"-"` // Structured certificate data
	RedactionProcessingComplete   bool                             `json:"-"` // Flag to track when redaction processing is complete
	finalSignatureState           atomic.Uint32                    // Pending -> InProgress -> Sent; failure terminates the session
	StreamsMutex                  sync.Mutex                       // Protect streams collection

	// Cache for original decryption streams to avoid regeneration during redaction
	CachedDecryptionStreams map[uint64][]byte `json:"-"` // Cache original streams by seqNum for redaction reuse

	// Connection management
	IsClosed bool
	Context  context.Context
	Cancel   context.CancelFunc

	// CAS guard: only the cleanupSession caller that flips this owns the
	// activeSessions decrement. Lives here, not on per-TEE state structs.
	CleanedUp atomic.Bool
}

func (s *Session) TryBeginFinalSignature() bool {
	return s != nil && s.finalSignatureState.CompareAndSwap(uint32(FinalSignaturePending), uint32(FinalSignatureInProgress))
}

func (s *Session) MarkFinalSignatureSent() bool {
	return s != nil && s.finalSignatureState.CompareAndSwap(uint32(FinalSignatureInProgress), uint32(FinalSignatureSent))
}

func (s *Session) FinalSignatureStatus() FinalSignatureState {
	if s == nil {
		return FinalSignaturePending
	}
	return FinalSignatureState(s.finalSignatureState.Load())
}

// RedactionSessionState holds redaction-specific state for each session.
//
// Streams arrive from the client; ranges arrive from TEE_K. Those two
// paths run on different goroutines and may write concurrently before
// the counter-at-join barrier (RequestPartsArrived hitting 2). Reads
// that happen AFTER the join are race-free via the counter's
// happens-before edge; the mutex guards the setters' publish.
type RedactionSessionState struct {
	mu                    sync.Mutex
	Ranges                []RequestRedactionRange
	EncryptedRequestData  []EncryptedRequestData
	EncryptedResponseData []EncryptedResponseData
	RedactionStreams      [][]byte
}

// SetStreams stores client-supplied redaction streams. Called by
// handleRedactionStreams before the counter-at-join barrier.
func (r *RedactionSessionState) SetStreams(streams [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.RedactionStreams = streams
}

// SetRanges stores TEE_K-supplied ranges. Called by
// handleBatchedEncryptedRequest before the counter-at-join barrier.
func (r *RedactionSessionState) SetRanges(ranges []RequestRedactionRange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Ranges = ranges
}

// ResponseSessionState holds response handling state for each session
type ResponseSessionState struct {
	PendingResponses    map[string][]byte
	ResponseSequence    int
	LastResponseTime    time.Time
	ResponseLengthBySeq map[uint64]int

	// Per-session pending encrypted responses
	PendingEncryptedResponses map[uint64]*EncryptedResponseData // Responses awaiting tag secrets by seq num
	ResponsesMutex            sync.Mutex                        // Protects PendingEncryptedResponses map access

	// Additional response state migrated from global state
	ExplicitIVBySeq map[uint64][]byte
	NonceBySeq      map[uint64][]byte // Full nonces computed by GenerateDecryptionStream

	// Response redaction ranges for transcript signature
	ResponseRedactionRanges []ResponseRedactionRange `json:"response_redaction_ranges,omitempty"`
}

// Protocol data structures

// Request redaction type constants
const (
	RedactionTypeSensitive      = "sensitive"       // R_S: Sensitive data not used in proofs
	RedactionTypeSensitiveProof = "sensitive_proof" // R_SP: Sensitive data used in proofs
)

// RequestRedactionRange is used for request redaction (needs types for proof verification)
type RequestRedactionRange struct {
	Start  int    `json:"start"`  // Start position in the decryption stream
	Length int    `json:"length"` // Length of the range to redact
	Type   string `json:"type"`   // Use RedactionTypeSensitive or RedactionTypeSensitiveProof
}

// ResponseRedactionRange is used for response redaction (no types needed - binary redaction)
type ResponseRedactionRange struct {
	Start  int    `json:"start"`          // Start position in the decryption stream
	Length int    `json:"length"`         // Length of the range to redact
	Hash   string `json:"hash,omitempty"` // whether to replace redacted data with a hash
}

// ConsolidateResponseRedactionRanges merges consecutive or overlapping redaction ranges
func ConsolidateResponseRedactionRanges(ranges []ResponseRedactionRange) []ResponseRedactionRange {
	// // TEMPORARILY DISABLE CONSOLIDATION to debug OPRF positioning issues
	// // Consolidation might be merging OPRF ranges with adjacent ranges,
	// // causing OPRF replacement to happen at wrong positions
	// return ranges

	// Original consolidation code commented out for debugging:

	if len(ranges) == 0 {
		return ranges
	}

	// Sort by start position
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].Start < ranges[j].Start
	})

	var consolidated []ResponseRedactionRange
	current := ranges[0]

	for i := 1; i < len(ranges); i++ {
		next := ranges[i]
		// Only merge ranges if they have the same hash type (or both empty)
		// Different hash types should NOT be consolidated to preserve OPRF ranges
		canMerge := current.Hash == next.Hash && current.Start+current.Length >= next.Start

		if canMerge {
			current.Length = max(current.Start+current.Length, next.Start+next.Length) - current.Start
		} else {
			consolidated = append(consolidated, current)
			current = next
		}
	}
	consolidated = append(consolidated, current)

	return consolidated

}

// Client to TEE_K: Request to establish connection
type RequestConnectionData struct {
	Hostname         string   `json:"hostname"`
	Port             int      `json:"port"`
	SNI              string   `json:"sni"`
	ALPN             []string `json:"alpn"`
	ForceTLSVersion  string   `json:"force_tls_version,omitempty"`  // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite string   `json:"force_cipher_suite,omitempty"` // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
	SupportsTLS12CBC bool     `json:"supports_tls12_cbc,omitempty"` // Absent/false preserves the pre-CBC negotiation surface.
}

// TEE_K to Client: Connection is ready
type ConnectionReadyData struct {
	Success bool `json:"success"`
}

// Client to TEE_K: TCP connection established
type TCPReadyData struct {
	Success bool `json:"success"`
}

// Bidirectional: TCP data transfer
type TCPData struct {
	Data []byte `json:"data"`
}

// TEE_K to Client: TLS handshake completed
type HandshakeCompleteData struct {
	Success          bool                             `json:"success"`
	CertificateChain [][]byte                         `json:"certificate_chain"`
	CipherSuite      uint16                           `json:"cipher_suite"` // Negotiated cipher suite
	TLS12CBCBinding  *teeproto.TLS12CBCSessionBinding `json:"-"`
}

// TEE_K to Client: Handshake key disclosure for certificate verification
type HandshakeKeyDisclosureData struct {
	HandshakeKey      []byte `json:"handshake_key"`      // Server handshake traffic secret
	HandshakeIV       []byte `json:"handshake_iv"`       // Server handshake IV
	CertificatePacket []byte `json:"certificate_packet"` // Raw encrypted certificate packet
	CipherSuite       uint16 `json:"cipher_suite"`       // TLS cipher suite (e.g., 0x1302 for TLS_AES_256_GCM_SHA384)
	Algorithm         string `json:"algorithm"`          // Algorithm name (e.g., "AES-256-GCM", "ChaCha20-Poly1305")
	Success           bool   `json:"success"`
}

// Error message
type ErrorData struct {
	Message string `json:"message"`
}

// TEE_K to TEE_T: Request key share for split AEAD
type KeyShareRequestData struct {
	KeyLength int `json:"key_length"`
	IVLength  int `json:"iv_length"`
}

// TEE_T to TEE_K: Response with key share
type KeyShareResponseData struct {
	KeyShare []byte `json:"key_share"`
	Success  bool   `json:"success"`
}

// TEE_T to Client: Send encrypted data with authentication tag
type EncryptedDataResponse struct {
	EncryptedData []byte `json:"encrypted_data"` // R_Enc
	AuthTag       []byte `json:"auth_tag"`       // Authentication tag T
	Success       bool   `json:"success"`
}

// Client to TEE_K: Send plaintext data for encryption
type PlaintextData struct {
	Data []byte `json:"data"`
}

// RedactedRequestData contains the redacted request and associated metadata
type RedactedRequestData struct {
	RedactedRequest []byte                  `json:"redacted_request"` // R_red
	RedactionRanges []RequestRedactionRange `json:"redaction_ranges"` // Position metadata
}

// RedactionStreamsData contains the XOR streams for revelation. Ranges are
// NOT carried here — TEE_T uses the authoritative ranges TEE_K validated in
// BatchedEncryptedRequest, not whatever the client claims separately.
type RedactionStreamsData struct {
	Streams [][]byte `json:"streams"` // [Str_S, Str_SP]
}

// DecryptedResponseData contains decrypted response data
type DecryptedResponseData struct {
	PlaintextData []byte `json:"plaintext_data"` // Decrypted response data
	SeqNum        uint64 `json:"seq_num"`        // TLS sequence number for AEAD
	Success       bool   `json:"success"`        // Whether decryption was successful
}

// Session-ready data structure
type SessionReadyData struct {
	SessionID string `json:"session_id"`
	Ready     bool   `json:"ready"`
}

type EncryptedRequestData struct {
	EncryptedData   []byte                  `json:"encrypted_data"` // R_red_Enc
	TagSecrets      []byte                  `json:"tag_secrets"`    // Data needed for tag computation
	CipherSuite     uint16                  `json:"cipher_suite"`
	SeqNum          uint64                  `json:"seq_num"`          // Sequence number for AEAD
	RedactionRanges []RequestRedactionRange `json:"redaction_ranges"` // Redaction position metadata for stream application
}

type EncryptedResponseData struct {
	EncryptedData []byte `json:"encrypted_data"`        // Raw TLS record payload (encrypted data + tag)
	Tag           []byte `json:"tag"`                   // Authentication tag extracted from TLS record
	RecordHeader  []byte `json:"record_header"`         // Actual TLS record header used by server (5 bytes)
	SeqNum        uint64 `json:"seq_num"`               // TLS sequence number for AEAD
	ExplicitIV    []byte `json:"explicit_iv,omitempty"` // TLS 1.2 AES-GCM explicit IV (8 bytes, nil for TLS 1.3)
}

// ResponseTagVerificationData contains result of tag verification by TEE_T
type ResponseTagVerificationData struct {
	Success bool   `json:"success"` // Whether tag verification passed
	SeqNum  uint64 `json:"seq_num"` // TLS sequence number for AEAD
	Message string `json:"message"` // Optional error message
}

// ResponseDecryptionStreamData contains AES-CTR decryption stream from TEE_K
type ResponseDecryptionStreamData struct {
	DecryptionStream []byte `json:"decryption_stream"` // AES-CTR keystream for XOR decryption
	SeqNum           uint64 `json:"seq_num"`           // TLS sequence number for AEAD
	Length           int    `json:"length"`            // Length of encrypted data to decrypt
}

// Single Session Mode data structures

// FinishedMessage represents a finished message from any party
type FinishedMessage struct {
}

// SignedTranscript represents a signed transcript with consolidated data, signature, and public key
type SignedTranscript struct {
	Data [][]byte `json:"data"` // Consolidated streams (keystream/ciphertext data)

	// Request metadata (formerly included in packets for TEE_K)
	RequestMetadata *RequestMetadata `json:"request_metadata,omitempty"`

	// Response redaction ranges for verifier display
	ResponseRedactionRanges []ResponseRedactionRange `json:"response_redaction_ranges,omitempty"`

	Signature  []byte `json:"signature"`   // Comprehensive signature over all data (consolidated streams + metadata)
	EthAddress []byte `json:"eth_address"` // ETH address (20 bytes)
}

// Transcript data type constants – exported so both client and TEEs can reference them.
const (
	TranscriptDataTypeTLSRecord           = "tls_record"
	TranscriptDataTypeHTTPRequestRedacted = "http_request_redacted"
)

// RequestRedactionSpec specifies which parts of the request should be redacted
type RequestRedactionSpec struct {
	Ranges []RequestRedactionRange `json:"ranges"` // Request redaction ranges with types
}

// ResponseRedactionSpec specifies which parts of the response should be redacted
type ResponseRedactionSpec struct {
	Ranges []ResponseRedactionRange `json:"ranges"` // Response redaction ranges (no types needed)
}

// SignedRedactedDecryptionStream represents a redacted decryption stream
type SignedRedactedDecryptionStream struct {
	RedactedStream []byte `json:"redacted_stream"` // Decryption stream with "*" for redacted parts
	SeqNum         uint64 `json:"seq_num"`         // TLS sequence number
}

// BatchedEncryptedResponseData contains multiple encrypted response packets for batch processing
type BatchedEncryptedResponseData struct {
	Responses  []EncryptedResponseData `json:"responses"`   // Array of individual encrypted responses
	SessionID  string                  `json:"session_id"`  // Session identifier
	TotalCount int                     `json:"total_count"` // Total number of responses in batch
}

// BatchedResponseLengthData contains multiple response lengths for batch processing
type BatchedResponseLengthData struct {
	Lengths []struct {
		Length       int    `json:"length"`                // Length of encrypted response data (without tag)
		RecordHeader []byte `json:"record_header"`         // Actual TLS record header used by server (5 bytes)
		SeqNum       uint64 `json:"seq_num"`               // TLS sequence number for AEAD
		ExplicitIV   []byte `json:"explicit_iv,omitempty"` // TLS 1.2 AES-GCM explicit IV (8 bytes, nil for TLS 1.3)
	} `json:"lengths"` // Array of individual response lengths
	SessionID  string `json:"session_id"`  // Session identifier
	TotalCount int    `json:"total_count"` // Total number of lengths in batch
}

// BatchedTagSecretsData contains multiple tag secrets for batch processing
type BatchedTagSecretsData struct {
	TagSecrets []struct {
		TagSecrets []byte `json:"tag_secrets"` // E_K(0^128) and E_K(nonce||1) for GCM
		SeqNum     uint64 `json:"seq_num"`     // TLS sequence number for AEAD
	} `json:"tag_secrets"` // Array of individual tag secrets
	SessionID  string `json:"session_id"`  // Session identifier
	TotalCount int    `json:"total_count"` // Total number of tag secrets in batch
}

// BatchedTagVerificationData contains multiple tag verification results for batch processing
type BatchedTagVerificationData struct {
	Verifications []ResponseTagVerificationData `json:"verifications"`  // Array of verification results
	SessionID     string                        `json:"session_id"`     // Session identifier
	TotalCount    int                           `json:"total_count"`    // Total number of verifications in batch
	AllSuccessful bool                          `json:"all_successful"` // True if all verifications passed
}

// BatchedDecryptionStreamData contains multiple decryption streams for batch processing
type BatchedDecryptionStreamData struct {
	DecryptionStreams []ResponseDecryptionStreamData `json:"decryption_streams"` // Array of decryption streams
	SessionID         string                         `json:"session_id"`         // Session identifier
	TotalCount        int                            `json:"total_count"`        // Total number of streams in batch
}

// BatchedSignedRedactedDecryptionStreamData contains multiple signed redacted decryption streams for batch processing
type BatchedSignedRedactedDecryptionStreamData struct {
	SignedRedactedStreams []SignedRedactedDecryptionStream `json:"signed_redacted_streams"` // Array of signed redacted decryption streams
	SessionID             string                           `json:"session_id"`              // Session identifier
	TotalCount            int                              `json:"total_count"`             // Total number of streams in batch
}

// SignedTranscriptWithStreams combines SignedTranscript and SignedRedactedStreams for efficient TEE_K messaging
type SignedTranscriptWithStreams struct {
	SignedTranscript                                       // Embed the existing SignedTranscript structure
	SignedRedactedStreams []SignedRedactedDecryptionStream `json:"signed_redacted_streams,omitempty"` // Optional redacted streams
	TotalStreamsCount     int                              `json:"total_streams_count"`               // Total number of streams included
}

// BatchedEncryptedRequestData contains multiple encrypted request fragments for batch processing
type BatchedEncryptedRequestData struct {
	Fragments   []EncryptedRequestData `json:"fragments"`    // Array of encrypted request fragments
	BaseSeqNum  uint64                 `json:"base_seq_num"` // Starting sequence number for fragments
	CipherSuite uint16                 `json:"cipher_suite"` // TLS cipher suite
}
