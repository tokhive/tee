package shared

import (
	"context"
	"fmt"
	"sync"
	"time"
	"uuid"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// SessionManagerInterface defines the interface for session management
type SessionManagerInterface interface {
	CreateSession(clientConn Connection) (string, error)
	RegisterSession(sessionID string) error
	ActivateSession(sessionID string, clientConn Connection) error
	CloseSession(sessionID string) error
	GetSession(sessionID string) (*Session, error)
	GetSessionByConnection(conn Connection) (*Session, error)
	RouteToSession(sessionID string, env *teeproto.Envelope) error
	RouteToTEEK(sessionID string, env *teeproto.Envelope) error
	RouteToClient(sessionID string, env *teeproto.Envelope) error
	StartCleanupRoutine()
	Stop()
}

// MaxSessions is the maximum number of concurrent sessions allowed
const MaxSessions = 1000

// SessionManager provides unified session management
type SessionManager struct {
	sessions       map[string]*Session
	sessionsByConn map[Connection]*Session
	mutex          sync.Mutex
	cleanupTicker  *time.Ticker
	cleanupDone    chan bool
	sessionTimeout time.Duration
	logger         *Logger

	// Fired once per session removed by the expiry ticker. Invoked
	// outside the mutex; receives the just-removed *Session pointer.
	onSessionExpired func(session *Session)
}

// Verify that SessionManager implements SessionManagerInterface
var _ SessionManagerInterface = (*SessionManager)(nil)

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*Session),
		sessionsByConn: make(map[Connection]*Session),
		cleanupDone:    make(chan bool),
		sessionTimeout: 30 * time.Minute, // Default 30 minute timeout
	}
}

// SetLogger sets the logger for session status reporting
func (sm *SessionManager) SetLogger(logger *Logger) {
	sm.logger = logger
}

func (sm *SessionManager) SetOnSessionExpired(fn func(session *Session)) {
	sm.onSessionExpired = fn
}

// CreateSession creates a new session with secure UUID
func (sm *SessionManager) CreateSession(clientConn Connection) (string, error) {
	sessionID := uuid.NewV4()

	ctx, cancel := context.WithCancel(context.Background())

	session := &Session{
		ID:             sessionID.String(),
		ClientConn:     clientConn,
		CreatedAt:      time.Now(),
		LastActiveAt:   time.Now(),
		State:          SessionStateNew,
		RedactionState: &RedactionSessionState{},
		ResponseState: &ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*EncryptedResponseData),
		},
		Context: ctx,
		Cancel:  cancel,
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if len(sm.sessions) >= MaxSessions {
		cancel()
		return "", fmt.Errorf("maximum session limit reached (%d)", MaxSessions)
	}

	sm.sessions[session.ID] = session
	if clientConn != nil {
		sm.sessionsByConn[clientConn] = session
	}

	return session.ID, nil
}

// RegisterSession registers a session ID (for TEE_T to prepare for incoming client)
func (sm *SessionManager) RegisterSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if len(sm.sessions) >= MaxSessions {
		return fmt.Errorf("maximum session limit reached (%d)", MaxSessions)
	}

	if _, exists := sm.sessions[sessionID]; exists {
		return fmt.Errorf("session %s already registered", sessionID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	// Create placeholder session
	session := &Session{
		ID:             sessionID,
		CreatedAt:      time.Now(),
		State:          SessionStateNew,
		RedactionState: &RedactionSessionState{},
		ResponseState: &ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*EncryptedResponseData),
		},
		Context: ctx,
		Cancel:  cancel,
	}

	sm.sessions[sessionID] = session
	return nil
}

// ActivateSession activates a registered session when client connects
func (sm *SessionManager) ActivateSession(sessionID string, clientConn Connection) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.ConnMutex.Lock()
	if session.ClientConn != nil && session.ClientConn != clientConn {
		session.ConnMutex.Unlock()
		return fmt.Errorf("session %s already has a client connection", sessionID)
	}
	session.ClientConn = clientConn
	session.ConnMutex.Unlock()
	session.LastActiveAt = time.Now()
	session.State = SessionStateActive
	sm.sessionsByConn[clientConn] = session

	return nil
}

// ActivateSessionIfCurrent activates expected only while it remains the exact
// session registered under its ID.
func (sm *SessionManager) ActivateSessionIfCurrent(expected *Session, clientConn Connection) error {
	if expected == nil {
		return fmt.Errorf("session is nil")
	}
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.sessions[expected.ID] != expected {
		return fmt.Errorf("session %s is no longer current", expected.ID)
	}
	expected.ConnMutex.Lock()
	if expected.ClientConn != nil && expected.ClientConn != clientConn {
		expected.ConnMutex.Unlock()
		return fmt.Errorf("session %s already has a client connection", expected.ID)
	}
	expected.ClientConn = clientConn
	expected.ConnMutex.Unlock()
	expected.LastActiveAt = time.Now()
	expected.State = SessionStateActive
	sm.sessionsByConn[clientConn] = expected
	return nil
}

func (sm *SessionManager) IsCurrentSessionWithClient(expected *Session, clientConn Connection) bool {
	if expected == nil {
		return false
	}
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	if sm.sessions[expected.ID] != expected {
		return false
	}
	expected.ConnMutex.RLock()
	defer expected.ConnMutex.RUnlock()
	return expected.ClientConn == clientConn
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	return session, nil
}

// GetSessionByConnection retrieves a session by connection
func (sm *SessionManager) GetSessionByConnection(conn Connection) (*Session, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessionsByConn[conn]
	if !exists {
		return nil, fmt.Errorf("session not found for connection")
	}

	return session, nil
}

// CloseSession closes and removes a session
func (sm *SessionManager) CloseSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}
	sm.closeSessionLocked(session)
	return nil
}

// CloseSessionIfCurrent closes expected only while it remains the exact session
// registered under its ID. Expiry callbacks use this to avoid closing a newer
// session that reused the same ID after expected was removed.
func (sm *SessionManager) CloseSessionIfCurrent(expected *Session) error {
	if expected == nil {
		return fmt.Errorf("session is nil")
	}
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if sm.sessions[expected.ID] != expected {
		return fmt.Errorf("session %s is no longer current", expected.ID)
	}
	sm.closeSessionLocked(expected)
	return nil
}

// closeSessionLocked closes and removes session. sm.mutex must be held.
func (sm *SessionManager) closeSessionLocked(session *Session) {
	sessionID := session.ID

	session.IsClosed = true
	session.State = SessionStateClosed

	// Cancel context
	if session.Cancel != nil {
		session.Cancel()
	}

	if session.ClientConn != nil {
		session.ClientConn.Close()
		delete(sm.sessionsByConn, session.ClientConn)
	}

	delete(sm.sessions, sessionID)
}

// StartCleanupRoutine starts the session cleanup routine
func (sm *SessionManager) StartCleanupRoutine() {
	sm.cleanupTicker = time.NewTicker(1 * time.Minute) // Run every minute for faster cleanup
	go func() {
		for {
			select {
			case <-sm.cleanupTicker.C:
				sm.cleanupExpiredSessions()
			case <-sm.cleanupDone:
				return
			}
		}
	}()
}

// Stop stops the session manager
func (sm *SessionManager) Stop() {
	if sm.cleanupTicker != nil {
		sm.cleanupTicker.Stop()
	}
	close(sm.cleanupDone)
}

// cleanupExpiredSessions removes expired sessions
func (sm *SessionManager) cleanupExpiredSessions() {
	sm.mutex.Lock()

	now := time.Now()
	const pendingSessionTimeout = 2 * time.Minute // Short timeout for registered-but-not-activated sessions

	// Capture pointers; callbacks fire outside the lock.
	var expired []*Session
	var pending, active int

	for sessionID, session := range sm.sessions {
		var shouldCleanup bool
		isPending := session.State == SessionStateNew && session.ClientConn == nil

		// Registered but never activated (no client connected) - 2 minute timeout
		if isPending {
			shouldCleanup = now.Sub(session.CreatedAt) > pendingSessionTimeout
		} else {
			// Active sessions - use standard timeout (30 min)
			shouldCleanup = now.Sub(session.LastActiveAt) > sm.sessionTimeout
		}

		if shouldCleanup {
			expired = append(expired, session)
			session.IsClosed = true
			if session.Cancel != nil {
				session.Cancel()
			}
			if session.ClientConn != nil {
				session.ClientConn.Close()
				delete(sm.sessionsByConn, session.ClientConn)
			}
			delete(sm.sessions, sessionID)
		} else {
			// Count remaining sessions
			if isPending {
				pending++
			} else {
				active++
			}
		}
	}

	total := len(sm.sessions)
	logger := sm.logger
	callback := sm.onSessionExpired
	sm.mutex.Unlock()

	if callback != nil {
		for _, s := range expired {
			callback(s)
		}
	}

	if logger != nil {
		logger.Info("Session status",
			zap.Int("total", total),
			zap.Int("active", active),
			zap.Int("pending", pending),
			zap.Int("cleaned_up", len(expired)))
	}
}

// Message routing methods
func (sm *SessionManager) RouteToSession(sessionID string, env *teeproto.Envelope) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}
	// Route to client connection
	if session.ClientConn != nil {
		if ws, ok := session.ClientConn.(*WSConnection); ok {
			// ensure session id is present
			if env.GetSessionId() == "" {
				env.SessionId = sessionID
			}
			data, err := proto.Marshal(env)
			if err != nil {
				return err
			}
			return ws.WriteMessage(websocket.BinaryMessage, data)
		}
	}

	return fmt.Errorf("no client connection in session %s", sessionID)
}

func (sm *SessionManager) RouteToTEEK(sessionID string, env *teeproto.Envelope) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}

	if session.TEEKConn == nil {
		return fmt.Errorf("no TEE_K connection in session %s", sessionID)
	}

	if ws, ok := session.TEEKConn.(*WSConnection); ok {
		if env.GetSessionId() == "" {
			env.SessionId = sessionID
		}
		data, err := proto.Marshal(env)
		if err != nil {
			return err
		}
		return ws.WriteMessage(websocket.BinaryMessage, data)
	}
	return fmt.Errorf("unsupported connection type for TEE_K")
}

func (sm *SessionManager) RouteToClient(sessionID string, env *teeproto.Envelope) error {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return err
	}

	if session.ClientConn == nil {
		return fmt.Errorf("no client connection in session %s", sessionID)
	}

	if ws, ok := session.ClientConn.(*WSConnection); ok {
		if env.GetSessionId() == "" {
			env.SessionId = sessionID
		}
		data, err := proto.Marshal(env)
		if err != nil {
			return err
		}
		return ws.WriteMessage(websocket.BinaryMessage, data)
	}
	return fmt.Errorf("unsupported client connection type")
}
