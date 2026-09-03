package hub

import (
	"context"
	"errors"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// ScriptedTEE is an in-memory stand-in for the TEE, for exercising Hub
// business rules at the cost of a function call.
//
// Pricing, quota, the ledger and gap detection are the parts of this system
// most likely to change, and all of them are pure logic once the TEE sits
// behind one interface. Running them against this keeps the loop in
// milliseconds and — more importantly — lets a test dictate exactly what the
// receipt says, including things a real TEE would rarely produce on demand: a
// 429, a truncated completion, a sequence number with a hole in it, a response
// large enough to overflow a price.
//
// This stands in for the TEE, not for the receipts. Build its replies with
// ScriptReceipt so the invariants the Hub checks are the real ones, and a
// stand-in cannot quietly disable the check it is supposed to be testing.
type ScriptedTEE struct {
	// Reply returns the result for the nth call, counted from 1. Nil means
	// every call fails; it is required so that a test cannot accidentally
	// run against an empty script and pass by doing nothing.
	Reply func(call int, spec jobs.Spec) (Result, error)

	// OpenReply, if set, returns a session tunnel for the nth session open.
	// When nil, OpenSession returns ErrSessionUnsupported. The two call
	// counters are independent so request/response and session tests can be
	// scripted without cross-talk.
	OpenReply func(call int, spec jobs.Spec) (SessionConn, error)

	mu        sync.Mutex
	calls     int
	openCalls int
}

// Execute implements TEE.
//
// Chunks are forwarded before an error is returned, matching the real TEE: a
// job that failed mid-flight still delivered bytes, and the Hub has to be able
// to prove what it got.
func (s *ScriptedTEE) Execute(_ context.Context, spec jobs.Spec, _ []byte, onChunk func([]byte) error) (Result, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()

	if s.Reply == nil {
		return Result{}, errors.New("scripted tee has no Reply set")
	}
	res, err := s.Reply(call, spec)
	for _, chunk := range res.Chunks {
		if onChunk == nil {
			break
		}
		if cerr := onChunk(chunk); cerr != nil {
			return Result{Chunks: res.Chunks}, cerr
		}
	}
	return res, err
}

// Calls reports how many times Execute has been invoked. A test asserting that
// quota blocked dispatch checks this is zero rather than inferring it from the
// error, so a Hub that dispatched anyway cannot pass.
func (s *ScriptedTEE) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// OpenSession implements TEE. It dispatches to OpenReply if set, otherwise it
// reports sessions as unsupported — a Hub wired to a scripted (request/response
// only) stand-in must not silently gain a session it cannot back.
func (s *ScriptedTEE) OpenSession(_ context.Context, spec jobs.Spec) (SessionConn, error) {
	s.mu.Lock()
	s.openCalls++
	call := s.openCalls
	s.mu.Unlock()

	if s.OpenReply == nil {
		return nil, ErrSessionUnsupported
	}
	conn, err := s.OpenReply(call, spec)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// OpenCalls reports how many times OpenSession has been invoked.
func (s *ScriptedTEE) OpenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openCalls
}

// ScriptReceipt fills in the StreamHash that commits a receipt to chunks, so
// the receipt passes the check the Hub performs before settling.
//
// Without this a test has to compute the hash itself, and a test that gets it
// wrong produces a Hub that reports ErrStreamMismatch for a reason that has
// nothing to do with what it meant to test.
func ScriptReceipt(chunks [][]byte, r proof.Receipt) proof.Receipt {
	if len(r.JobID) == 0 {
		r.JobID = make([]byte, proof.JobIDLength)
	}
	hash := proof.HashResponseStream(r.JobID, chunks)
	r.StreamHash = hash[:]
	return r
}
