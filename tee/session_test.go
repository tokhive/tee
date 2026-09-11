package tee

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// fakeSessionConn is a scripted provider byte pipe for Session tests.
type fakeSessionConn struct {
	readData []byte // remaining bytes to return from Read
	readErr  error  // error to return once readData is exhausted
}

func (c *fakeSessionConn) Read(p []byte) (int, error) {
	if len(c.readData) > 0 {
		n := copy(p, c.readData)
		c.readData = c.readData[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *fakeSessionConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakeSessionConn) Close() error                { return nil }

// newSessionForTest assembles a Session around a fake conn and a real service
// (for the signer), so tests can drive Read and inspect the receipt. The
// decision is synthesised rather than authorised: these tests exercise the
// byte accounting, not policy, and the default test policy has no GET rule.
func newSessionForTest(t *testing.T, conn SessionConn) *Session {
	t.Helper()
	env := newTestEnv(t)
	spec := env.spec(t, nil)
	spec.Session = true
	spec.Method = "GET"
	hash, err := spec.Hash()
	if err != nil {
		t.Fatalf("hash spec: %v", err)
	}
	policyHash := make([]byte, 32)
	return &Session{
		svc:       env.service,
		spec:      spec,
		specHash:  hash,
		decision:  policy.Decision{PolicyHash: policyHash},
		seq:       1,
		conn:      conn,
		hasher:    proof.NewStreamingHasher(spec.JobID),
		started:   baseTime.Unix(),
		downLimit: spec.MaxResponseBytes,
	}
}

// drainSession reads until the session ends, returning everything delivered.
func drainSession(t *testing.T, ss *Session) []byte {
	t.Helper()
	var got []byte
	buf := make([]byte, 64)
	for i := 0; i < 1000; i++ {
		n, err := ss.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read: %v", err)
			}
			return got
		}
	}
	t.Fatal("session never ended")
	return nil
}

// TestSessionEnforcesTheDownlinkCap pins the property the Hub's billing depends
// on: the TEE delivers no more than Spec.MaxResponseBytes and digests exactly
// what it delivered. A byte that were counted (or digested) but not handed over
// would leave the receipt describing a transcript no relay could have produced,
// and a session cut at its cap could never be settled.
func TestSessionEnforcesTheDownlinkCap(t *testing.T) {
	conn := &fakeSessionConn{readData: []byte("0123456789"), readErr: io.EOF}
	ss := newSessionForTest(t, conn)
	ss.downLimit = 4

	got := drainSession(t, ss)
	if string(got) != "0123" {
		t.Fatalf("delivered %q, want exactly the 4 bytes the cap allows", got)
	}

	result, err := ss.Receipt()
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if !result.Truncated {
		t.Fatal("reaching the cap must mark the session truncated")
	}
	if got := result.Receipt.Receipt.Completion; got != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", got)
	}
	if result.ResponseBytes != 4 {
		t.Fatalf("attested response bytes = %d, want 4 (the delivered prefix only)", result.ResponseBytes)
	}
	// The digest must cover exactly the delivered bytes — that is what lets the
	// Hub match its own relayed transcript against the receipt.
	want := proof.HashResponseStream(ss.spec.JobID, [][]byte{got})
	if !bytes.Equal(result.Receipt.Receipt.StreamHash, want[:]) {
		t.Fatal("receipt digest does not cover exactly the delivered bytes")
	}
}

// TestSessionWithoutACapRunsToTheProviderEnd is the counterpart: no cap means
// the whole transcript is delivered and digested, and a clean EOF stays
// complete.
func TestSessionWithoutACapRunsToTheProviderEnd(t *testing.T) {
	conn := &fakeSessionConn{readData: []byte("all of it"), readErr: io.EOF}
	ss := newSessionForTest(t, conn)
	ss.downLimit = 0

	got := drainSession(t, ss)
	if string(got) != "all of it" {
		t.Fatalf("delivered %q, want the whole transcript", got)
	}
	result, err := ss.Receipt()
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if result.Truncated {
		t.Fatal("an uncapped session ending on a clean EOF must stay complete")
	}
}

// TestSessionZeroByteNonEOFErrorIsTruncated locks the bug where a provider
// drop that surfaces as a (0, non-EOF) read error — an RST with no pending
// bytes — left the session marked complete: the truncated flag was only set
// when the error arrived together with data. A session that dies with zero
// downlink bytes in the final read is still a truncated transcript, not a
// whole one.
func TestSessionZeroByteNonEOFErrorIsTruncated(t *testing.T) {
	boom := errors.New("connection reset by peer")
	ss := newSessionForTest(t, &fakeSessionConn{readErr: boom})

	buf := make([]byte, 1024)
	if _, err := ss.Read(buf); err == nil {
		t.Fatal("expected the reset error to surface from Read")
	}

	result, err := ss.Receipt()
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if !result.Truncated {
		t.Fatal("session marked complete despite a non-EOF read error")
	}
	if got := result.Receipt.Receipt.Completion; got != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", got)
	}
}

// TestSessionDataThenEOFIsComplete is the healthy counterpart: bytes followed
// by a clean EOF is a whole session, and must not be marked truncated.
func TestSessionDataThenEOFIsComplete(t *testing.T) {
	ss := newSessionForTest(t, &fakeSessionConn{
		readData: []byte("some provider bytes"),
		readErr:  io.EOF,
	})

	buf := make([]byte, 1024)
	n, err := ss.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n == 0 {
		t.Fatal("expected data from the first read")
	}
	if _, err := ss.Read(buf); err != io.EOF {
		t.Fatalf("second read = %v, want EOF", err)
	}

	result, err := ss.Receipt()
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if result.Truncated {
		t.Fatal("session marked truncated despite a clean EOF")
	}
	if got := result.Receipt.Receipt.Completion; got != proof.CompletionComplete {
		t.Fatalf("completion = %v, want complete", got)
	}
}
