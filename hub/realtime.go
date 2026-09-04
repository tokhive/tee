package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Session errors.
var (
	// ErrNoReceiptForSession means the tunnel ended without a terminal receipt,
	// so there is nothing to settle against.
	ErrNoReceiptForSession = errors.New("session ended without a receipt")
	// ErrSessionStreamMismatch means the session receipt attests bytes other
	// than the ones the Hub actually relayed.
	ErrSessionStreamMismatch = errors.New("session receipt attests different bytes than the Hub relayed")
	// ErrSessionLimitExceeded means the Hub stopped relaying because a
	// configured bound (downlink bytes) was hit. Unlike a request — whose cap is
	// enforced by the TEE, which can attest the exact truncated prefix — a
	// session's byte cap is enforced here on the Hub, over a tunnel the TEE
	// deliberately does not truncate. Everything the TEE already forwarded past
	// the cap is in its digest but was never relayed, so the Hub cannot produce
	// a receipt that matches it. Truncation therefore ends the session and earns
	// nothing; it is a bound, not a billable event (matching "断流 0 计价").
	ErrSessionLimitExceeded = errors.New("session exceeded the Hub's relay bound")
)

// upGrant is how long relaySession waits for an in-flight uplink to finish
// before counting it, once the session has ended. Long enough for a buffered
// user link to drain in tests, short enough that a silent-but-connected user
// cannot hold a session open through a count that is already settled.
const upGrant = 250 * time.Millisecond

// RealtimeLink is the user side of a streaming session. The Hub only moves
// bytes: Read yields the user's frames to forward uplink, Write delivers the
// provider's downlink frames back. Frame semantics belong to the caller (the
// user's protocol), never to the Hub or the TEE.
type RealtimeLink interface {
	io.Reader
	io.Writer
}

// SessionOutcome is the settled result of a streaming session.
type SessionOutcome struct {
	Receipt       proof.SignedReceipt
	Provider      string
	UplinkBytes   uint64
	DownlinkBytes uint64
	Charged       uint64
	Commission    uint64
	Buyer         uint64
	Stored        bool
}

// OpenSessionForModel selects the cheapest provider serving a model and opens a
// streaming session to it through the TEE. Provider selection happens before a
// single byte reaches the user, so a provider whose open fails can give way to
// the next-cheapest candidate, exactly as ExecuteForModel does for requests.
//
// build frames the session spec for one provider (host, path, Session flag);
// the caller supplies it once because that framing is identical across
// providers.
func (h *Hub) OpenSessionForModel(ctx context.Context, tenant, model string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	if h.quota != nil && !h.quota.Allow(tenant, h.clock()) {
		return nil, jobs.Spec{}, fmt.Errorf("%w: tenant %q", ErrQuotaExceeded, tenant)
	}

	providers := h.providersForModel(model)
	if len(providers) == 0 {
		return nil, jobs.Spec{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
	}
	for _, provider := range providers {
		spec, berr := build(provider)
		if berr != nil {
			return nil, jobs.Spec{}, fmt.Errorf("build session spec for %q: %w", provider, berr)
		}
		spec, aerr := h.attachCredential(spec)
		if aerr != nil {
			return nil, jobs.Spec{}, fmt.Errorf("attach credential for %q: %w", provider, aerr)
		}
		conn, oerr := h.tee.OpenSession(ctx, spec)
		if oerr != nil {
			continue
		}
		return conn, spec, nil
	}
	return nil, jobs.Spec{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
}

// RunRealtime drives a streaming session end to end: select the cheapest
// provider for model, open the tunnel through the TEE, relay the user's frames,
// and settle the terminal receipt. It returns the settled outcome together with
// the relay error (if the session was cut short by a bound or a transport
// failure).
//
// The Hub applies its own session bounds here — a wall-clock timeout, a
// downlink byte cap, and a downlink-stall watchdog — because the TEE
// deliberately applies none to a session (it is a transparent relay). Keeping
// unbounded resource consumption out of the account book and on the Hub's side
// of the wire.
func (h *Hub) RunRealtime(ctx context.Context, tenant, model string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	conn, spec, err := h.OpenSessionForModel(ctx, tenant, model, build)
	if err != nil {
		return SessionOutcome{}, err
	}
	defer conn.Close()

	h.ledger.NoteDispatch(spec.Provider)

	if h.sessionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.sessionTimeout)
		defer cancel()
	}
	// Any expiry (wall-clock timeout or the caller's cancellation) must unwedge
	// the relay loops, which are otherwise blocked on the tunnel: closing the
	// tunnel aborts the downlink read so we can return and settle.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	up, down, downHash, relErr := relaySession(ctx, conn, link, spec.JobID, h.sessionMaxDownBytes, h.sessionIdle)

	if errors.Is(relErr, ErrSessionLimitExceeded) {
		// The Hub answered its own byte bound. The tunnel is already torn down;
		// settle nothing: no receipt can be reconciled (see ErrSessionLimitExceeded),
		// so nothing is charged and no receipt is stored. Report the frame it cut.
		return SessionOutcome{Provider: spec.Provider, UplinkBytes: up, DownlinkBytes: down}, relErr
	}

	receipt, rerr := conn.Receipt()
	if rerr != nil {
		return SessionOutcome{}, fmt.Errorf("%w: %v", ErrNoReceiptForSession, rerr)
	}
	if err := h.verify(receipt); err != nil {
		return SessionOutcome{}, fmt.Errorf("verify session receipt: %w", err)
	}
	h.ledger.NoteVerified(spec.Provider)

	rec := receipt.Receipt
	if rec.StatusCode != 101 {
		return SessionOutcome{}, fmt.Errorf("session receipt status %d, want 101", rec.StatusCode)
	}
	if rec.RequestBytes != up || rec.ResponseBytes != down || !streamHashEq(rec.StreamHash, downHash[:]) {
		return SessionOutcome{}, ErrSessionStreamMismatch
	}

	card, ok := h.card(spec.Provider)
	if !ok {
		return SessionOutcome{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	charged, err := Price(card, model, rec)
	if err != nil {
		return SessionOutcome{}, fmt.Errorf("price session: %w", err)
	}
	commission, err := h.commission.CommissionOn(charged)
	if err != nil {
		return SessionOutcome{}, err
	}
	buyer, ok := addChecked(charged, commission)
	if !ok {
		return SessionOutcome{}, fmt.Errorf("%w: charged %d plus commission %d", ErrPriceOverflow, charged, commission)
	}
	h.ledger.NoteSettled(spec.Provider, charged)
	h.ledger.NoteCommission(spec.Provider, commission)

	outcome := SessionOutcome{
		Receipt:       receipt,
		Provider:      spec.Provider,
		UplinkBytes:   up,
		DownlinkBytes: down,
		Charged:       charged,
		Commission:    commission,
		Buyer:         buyer,
	}
	if err := h.store.Put(spec.Provider, receipt); err != nil {
		return outcome, fmt.Errorf("store session receipt: %w", err)
	}
	outcome.Stored = true
	return outcome, relErr
}

// relaySession copies the provider's downlink to the user (hashing and capping
// it) on one goroutine and the user's uplink to the provider on another. The
// session ends when the provider closes (downlink hits io.EOF after the receipt
// has been flushed through the tunnel), the user closes, or a bound fires.
//
// relaySession returns as soon as the downlink side resolves (or the session
// times out), because that is when the receipt has been produced. The uplink
// goroutine is left to unwind when the caller closes the user connection, which
// is the only thing that can unblock a read on a live user socket.
func relaySession(ctx context.Context, tunnel SessionConn, link RealtimeLink, jobID []byte,
	maxDown uint64, idle time.Duration) (up, down uint64, downHash [32]byte, relErr error) {

	hasher := proof.NewStreamingHasher(jobID)

	// Downlink-stall watchdog: if the provider streams nothing for `idle`, tear
	// the tunnel down so the receipt (or io.EOF) surfaces and we stop waiting.
	var idleTimer *time.Timer
	if idle > 0 {
		idleTimer = time.AfterFunc(idle, func() { _ = tunnel.Close() })
		defer idleTimer.Stop()
	}

	var downCount uint64
	downDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := tunnel.Read(buf)
			if n > 0 {
				if maxDown > 0 && downCount+uint64(n) > maxDown {
					downDone <- ErrSessionLimitExceeded
					return
				}
				downCount += uint64(n)
				_ = hasher.WriteChunk(buf[:n])
				if _, werr := link.Write(buf[:n]); werr != nil {
					downDone <- werr
					return
				}
				if idleTimer != nil {
					idleTimer.Reset(idle)
				}
			}
			if rerr != nil {
				if rerr == io.EOF {
					downDone <- nil
				} else {
					downDone <- rerr
				}
				return
			}
		}
	}()

	var upCount atomic.Uint64
	upGone := make(chan struct{})
	go func() {
		defer close(upGone)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := link.Read(buf)
			if n > 0 {
				upCount.Add(uint64(n))
				if _, werr := tunnel.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		// User side finished: stop the provider-side read so the session can end.
		_ = tunnel.Close()
	}()

	// drainUplink lets an in-flight uplink finish so the count is stable before
	// it is compared against the receipt's RequestBytes — otherwise a receipt
	// that is perfectly honest races the last write. It returns immediately if
	// the goroutine is already gone, and is bounded because with a live user
	// socket the goroutine can only be unwound by the caller closing the
	// connection, which happens after we return.
	drainUplink := func() {
		timer := time.NewTimer(upGrant)
		defer timer.Stop()
		select {
		case <-upGone:
		case <-timer.C:
		}
	}

	select {
	case <-ctx.Done():
		_ = tunnel.Close()
		<-downDone
		drainUplink()
		return upCount.Load(), downCount, hasher.Sum(), ctx.Err()
	case downErr := <-downDone:
		// The provider closed (or a bound fired); the receipt may already have
		// been read. Close the relay so any uplink still being handed to the
		// tunnel unwinds, then settle the uplink count.
		_ = tunnel.Close()
		drainUplink()
		if downErr != nil {
			return upCount.Load(), downCount, hasher.Sum(), downErr
		}
		return upCount.Load(), downCount, hasher.Sum(), nil
	}
}

func streamHashEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
