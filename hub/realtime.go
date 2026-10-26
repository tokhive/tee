package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tokhive/tee/jobs"
	"github.com/tokhive/tee/proof"
)

// Session errors.
var (
	// ErrNoReceiptForSession means the tunnel ended without a terminal receipt,
	// so there is nothing to settle against.
	ErrNoReceiptForSession = errors.New("session ended without a receipt")
	// ErrSessionStreamMismatch means the session receipt attests bytes other
	// than the ones the Hub actually relayed. For the downlink that is exact
	// (the stream hash binds the receipt to the relayed bytes); for the uplink
	// it fires only when the receipt attests MORE uplink than the Hub counted
	// — the direction that indicates a receipt the Hub could not have relayed.
	// A receipt attesting fewer uplink bytes than the Hub counted is the
	// teardown tail, not a lie, and does not forfeit the session (see
	// relaySession).
	ErrSessionStreamMismatch = errors.New("session receipt attests different bytes than the Hub relayed")
	// ErrSessionLimitExceeded means the Hub's downlink backstop fired: the TEE
	// relayed past the bound the two agreed on through Spec.MaxResponseBytes.
	//
	// It is a fault, not a normal bound. A session's cap travels on its spec and
	// is enforced by the TEE, which digests exactly what it delivers; the Hub's
	// sessionMaxDownBytes is aligned to that number (see boundSession), so the
	// TEE always cuts first and the receipt reconciles with what the Hub
	// relayed. This error therefore means the TEE broke its own attested bound:
	// it forwarded bytes the Hub never moved, so its digest no longer covers a
	// transcript the Hub can produce — and since the response digest is a plain
	// hash rather than a prefix-verifiable one, no prefix of it can be checked
	// either. Nothing is settled, because there is nothing to settle *against*:
	// a buyer must not be charged on a number no receipt supports. A TEE that
	// honours its cap never produces this.
	ErrSessionLimitExceeded = errors.New("the TEE relayed past the session's agreed downlink bound")
	// ErrSessionProtocolMismatch means the provider answered the Upgrade with a
	// WebSocket subprotocol the user did not negotiate. Forwarding bytes after
	// that would hand the user a protocol they did not ask for, and would make
	// the Hub's own handshake answer a lie, so the session is refused before
	// any tunnel byte is moved.
	ErrSessionProtocolMismatch = errors.New("provider selected a different WebSocket subprotocol than the user negotiated")
)

// sessionCloseGrace is how long the relay holds a tunnel open after the user
// side has ended. A user who closes first has already sent a close frame
// upstream (the link owns that handshake), and the provider answers it by
// ending its stream — which is what lets the TEE sign the terminal receipt.
// Settling that receipt is the difference between a session that is billed for
// what it delivered and one that is forfeited because the user hung up first.
const sessionCloseGrace = 5 * time.Second

// SessionLinkBinder is the optional extension a RealtimeLink implements when it
// owns WebSocket control semantics.
//
// relaySession calls BindSession once, before relaying begins, with a writer
// that serializes every tunnel write and counts every tunnel byte — the user's
// uplink and the link's own ping/pong/close frames alike. ReleaseSession is
// called when relaying stops, so a keepalive goroutine the link started cannot
// outlive the session.
type SessionLinkBinder interface {
	BindSession(tunnel io.Writer)
	ReleaseSession()
}

// SessionProtocol is the optional extension a RealtimeLink implements to state
// the subprotocol it negotiated with the user (or that it negotiated none).
// After the tunnel opens, runRealtime requires the provider's selection to
// match it exactly; see ErrSessionProtocolMismatch.
type SessionProtocol interface {
	Subprotocol() string
}

// SessionCloser is the optional extension a RealtimeLink implements when it can
// end the user-facing connection cleanly. relaySession calls it when the Hub —
// not the provider or the user — ends the session (an uplink bound), so a
// WebSocket link can also send the close frame upstream. Without that close the
// provider would keep streaming until the grace expires, and the receipt that
// attests what it delivered would be lost.
type SessionCloser interface {
	CloseSession(reason string)
}

// meteredTunnel is the only writer to the TEE tunnel. It serializes concurrent
// writers — the uplink relay and the link's control frames — and counts every
// byte that actually reached the tunnel, which is the number the receipt's
// RequestBytes must not exceed.
//
// The count is deliberately not the user's byte count: a close handshake or a
// ping answer the Hub injected is still a byte the TEE received and attested,
// and reconciling against anything smaller would forfeit an honest session.
type meteredTunnel struct {
	SessionConn
	writeMu sync.Mutex
	written atomic.Uint64
}

func (m *meteredTunnel) Write(p []byte) (int, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	n, err := m.SessionConn.Write(p)
	if n > 0 {
		m.written.Add(uint64(n))
	}
	return n, err
}

// Written is how many bytes have been handed to the tunnel.
func (m *meteredTunnel) Written() uint64 { return m.written.Load() }

// sessionProtocolOK reconciles the subprotocol the user negotiated with the one
// the provider selected. A link that does not speak WebSocket has no opinion
// and is skipped, as is a tunnel that does not expose its handshake.
func sessionProtocolOK(link RealtimeLink, conn SessionConn) error {
	wanted, ok := link.(SessionProtocol)
	if !ok {
		return nil
	}
	got := ""
	if handshake, ok := conn.(SessionHandshake); ok {
		got = handshake.Subprotocol()
	}
	if wanted.Subprotocol() != got {
		return fmt.Errorf("%w: user %q, provider %q", ErrSessionProtocolMismatch, wanted.Subprotocol(), got)
	}
	return nil
}

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
// providers. The built spec's downlink cap is then tightened to the Hub's own
// session bound (see boundSession) — the two must be the same number for a
// capped session to reconcile.
//
// The tenant's in-flight share is taken here and travels with the returned
// connection, because a session does not finish when this call returns: it runs
// until the connection closes, holding a provider connection the whole time. A
// caller must close it, or the slot — and the pool slot behind it — is held
// until the process exits.
func (h *Hub) OpenSessionForModel(ctx context.Context, tenant, model string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	return h.openSession(ctx, tenant, model, "", build)
}

// OpenSessionForProvider opens a streaming session to a named provider pinned
// source, with no fallback. It mirrors ExecuteForProvider for the session path:
// the buyer who asks for a specific AI source by name gets exactly that source,
// never a substitute. The named provider must be a current server of the model,
// otherwise the open is refused before a byte moves.
func (h *Hub) OpenSessionForProvider(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	return h.openSession(ctx, tenant, model, provider, build)
}

// openSession opens a session either for the cheapest server of a model
// (provider empty) or pinned to one named provider. It admits the tenant and,
// on a failed open, returns the reserved share so a failed open never holds a
// running job.
func (h *Hub) openSession(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	release, err := h.beginJob(tenant)
	if err != nil {
		return nil, jobs.Spec{}, err
	}
	conn, spec, err := h.openSessionFor(ctx, model, provider, build)
	if err != nil {
		// Nothing came up, so the share this admission reserved goes straight
		// back: a failed open is not a running job and must not hold one.
		release()
		return nil, jobs.Spec{}, err
	}
	return newFlightConn(conn, release), spec, nil
}

// openSessionFor opens the session itself, without admitting the tenant.
// It is split out so admission happens once, above, and so the slot it reserves
// is still in hand when the caller decides whether the session came up.
func (h *Hub) openSessionFor(ctx context.Context, model, provider string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	var providers []string
	if provider != "" {
		if !h.providerServes(provider, model) {
			return nil, jobs.Spec{}, fmt.Errorf("%w: model %q from provider %q", ErrNoProviderForModel, model, provider)
		}
		providers = []string{provider}
	} else {
		providers = h.providersForModel(model)
		if len(providers) == 0 {
			return nil, jobs.Spec{}, h.supplyError(model)
		}
	}
	for _, p := range providers {
		spec, berr := build(p)
		if berr != nil {
			return nil, jobs.Spec{}, fmt.Errorf("build session spec for %q: %w", p, berr)
		}
		spec = h.boundSession(spec)
		spec, aerr := h.attachCredential(spec)
		if aerr != nil {
			return nil, jobs.Spec{}, fmt.Errorf("attach credential for %q: %w", p, aerr)
		}
		attemptCtx, cancel := h.attemptContext(ctx)
		conn, oerr := h.tee.OpenSession(attemptCtx, spec)
		cancel()
		if oerr != nil {
			continue
		}
		return conn, spec, nil
	}
	return nil, jobs.Spec{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
}

// boundSession returns spec with its downlink cap tightened to the Hub's own
// session bound, so the TEE stops relaying exactly where the Hub would.
//
// The two numbers must agree or a capped session cannot be reconciled. The TEE
// enforces Spec.MaxResponseBytes on the downlink and digests exactly what it
// delivers (tee.Session.Read); the Hub enforces its own sessionMaxDownBytes and
// digests exactly what it relays. If the Hub's bound were the tighter of the
// two it would cut the tunnel first, its digest would cover a prefix the TEE's
// does not, and — since the response digest is a plain hash rather than a
// prefix-verifiable one — nothing the TEE signs could be matched against what
// the Hub moved. Aligning them means the TEE always cuts first, its receipt
// covers exactly the relayed bytes, and the session settles for what it
// delivered.
//
// The Hub only ever tightens, never widens: widening the caller's cap could
// raise it above the provider policy's own limit, which the TEE refuses
// outright (policy.AuthorizeAt). A zero Hub bound means "no bound of mine", so
// the caller's cap stands alone, exactly as before.
func (h *Hub) boundSession(spec jobs.Spec) jobs.Spec {
	if h.sessionMaxDownBytes == 0 {
		return spec
	}
	if spec.MaxResponseBytes == 0 || h.sessionMaxDownBytes < spec.MaxResponseBytes {
		spec.MaxResponseBytes = h.sessionMaxDownBytes
	}
	return spec
}

// RunRealtime drives a streaming session end to end: select the cheapest
// provider for model, open the tunnel through the TEE, relay the user's frames,
// and settle the terminal receipt. It returns the settled outcome together with
// the relay error (if the session was cut short by a bound or a transport
// failure).
//
// The Hub applies its own session bounds here — a wall-clock timeout, an
// uplink byte bound, a downlink byte backstop, and a downlink-stall watchdog.
// The wall-clock, uplink and stall bounds are the Hub's because the TEE applies
// none of them to a session: it is a transparent relay, and keeping unbounded
// consumption out of the account book is the Hub's job. The downlink bound is
// the exception — it travels on the session spec and is enforced by the TEE, so
// that the byte count in the receipt is one the Hub can actually reconcile (see
// boundSession); the Hub's own copy is only a backstop for a TEE that breaks
// that contract.
func (h *Hub) RunRealtime(ctx context.Context, tenant, model string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	return h.runRealtime(ctx, tenant, model, "", build, link)
}

// RunRealtimeForProvider drives a streaming session pinned to one named
// provider, with no fallback. It is the session counterpart of
// ExecuteForProvider (and of the route's optional "provider" field): the buyer
// gets exactly the source they asked for. An open that cannot find the named
// provider serving the model is refused before a byte moves.
func (h *Hub) RunRealtimeForProvider(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	return h.runRealtime(ctx, tenant, model, provider, build, link)
}

// runRealtime drives a streaming session end to end: select the cheapest
// provider for model (or the pinned provider), open the tunnel through the TEE,
// relay the user's frames, and settle the terminal receipt. It returns the
// settled outcome together with the relay error (if the session was cut short
// by a bound or a transport failure).
func (h *Hub) runRealtime(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	var (
		conn SessionConn
		spec jobs.Spec
		err  error
	)
	if provider != "" {
		conn, spec, err = h.OpenSessionForProvider(ctx, tenant, model, provider, build)
	} else {
		conn, spec, err = h.OpenSessionForModel(ctx, tenant, model, build)
	}
	if err != nil {
		return SessionOutcome{}, err
	}
	defer conn.Close()

	// The user's handshake has already been answered with a subprotocol; the
	// provider's answer is only known now. A mismatch is refused before the
	// first byte, because every later frame would speak a protocol the user did
	// not negotiate.
	if err := sessionProtocolOK(link, conn); err != nil {
		return SessionOutcome{}, err
	}

	h.ledger.NoteDispatch(spec.Provider)

	tunnel := &meteredTunnel{SessionConn: conn}

	if h.sessionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.sessionTimeout)
		defer cancel()
	}

	// relaySession itself watches ctx.Done. It does not merely cut the tunnel:
	// a link that owns the user-side handshake is asked to close both ends and
	// the provider gets the same grace as any other user-side end, so a session
	// that stops because its wall clock ran out can still produce a receipt for
	// what it delivered. A link that cannot close is cut immediately, which is
	// also what unwedges its blocked tunnel reads.
	up, down, downHash, relErr := relaySession(ctx, tunnel, link, spec.JobID,
		h.sessionMaxUpBytes, h.sessionMaxDownBytes, h.sessionIdle)

	if errors.Is(relErr, ErrSessionLimitExceeded) {
		// The Hub's backstop answered: the TEE relayed past the bound its own
		// spec declared, so the tunnel is already torn down and its digest
		// covers bytes this Hub never moved. Settle nothing — no receipt can be
		// reconciled against the relayed transcript (see
		// ErrSessionLimitExceeded) — and report the frame that cut it.
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
	// The uplink comparison is deliberately one-sided. The Hub counts the
	// bytes it handed to the tunnel, and a session can end while the user's
	// final bytes are still in flight: the Hub may count bytes the closed
	// tunnel never delivered, so its count is an upper bound on what the TEE
	// can attest. An exact equality would forfeit a settled session over that
	// teardown tail. Only a receipt attesting MORE uplink than the Hub ever
	// relayed is a contradiction worth refusing — and the receipt stays the
	// billing record either way, so the buyer pays exactly what the TEE
	// attested was delivered. The count includes control frames the Hub
	// injected (ping answers, the close handshake), because those are bytes the
	// TEE received and attested too. The downlink side is exact (the stream
	// hash already binds it), so its count stays an equality.
	if rec.RequestBytes > tunnel.Written() || rec.ResponseBytes != down || !streamHashEq(rec.StreamHash, downHash[:]) {
		return SessionOutcome{}, ErrSessionStreamMismatch
	}

	card, ok := h.card(spec.Provider)
	if !ok {
		return SessionOutcome{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	// Sessions are never capped by the TEE, so the receipt's ResponseBytes is
	// exactly what was relayed — and the mismatch check above bound it to the
	// Hub's own relayed count. Pass the relayed count so pricing needs no cap
	// special case.
	charged, err := Price(card, model, down, rec)
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
	outcome := SessionOutcome{
		Receipt:       receipt,
		Provider:      spec.Provider,
		UplinkBytes:   up,
		DownlinkBytes: down,
		Charged:       charged,
		Commission:    commission,
		Buyer:         buyer,
	}
	if h.maxJob > 0 && buyer > h.maxJob {
		// Same policy as the request path: the exchange really happened, so
		// the receipt is kept for the provider's audit, but a session priced
		// above the Hub's per-job ceiling settles nothing.
		if serr := h.store.Put(spec.Provider, receipt); serr != nil {
			return outcome, fmt.Errorf("store session receipt: %w", serr)
		}
		outcome.Stored = true
		return outcome, fmt.Errorf("%w: buyer %d exceeds %d", ErrJobPriceExceeded, buyer, h.maxJob)
	}
	if err := h.store.Put(spec.Provider, receipt); err != nil {
		// Same rule as the request path: the receipt is not durable, so the
		// ledger records no money. The caller still gets the priced outcome
		// to report what would have been charged.
		return outcome, fmt.Errorf("store session receipt: %w", err)
	}
	// Store first, then settle: the ledger is in-memory and cannot fail, so
	// once Put has succeeded the settlement is guaranteed to be recorded.
	outcome.Stored = true
	if !h.claimSettlement(receipt.Receipt.JobID) {
		return outcome, fmt.Errorf("%w: job %x", ErrDuplicateSettlement, receipt.Receipt.JobID)
	}
	h.ledger.NoteSettled(spec.Provider, charged)
	h.ledger.NoteCommission(spec.Provider, commission)
	h.chargeTenant(tenant, buyer)
	return outcome, relErr
}

// relaySession copies the provider's downlink to the user (hashing and capping
// it) on one goroutine and the user's uplink to the provider on another. The
// session ends when the provider closes (downlink hits io.EOF after the receipt
// has been flushed through the tunnel), the user closes, or a bound fires.
//
// maxUp and maxDown are the Hub's own byte bounds; zero means no bound. The
// uplink bound is enforced by simply not reading further from the user, which
// ends the session normally: nothing was truncated on the provider's side, so
// the receipt still reconciles and the session still settles for what crossed.
// The downlink bound is different — it is a backstop, not the operative cap; a
// healthy session is cut by the TEE at the same number and settles for the
// bytes it delivered. See ErrSessionLimitExceeded.
//
// The two directions end independently, and the difference matters to billing.
// When the provider finishes, the TEE has signed the receipt and the session is
// settled; the uplink is drained briefly and abandoned. When the user finishes
// first, a WebSocket link has already sent its close frame upstream (the link
// owns that handshake), so the provider answers it and the downlink ends on its
// own. The tunnel is deliberately NOT closed at that point: closing it would
// abort the TEE's provider read before it can sign, forfeiting a session that
// delivered bytes and was simply closed by its user. A grace timer bounds how
// long the relay waits for a provider that never answers the close.
//
// Every boundary that ends a session early follows the same rule: a flow the
// Hub itself stops — an uplink bound, a wall-clock timeout, a cancelled
// context, a downlink stall, or a user socket that broke — asks a link that
// implements SessionCloser to close both ends, then waits out that same grace,
// so the provider can still answer and the TEE can still sign. Only a link that
// cannot close is cut directly, because nothing else would end its session.
//
// relaySession returns as soon as the downlink side resolves (or a bound or the
// context ends), because that is when the receipt has been produced. The uplink
// goroutine is left to unwind when the caller closes the user connection, which
// is the only thing that can unblock a read on a live user socket.
func relaySession(ctx context.Context, tunnel *meteredTunnel, link RealtimeLink, jobID []byte,
	maxUp, maxDown uint64, idle time.Duration) (up, down uint64, downHash [32]byte, relErr error) {

	hasher := proof.NewStreamingHasher(jobID)

	// Hand the link the one metered writer before any byte moves. A WebSocket
	// link owns the control plane on both sides — it answers the provider's
	// pings and sends the close frame when the user ends — and those bytes must
	// go through the same writer as the uplink so the receipt's RequestBytes
	// still reconciles with what the tunnel received.
	if binder, ok := link.(SessionLinkBinder); ok {
		binder.BindSession(tunnel)
		defer binder.ReleaseSession()
	}

	// Downlink-stall watchdog: if the provider streams nothing for `idle`, end
	// the session so the receipt (or io.EOF) surfaces instead of the relay
	// waiting forever. A link that owns the WebSocket control plane is asked to
	// close both ends — that close is what lets the provider finish and the TEE
	// sign — and the select loop below gives it the same grace as any other
	// user-side end. A link without that ability is simply cut.
	//
	// The callback runs on its own goroutine: a close handshake can block on a
	// tunnel write for a writer that has stopped reading, and the relay loop must
	// stay free to process the downlink that may still arrive.
	var idleTimer *time.Timer
	idleFired := make(chan struct{}, 1)
	if idle > 0 {
		var idleOnce sync.Once
		idleTimer = time.AfterFunc(idle, func() {
			idleOnce.Do(func() {
				if closer, ok := link.(SessionCloser); ok {
					closer.CloseSession("provider went idle")
				} else {
					_ = tunnel.Close()
				}
				select {
				case idleFired <- struct{}{}:
				default:
				}
			})
		})
		defer idleTimer.Stop()
	}

	var downCount uint64
	downDone := make(chan error, 1)
	// linkGone reports that delivery to the user failed. The downlink keeps
	// draining after that: the provider's transcript and the terminal receipt
	// are still worth having, and abandoning the read would forfeit the session
	// over a user that merely hung up. The grace timer below bounds the wait.
	linkGone := make(chan struct{})
	go func() {
		buf := make([]byte, 32*1024)
		var writeErr error
		for {
			n, rerr := tunnel.Read(buf)
			if n > 0 {
				if maxDown > 0 && downCount+uint64(n) > maxDown {
					downDone <- ErrSessionLimitExceeded
					return
				}
				downCount += uint64(n)
				_ = hasher.WriteChunk(buf[:n])
				if writeErr == nil {
					if _, werr := link.Write(buf[:n]); werr != nil {
						writeErr = werr
						close(linkGone)
					}
				}
				if idleTimer != nil {
					idleTimer.Reset(idle)
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					// A clean provider end: the session ends normally. If the
					// user side had already failed, still report that failure —
					// the receipt is settled, but the caller may want to log
					// that delivery broke.
					downDone <- writeErr
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
				if maxUp > 0 && upCount.Load()+uint64(n) > maxUp {
					// The user is uploading more than the Hub will relay into
					// the provider's tunnel. Stop reading and end the session
					// cleanly: the link owns the handshake on both ends, and a
					// graceful close is what lets the provider finish and the
					// TEE sign a receipt for what it actually delivered.
					if closer, ok := link.(SessionCloser); ok {
						closer.CloseSession("uplink byte limit reached")
					}
					break
				}
				upCount.Add(uint64(n))
				if _, werr := tunnel.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	}()

	// drainUplink lets an in-flight uplink finish so the count is as settled as
	// it can be before it is compared against the receipt's RequestBytes —
	// otherwise a receipt that is perfectly honest races the last write. The
	// count can still grow after the drain (a user socket the goroutine is
	// blocked reading), which is why the comparison in RunRealtime accepts a
	// receipt attesting no more than the Hub counted: the Hub's count is an
	// upper bound on what the TEE could have received, and a receipt inside
	// that bound is the attested billing record. It returns immediately if
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

	// The grace timer starts whenever the user side ends (cleanly, by a failed
	// delivery, or because a bound or the context is ending the session), and
	// only bounds how long the provider gets to finish on its own. It is never
	// armed for a session the provider has already ended.
	var (
		graceC     <-chan time.Time
		graceTimer *time.Timer
		ctxErr     error
	)
	armGrace := func() {
		if graceTimer != nil {
			return
		}
		graceTimer = time.NewTimer(sessionCloseGrace)
		graceC = graceTimer.C
	}
	defer func() {
		if graceTimer != nil {
			graceTimer.Stop()
		}
	}()

	// askToClose sends the upstream close through the link when it owns the
	// handshake, and reports whether that happened. A link that cannot close is
	// cut where it stands: nothing upstream would otherwise end the session.
	askToClose := func(reason string) bool {
		closer, ok := link.(SessionCloser)
		if !ok {
			_ = tunnel.Close()
			return false
		}
		// CloseSession can block on a tunnel write the provider stopped reading;
		// that is why the idle watchdog calls it off this goroutine. Here the
		// loop is already ending the session, and the bounded wait for the answer
		// is the same grace every other end path gets.
		closer.CloseSession(reason)
		return true
	}

	upCh, linkCh, ctxCh := upGone, linkGone, ctx.Done()
	for {
		select {
		case <-ctxCh:
			// The wall clock ran out or the caller cancelled. Do not cut the
			// tunnel: ask both ends to close and wait out the grace for the
			// provider's answer, because that answer is what lets the TEE sign a
			// receipt for the bytes that already crossed. A link that cannot
			// close is cut immediately, exactly as before.
			ctxCh = nil
			ctxErr = ctx.Err()
			if askToClose("session ended") {
				armGrace()
			}
		case downErr := <-downDone:
			// The provider closed (or a bound fired); the receipt may already
			// have been read. Close the relay so any uplink still being handed
			// to the tunnel unwinds, then settle the uplink count. A cancelled
			// context is reported even when the provider finished first: the
			// caller asked to stop, and runRealtime still settles the receipt.
			_ = tunnel.Close()
			drainUplink()
			if ctxErr != nil && !errors.Is(downErr, ErrSessionLimitExceeded) {
				return upCount.Load(), downCount, hasher.Sum(), ctxErr
			}
			return upCount.Load(), downCount, hasher.Sum(), downErr
		case <-upCh:
			// The user closed (their close frame already went upstream), or the
			// uplink bound fired and the link sent one. Wait for the provider to
			// answer before tearing the tunnel down.
			upCh = nil
			armGrace()
		case <-linkCh:
			// Delivery to the user failed. The user socket is gone, so the
			// provider must be told too — otherwise it streams into a dead
			// session until the grace expires. The downlink keeps draining, so
			// the provider's transcript is still captured.
			linkCh = nil
			askToClose("user delivery failed")
			armGrace()
		case <-idleFired:
			// The watchdog already asked a closing link to close both ends (or
			// cut the tunnel itself); give the provider its grace to finish.
			armGrace()
		case <-graceC:
			// The user side is gone and the provider did not answer the close in
			// time. Tear the tunnel down; if no receipt follows, RunRealtime
			// reports ErrNoReceiptForSession rather than charging for a
			// transcript nothing attested.
			_ = tunnel.Close()
			<-downDone
			drainUplink()
			return upCount.Load(), downCount, hasher.Sum(), ctxErr
		}
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
