package hub

import "sync"

// Ledger is the Hub's account of what it owes providers.
//
// It counts in the micro-units of each provider's own rate card, so the
// revenue total is only meaningful if every provider prices in the same unit.
// Summing across providers is therefore a convenience for reporting, not a
// number to settle on — a real Hub keeps one account per provider per
// currency, which is a change to this file, not to the pricing path.
type Ledger struct {
	mu         sync.Mutex
	dispatched int
	verified   int
	settled    int
	revenue    uint64
	commission uint64
	accounts   map[string]*providerAccount
}

type providerAccount struct {
	dispatched int
	verified   int
	settled    int
	revenue    uint64
	commission uint64
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{accounts: make(map[string]*providerAccount)}
}

// NoteDispatch records that a job was sent to the TEE.
func (l *Ledger) NoteDispatch(provider string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dispatched++
	l.account(provider).dispatched++
}

// NoteVerified records that a receipt survived verification.
func (l *Ledger) NoteVerified(provider string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verified++
	l.account(provider).verified++
}

// NoteSettled records that a receipt was priced, whether or not it earned
// anything. A zero charge is still settled: the Hub accounted for it, and the
// provider can be shown why it earned nothing.
func (l *Ledger) NoteSettled(provider string, micros uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.settled++
	l.revenue += micros
	account := l.account(provider)
	account.settled++
	account.revenue += micros
}

// NoteCommission records the Hub's cut on a settled charge, in the same
// provider-scoped micro-units as the charge it is taken from.
func (l *Ledger) NoteCommission(provider string, micros uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.commission += micros
	account := l.account(provider)
	account.commission += micros
}

func (l *Ledger) account(provider string) *providerAccount {
	account := l.accounts[provider]
	if account == nil {
		account = &providerAccount{}
		l.accounts[provider] = account
	}
	return account
}

// ProviderAccount is one provider's line in the ledger.
type ProviderAccount struct {
	Dispatched int
	Verified   int
	Settled    int
	Revenue    uint64
	Commission uint64
}

// Snapshot is a point-in-time copy of the ledger. Reading the counters
// individually would let a concurrent caller observe a total and a per-provider
// breakdown from different instants, which do not add up.
type Snapshot struct {
	Dispatched int
	Verified   int
	Settled    int
	Revenue    uint64
	Commission uint64
	ByProvider map[string]ProviderAccount
}

// Snapshot returns a consistent copy of the ledger.
func (l *Ledger) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()

	byProvider := make(map[string]ProviderAccount, len(l.accounts))
	for provider, account := range l.accounts {
		byProvider[provider] = ProviderAccount{
			Dispatched: account.dispatched,
			Verified:   account.verified,
			Settled:    account.settled,
			Revenue:    account.revenue,
			Commission: account.commission,
		}
	}
	return Snapshot{
		Dispatched: l.dispatched,
		Verified:   l.verified,
		Settled:    l.settled,
		Revenue:    l.revenue,
		Commission: l.commission,
		ByProvider: byProvider,
	}
}
