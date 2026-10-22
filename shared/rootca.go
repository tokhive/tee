package shared

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
)

var (
	customRootPool *x509.CertPool
	rootPoolMu     sync.RWMutex

	sysPoolOnce sync.Once
	sysPool     *x509.CertPool
)

// Loaded once; SystemCertPool clones per call. Error dropped on purpose: a nil
// pool means "system default". Shared pointer, so treat it as read-only.
func systemRootPool() *x509.CertPool {
	sysPoolOnce.Do(func() {
		sysPool, _ = x509.SystemCertPool()
	})
	return sysPool
}

// SetRootCAPool sets a custom root CA pool to use globally.
func SetRootCAPool(pool *x509.CertPool) {
	rootPoolMu.Lock()
	customRootPool = pool
	rootPoolMu.Unlock()
}

// GetRootCAPool returns the custom root CA pool if set, otherwise system pool.
func GetRootCAPool() *x509.CertPool {
	rootPoolMu.RLock()
	pool := customRootPool
	rootPoolMu.RUnlock()

	if pool != nil {
		return pool
	}

	// Fall back to system pool; nil makes crypto/tls use its own default
	return systemRootPool()
}

// IsCustomRootCAPool returns true if a custom root CA pool is set.
func IsCustomRootCAPool() bool {
	rootPoolMu.RLock()
	isCustom := customRootPool != nil
	rootPoolMu.RUnlock()
	return isCustom
}

// GetTLSConfig returns a TLS config with the current root CA pool.
// Use this when creating custom http.Transport or websocket.Dialer.
func GetTLSConfig() *tls.Config {
	return &tls.Config{RootCAs: GetRootCAPool()}
}
