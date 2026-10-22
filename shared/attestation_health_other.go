//go:build !linux || mobile

package shared

import "go.uber.org/zap"

// Non-Linux / mobile builds don't run in a SEV-SNP enclave; diagnostics and
// self-reset are no-ops so the shared package still compiles for the client.
func captureAttestationDiag(err error) []zap.Field { return nil }

func attestSelfReset(logger *Logger) {}

func isTerminalAttestWedge(err error) bool { return false }
