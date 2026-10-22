//go:build !linux || mobile

package shared

func RunSNPAttestationBrokerIfRequested() (bool, error) {
	return false, nil
}

func hasSNPAttestationBroker() bool { return false }

func resetGuestThroughSNPAttestationBroker() (bool, error) { return false, nil }
