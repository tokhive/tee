package shared

import (
	"crypto/tls"
	"fmt"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"

	"github.com/gorilla/websocket"
)

// extractTLSCertFromWebSocket extracts the peer TLS certificate from a WebSocket connection
func ExtractTLSCertFromWebSocket(conn *websocket.Conn) ([]byte, error) {
	underlying := conn.NetConn()

	tlsConn, ok := underlying.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a TLS connection")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}

	return state.PeerCertificates[0].Raw, nil
}

// ExtractPCR0FromAttestation extracts PCR0 from platform-specific attestation as string
func ExtractPCR0FromAttestation(attestation *teeproto.AttestationReport, logger *Logger) (string, error) {
	switch attestation.Type {
	case "gcp":
		return ExtractImageDigestFromGCPAttestation(attestation.Report, logger)
	default:
		return "", fmt.Errorf("unknown attestation type: %s", attestation.Type)
	}
}

// ExtractUserDataFromGCPAttestation extracts userData from GCP Confidential Space attestation token
func ExtractUserDataFromGCPAttestation(token []byte, logger *Logger) (string, error) {
	// Validate JWT signature and extract userData from eat_nonce claim
	userData, err := ValidateGCPAttestationAndExtractUserData(token, logger)
	if err != nil {
		return "", fmt.Errorf("GCP attestation validation failed: %v", err)
	}
	return userData, nil
}
