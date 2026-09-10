// Command gencerts generates the TLS fixture set used by the real cross-host
// cloudtest: the Hub↔TEE mTLS identities and the mock AI provider's TLS
// identity. The two CAs ride inside the measured bundle (so the TEE trusts
// only these CAs for the Hub client cert and the provider upstream), while the
// certificate/key pairs deploy to the ordinary host processes that present
// them.
//
//	gencerts <dir>   writes dir/{hub-ca,hub-cert,hub-key,mp-ca,mp-cert,mp-key}.pem
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gencerts <dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write", name, ":", err)
			os.Exit(1)
		}
	}
	hubCA, hubCert, hubKey, err := mtls.GenHubClientCerts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen hub certs:", err)
		os.Exit(1)
	}
	write("hub-ca.pem", hubCA)
	write("hub-cert.pem", hubCert)
	write("hub-key.pem", hubKey)
	mpCA, mpCert, mpKey, err := mtls.GenMockProviderCerts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen mock-provider certs:", err)
		os.Exit(1)
	}
	write("mp-ca.pem", mpCA)
	write("mp-cert.pem", mpCert)
	write("mp-key.pem", mpKey)
	fmt.Println(dir)
}