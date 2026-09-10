// Command gencerts generates the Hub↔TEE mTLS fixture set used by the real
// cross-host cloudtest: a throwaway CA plus a Hub client certificate signed by
// it. The CA goes inside the measured bundle (so the TEE trusts only this Hub
// CA), while the client certificate/key go to the Hub on the ordinary host.
//
//   gencerts <dir>   writes dir/hub-ca.pem dir/hub-cert.pem dir/hub-key.pem
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
	caPEM, certPEM, keyPEM, err := mtls.GenHubClientCerts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen certs:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	for name, b := range map[string][]byte{
		"hub-ca.pem":   caPEM,
		"hub-cert.pem": certPEM,
		"hub-key.pem":  keyPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write", name, ":", err)
			os.Exit(1)
		}
	}
	fmt.Println(dir)
}