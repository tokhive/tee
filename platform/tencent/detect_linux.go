//go:build linux && !mobile

package tencent

import (
	"os"
	"strings"
)

// hostTEETech reports whether this process runs on a Tencent Cloud
// confidential-computing guest, and which TEE technology is present. Detection
// is best-effort: the DMI system vendor is matched for "Tencent", and the guest
// TEE device nodes (/dev/sgx_enclave for Intel SGX, /dev/tdx_guest for Intel
// TDX, /dev/sev-guest for AMD SEV-SNP) decide the technology. Unknown future
// devices fail closed — the adapter refuses to start.
func hostTEETech() (teeTech string, ok bool) {
	v, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil || !strings.Contains(strings.ToLower(string(v)), "tencent") {
		return "", false
	}
	for _, dev := range []struct {
		path string
		tech string
	}{
		{"/dev/sev-guest", "amd-sev-snp"},
		{"/dev/tdx_guest", "intel-tdx"},
		{"/dev/sgx_enclave", "intel-sgx"},
	} {
		if _, err := os.Stat(dev.path); err == nil {
			return dev.tech, true
		}
	}
	return "", false
}
