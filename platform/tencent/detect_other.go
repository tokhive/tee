//go:build !linux || mobile

package tencent

// hostTEETech reports false off Linux: there is no Tencent TEE device node to
// probe, so the adapter cannot verify the host and fails closed.
func hostTEETech() (teeTech string, ok bool) {
	return "", false
}
