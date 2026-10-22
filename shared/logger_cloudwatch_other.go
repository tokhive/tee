//go:build !linux && !mobile

package shared

import (
	"errors"

	"go.uber.org/zap/zapcore"
)

// newCloudWatchCore is a no-op off Linux — CloudWatch shipping is only used by
// the AWS SEV-SNP TEE, which is Linux. NewLogger then falls back to console.
func newCloudWatchCore(_ string, _ zapcore.Level) (zapcore.Core, error) {
	return nil, errors.New("cloudwatch logging only supported on linux")
}
