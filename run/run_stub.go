//go:build !linux

package run

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/coder/boundary/config"
)

func Run(ctx context.Context, logger *slog.Logger, cfg config.AppConfig) error {
	return fmt.Errorf("boundary is only supported on Linux, current platform: %s", runtime.GOOS)
}
