//go:build linux

package run

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/coder/boundary/config"
	"github.com/coder/boundary/landjail"
	"github.com/coder/boundary/nsjail_manager"
	"github.com/google/uuid"
)

func Run(ctx context.Context, logger *slog.Logger, cfg config.AppConfig) error {
	cfg.SessionID = uuid.New()
	logger.Info("boundary session started", "session_id", cfg.SessionID.String())

	switch cfg.JailType {
	case config.NSJailType:
		return nsjail_manager.Run(ctx, logger, cfg)
	case config.LandjailType:
		return landjail.Run(ctx, logger, cfg)
	default:
		return fmt.Errorf("unknown jail type: %s", cfg.JailType)
	}
}
