package run

import (
	"context"
	"log/slog"

	"github.com/coder/boundary/config"
)

func Run(ctx context.Context, logger *slog.Logger, config config.AppConfig) error {
	//if isChild() {
	//	return RunChild(logger, args)
	//}
	//
	//return RunParent(ctx, logger, args, config)
}
