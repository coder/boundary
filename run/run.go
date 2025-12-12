package run

import "context"

func Run(ctx context.Context, logger *slog.Logger, config config.AppConfig, args []string) error {
	//if isChild() {
	//	return RunChild(logger, args)
	//}
	//
	//return RunParent(ctx, logger, args, config)
}
