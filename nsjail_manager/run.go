package nsjail_manager

import (
	"context"
	"log/slog"
	"os"

	"github.com/coder/boundary/config"
)

func isChild() bool {
	return os.Getenv("CHILD") == "true"
}

// Run is the main entry point that determines whether to execute as a parent or child process.
// If running as a child (CHILD env var is set), it sets up networking in the namespace
// and executes the target command. Otherwise, it runs as the parent process, setting up the jail,
// proxy server, and managing the child process lifecycle.
func Run(ctx context.Context, logger *slog.Logger, config config.AppConfig, args []string) error {
	if isChild() {
		return RunChild(logger, args)
	}

	return RunParent(ctx, logger, args, config)
}
