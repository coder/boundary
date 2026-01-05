package nojail

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
// If running as a child (CHILD env var is set), it executes the target command with proxy
// environment variables but without any network restrictions.
// Otherwise, it runs as the parent process, sets up the proxy server and auditors,
// and manages the child process lifecycle.
func Run(ctx context.Context, logger *slog.Logger, config config.AppConfig) error {
	if isChild() {
		return RunChild(logger, config)
	}

	return RunParent(ctx, logger, config)
}
