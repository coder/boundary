package cli

import (
	"os"
	"path/filepath"

	"github.com/coder/boundary/app"
	"github.com/coder/serpent"
)

// NewCommand creates and returns the root serpent command
func NewCommand() *serpent.Command {
	// To make the top level boundary command, we just make some minor changes to the base command
	cmd := BaseCommand()
	cmd.Use = "boundary [flags] -- command [args...]" // Add the flags and args pieces to usage.

	// Add example usage to the long description. This is different from usage as a subcommand because it
	// may be called something different when used as a subcommand / there will be a leading binary (i.e. `coder boundary` vs. `boundary`).
	cmd.Long += `Examples:
  # Allow only requests to github.com (requires sudo/capabilities)
  boundary-run --allow "domain=github.com" -- curl https://github.com

  # Simple mode - no special permissions required
  boundary --simple --allow "domain=github.com" -- curl https://github.com

  # Monitor all requests to specific domains (allow only those)
  boundary --simple --allow "domain=github.com" --allow "domain=api.npmjs.org" -- npm install

  # Use allowlist from config file with additional CLI allow rules
  boundary --simple --allow "domain=example.com" -- curl https://example.com

  # Block everything by default (implicit)`

	return cmd
}

// Base command returns the boundary serpent command without the information involved in making it the
// *top level* serpent command. We are creating this split to make it easier to integrate into the coder
// CLI if needed.
func BaseCommand() *serpent.Command {
	config := app.Config{}

	// Set default config path if file exists - serpent will load it automatically
	if home, err := os.UserHomeDir(); err == nil {
		defaultPath := filepath.Join(home, ".config", "coder_boundary", "config.yaml")
		if _, err := os.Stat(defaultPath); err == nil {
			config.Config = serpent.YAMLConfigPath(defaultPath)
		}
	}

	return &serpent.Command{
		Use:   "boundary",
		Short: "Network isolation tool for monitoring and restricting HTTP/HTTPS requests",
		Long:  `boundary creates an isolated network environment for target processes, intercepting HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.`,
		Options: []serpent.Option{
			{
				Flag:        "config",
				Env:         "BOUNDARY_CONFIG",
				Description: "Path to YAML config file.",
				Value:       &config.Config,
				YAML:        "",
			},
			{
				Flag:        "simple",
				Env:         "BOUNDARY_SIMPLE",
				Description: "Use simple mode (no network isolation, no special permissions required). Traffic is proxied via HTTP_PROXY/HTTPS_PROXY environment variables. Less secure: processes can bypass by ignoring proxy env vars.",
				Value:       &config.SimpleMode,
				YAML:        "simple",
			},
			{
				Flag:        "allow",
				Env:         "BOUNDARY_ALLOW",
				Description: "Allow rule (repeatable). These are merged with allowlist from config file. Format: \"pattern\" or \"METHOD[,METHOD] pattern\".",
				Value:       &config.AllowStrings,
				YAML:        "", // CLI only, not loaded from YAML
			},
			{
				Flag:        "allowlist",
				Env:         "BOUNDARY_ALLOWLIST",
				Description: "Allowlist rules from config file.",
				Value:       &config.AllowListStrings,
				YAML:        "allowlist",
				Hidden:      true, // Hide from CLI help since it's primarily for YAML config
			},
			{
				Flag:        "log-level",
				Env:         "BOUNDARY_LOG_LEVEL",
				Description: "Set log level (error, warn, info, debug).",
				Default:     "warn",
				Value:       &config.LogLevel,
				YAML:        "log_level",
			},
			{
				Flag:        "log-dir",
				Env:         "BOUNDARY_LOG_DIR",
				Description: "Set a directory to write logs to rather than stderr.",
				Value:       &config.LogDir,
				YAML:        "log_dir",
			},
			{
				Flag:        "proxy-port",
				Env:         "PROXY_PORT",
				Description: "Set a port for HTTP proxy.",
				Default:     "8080",
				Value:       &config.ProxyPort,
				YAML:        "proxy_port",
			},
			{
				Flag:        "pprof",
				Env:         "BOUNDARY_PPROF",
				Description: "Enable pprof profiling server.",
				Value:       &config.PprofEnabled,
				YAML:        "pprof_enabled",
			},
			{
				Flag:        "pprof-port",
				Env:         "BOUNDARY_PPROF_PORT",
				Description: "Set port for pprof profiling server.",
				Default:     "6060",
				Value:       &config.PprofPort,
				YAML:        "pprof_port",
			},
			{
				Flag:        "audit-socket",
				Env:         "BOUNDARY_AUDIT_SOCKET",
				Description: "Path to Unix socket for sending audit events to Coder agent.",
				Value:       &config.AuditSocket,
				YAML:        "audit_socket",
			},
			// OTLP Configuration
			{
				Flag:        "otlp-endpoint",
				Env:         "BOUNDARY_OTLP_ENDPOINT",
				Description: "OTLP HTTP endpoint for exporting audit logs (e.g., https://collector:4318/v1/logs).",
				Value:       &config.OTLPEndpoint,
				YAML:        "otlp_endpoint",
			},
			{
				Flag:        "otlp-headers",
				Env:         "BOUNDARY_OTLP_HEADERS",
				Description: "Comma-separated key=value headers for OTLP requests (e.g., \"x-api-key=secret,x-team=platform\").",
				Value:       &config.OTLPHeaders,
				YAML:        "otlp_headers",
			},
			{
				Flag:        "otlp-insecure",
				Env:         "BOUNDARY_OTLP_INSECURE",
				Description: "Skip TLS certificate verification for OTLP endpoint (not recommended for production).",
				Value:       &config.OTLPInsecure,
				YAML:        "otlp_insecure",
			},
			{
				Flag:        "otlp-ca-cert",
				Env:         "BOUNDARY_OTLP_CA_CERT",
				Description: "Path to CA certificate file for OTLP TLS verification (for internal/custom CAs).",
				Value:       &config.OTLPCACert,
				YAML:        "otlp_ca_cert",
			},
			// Workspace metadata
			{
				Flag:        "workspace-id",
				Env:         "BOUNDARY_WORKSPACE_ID",
				Description: "Coder workspace ID to include in OTLP log attributes.",
				Value:       &config.WorkspaceID,
				YAML:        "workspace_id",
			},
			{
				Flag:        "workspace-name",
				Env:         "BOUNDARY_WORKSPACE_NAME",
				Description: "Coder workspace name to include in OTLP log attributes.",
				Value:       &config.WorkspaceName,
				YAML:        "workspace_name",
			},
			{
				Flag:        "workspace-owner",
				Env:         "BOUNDARY_WORKSPACE_OWNER",
				Description: "Coder workspace owner to include in OTLP log attributes.",
				Value:       &config.WorkspaceOwner,
				YAML:        "workspace_owner",
			},
		},
		Handler: func(inv *serpent.Invocation) error {
			args := inv.Args
			return app.Run(inv.Context(), config, args)
		},
	}
}
