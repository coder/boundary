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
  # Allow only requests to github.com
  boundary --allow "domain=github.com" -- curl https://github.com

  # Monitor all requests to specific domains (allow only those)
  boundary --allow "domain=github.com path=/api/issues/*" --allow "method=GET,HEAD domain=github.com" -- npm install

  # Use allowlist from config file with additional CLI allow rules
  boundary --allow "domain=example.com" -- curl https://example.com

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
				Flag:        "allow",
				Env:         "BOUNDARY_ALLOW",
				Description: "Allow rule (repeatable). These are merged with allowlist from config file. Format: \"pattern\" or \"METHOD[,METHOD] pattern\".",
				Value:       &config.AllowStrings,
				YAML:        "", // CLI only, not loaded from YAML
			},
			{
				Flag:        "", // No CLI flag, YAML only
				Description: "Allowlist rules from config file (YAML only).",
				Value:       &config.AllowListStrings,
				YAML:        "allowlist",
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
				Flag:        "configure-dns-for-local-stub-resolver",
				Env:         "BOUNDARY_CONFIGURE_DNS_FOR_LOCAL_STUB_RESOLVER",
				Description: "Configure DNS for local stub resolver (e.g., systemd-resolved). Only needed when /etc/resolv.conf contains nameserver 127.0.0.53.",
				Value:       &config.ConfigureDNSForLocalStubResolver,
				YAML:        "configure_dns_for_local_stub_resolver",
			},
			// OTLP Configuration
			{
				Flag:        "otlp-endpoint",
				Env:         "BOUNDARY_OTLP_ENDPOINT",
				Description: "OTLP HTTP endpoint for exporting audit logs (e.g., http://collector:4318).",
				Value:       &config.OTLPEndpoint,
				YAML:        "otlp_endpoint",
			},
			{
				Flag:        "otlp-headers",
				Env:         "BOUNDARY_OTLP_HEADERS",
				Description: "Comma-separated key=value headers for OTLP requests (e.g., \"x-api-key=secret\").",
				Value:       &config.OTLPHeaders,
				YAML:        "otlp_headers",
			},
			{
				Flag:        "otlp-insecure",
				Env:         "BOUNDARY_OTLP_INSECURE",
				Description: "Use HTTP instead of HTTPS for OTLP endpoint.",
				Value:       &config.OTLPInsecure,
				YAML:        "otlp_insecure",
			},
			{
				Flag:        "otlp-ca-cert",
				Env:         "BOUNDARY_OTLP_CA_CERT",
				Description: "Path to CA certificate file for OTLP TLS verification.",
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
