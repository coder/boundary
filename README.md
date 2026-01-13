# boundary

Network isolation tool for monitoring and restricting HTTP/HTTPS requests from processes.

boundary creates an isolated network environment for target processes, intercepting HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.

## Features

 - Process-level network isolation (Linux namespaces)
- HTTP/HTTPS interception with transparent proxy and TLS certificate injection
- Wildcard pattern matching for URL patterns
- Request logging and monitoring
 - Linux support
- Default deny-all security model

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/coder/boundary/main/install.sh | bash
```

> For installation options, manual installation, and release details, see [RELEASES.md](RELEASES.md).

### From Source

Build `boundary` from source:

```bash
# Clone the repository
git clone https://github.com/coder/boundary.git
cd boundary

# Build the binary
make build

# Install binary and wrapper script (optional)
sudo cp boundary /usr/local/bin/
sudo cp scripts/boundary-wrapper.sh /usr/local/bin/boundary-run
sudo chmod +x /usr/local/bin/boundary-run
```

**Requirements:**
- Go 1.24 or later
- Linux

## Usage

### Quick Start with Shortcut

The recommended way to run `boundary` is using the `boundary-run` shortcut, which handles privilege escalation automatically. The `boundary-run` wrapper is installed automatically when you use the installation script:

```bash
# After installation, use the shortcut:
boundary-run --allow "domain=github.com" -- curl https://github.com
boundary-run -- bash
```

> **Note:** If you installed `boundary` manually, you can install the wrapper script separately:
> ```bash
> sudo cp scripts/boundary-wrapper.sh /usr/local/bin/boundary-run
> sudo chmod +x /usr/local/bin/boundary-run
> ```

### Direct Usage

If you prefer to run `boundary` directly, you'll need to handle privilege escalation:

```bash
# Note: sys_admin is only needed in restricted environments (e.g., Docker with seccomp).
# If boundary works without it on your system, you can remove +sys_admin from both flags.
sudo -E env PATH=$PATH setpriv \
  --reuid=$(id -u) \
  --regid=$(id -g) \
  --clear-groups \
  --inh-caps=+net_admin,+sys_admin \
  --ambient-caps=+net_admin,+sys_admin \
  boundary --allow "domain=github.com" -- curl https://github.com
```

### Examples

```bash
# Allow only requests to github.com
boundary-run --allow "domain=github.com" -- curl https://github.com

# Allow full access to GitHub issues API, but only GET/HEAD elsewhere on GitHub
boundary-run \
  --allow "domain=github.com path=/api/issues/*" \
  --allow "method=GET,HEAD domain=github.com" \
  -- npm install

# Default deny-all: everything is blocked unless explicitly allowed
boundary-run -- curl https://example.com
```

## Allow Rules

### Format
```text
--allow "key=value [key=value ...]"
```

**Keys:**
- `method` - HTTP method(s), comma-separated (GET, POST, etc.)
- `domain` - Domain/hostname pattern
- `path` - URL path pattern(s), comma-separated

### Examples
```bash
boundary-run --allow "domain=github.com" -- git pull
boundary-run --allow "domain=*.github.com" -- npm install           # GitHub subdomains
boundary-run --allow "method=GET,HEAD domain=api.github.com" -- curl https://api.github.com
boundary-run --allow "method=POST domain=api.example.com path=/users,/posts" -- ./app  # Multiple paths
boundary-run --allow "path=/api/v1/*,/api/v2/*" -- curl https://api.example.com/api/v1/users
```

Wildcards: `*` matches any characters. All traffic is denied unless explicitly allowed.

## Logging

```bash
boundary-run --log-level warn --allow "domain=github.com" -- git pull  # Default: only logs denied requests
boundary-run --log-level info --allow "method=*" -- npm install     # Show all requests
boundary-run --log-level debug --allow "domain=github.com" -- git pull  # Debug info
```

**Log Levels:** `error`, `warn` (default), `info`, `debug`

## Audit Logs

Boundary tracks all HTTP/HTTPS requests that pass through the transparent proxy, recording
whether each request was allowed or denied. This provides visibility into network access
patterns for monitoring and compliance. By default, all requests are logged to stderr using
structured logging.

### Coder Integration

When running inside a Coder workspace, boundary can forward audit logs to the workspace
agent, which then sends them to coderd for centralized logging. The intention is for
these logs to work out of the box when an AI agent runs in a workspace using a module
that has boundary enabled (e.g. the [Claude Code](https://registry.coder.com/modules/coder/claude-code)
module), and when `boundary-run` is used directly.

**How it works:**

1. The workspace agent runs a Unix socket server at a configurable path (see:
   `--log-proxy-socket-path`)
2. Boundary connects to this socket and streams audit event batches using a [protobuf-based
   protocol](https://github.com/coder/coder/blob/0c5809726d61c628ecbd359ae47bb85e83700681/agent/boundarylogproxy/codec/codec.go)
   - If the socket doesn't exist when boundary starts, a warning is logged to stderr and
   no audit logs are forwarded. This will occur on versions of coder that do not yet support
   forwarding boundary audit logs
3. The workspace agent forwards these logs to coderd
4. coderd emits the logs as structured log entries for ingestion by log aggregation systems

## Platform Support

| Platform | Implementation                 | Privileges                |
|----------|--------------------------------|---------------------------|
| Linux    | Network namespaces + iptables  | CAP_NET_ADMIN (or root)   |
| macOS    | Not supported                  | -                         |
| Windows  | Not supported                  | -                         |

## Security and Privileges

**All processes are expected to run as non-root users** for security best practices:

- **boundary-parent**: The main boundary process that sets up network isolation
- **boundary-child**: The child process created within the network namespace
- **target/agent process**: The command you're running (e.g., `curl`, `npm`, `bash`)

The `boundary-run` wrapper script handles privilege escalation automatically using `setpriv` to drop privileges before launching boundary. This ensures all processes run with the minimum required capabilities (`CAP_NET_ADMIN` and optionally `CAP_SYS_ADMIN` for restricted environments) while executing as your regular user account.

If you run `boundary` directly with `sudo` (without `setpriv`), all processes will run as root, which is **not recommended** for security reasons. Always use `boundary-run` or the equivalent `setpriv` command shown in the [Direct Usage](#direct-usage) section.

## Command-Line Options

```text
boundary-run [flags] -- command [args...]

 --config <PATH>                  Path to YAML config file (default: ~/.config/coder_boundary/config.yaml)
 --allow <SPEC>                   Allow rule (repeatable). Merged with allowlist from config file
 --log-level <LEVEL>              Set log level (error, warn, info, debug). Default: warn
 --log-dir <DIR>                  Directory to write logs to (default: stderr)
 --proxy-port <PORT>              HTTP proxy port (default: 8080)
 --pprof                          Enable pprof profiling server
 --pprof-port <PORT>              pprof server port (default: 6060)
 --disable-audit-logs             Disable sending audit logs to the workspace agent
 --log-proxy-socket-path <PATH>   Path to the audit log socket
 -h, --help                       Print help
```

Environment variables: `BOUNDARY_CONFIG`, `BOUNDARY_ALLOW`, `BOUNDARY_LOG_LEVEL`, `BOUNDARY_LOG_DIR`, `PROXY_PORT`, `BOUNDARY_PPROF`, `BOUNDARY_PPROF_PORT`, `DISABLE_AUDIT_LOGS`, `CODER_AGENT_BOUNDARY_LOG_PROXY_SOCKET_PATH`

## Development

```bash
make build          # Build for current platform
make build-all      # Build for all platforms
make test           # Run tests
make test-coverage  # Run tests with coverage
make clean          # Clean build artifacts
make fmt            # Format code
make lint           # Lint code
```

## Architecture

For detailed information about how `boundary` works internally, see [ARCHITECTURE.md](ARCHITECTURE.md).

## License

MIT License - see LICENSE file for details.