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
sudo -E env PATH=$PATH setpriv \
  --reuid=$(id -u) \
  --regid=$(id -g) \
  --clear-groups \
  --inh-caps=+net_admin \
  --ambient-caps=+net_admin \
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

## Platform Support

| Platform | Implementation                 | Privileges                |
|----------|--------------------------------|---------------------------|
| Linux    | Network namespaces + iptables  | CAP_NET_ADMIN (or root)   |
| macOS    | Not supported                  | -                         |
| Windows  | Not supported                  | -                         |

## Command-Line Options

```text
boundary-run [flags] -- command [args...]

 --config <PATH>             Path to YAML config file (default: ~/.config/coder_boundary/config.yaml)
 --allow <SPEC>              Allow rule (repeatable). Merged with allowlist from config file
 --log-level <LEVEL>        Set log level (error, warn, info, debug). Default: warn
 --log-dir <DIR>             Directory to write logs to (default: stderr)
 --proxy-port <PORT>        HTTP proxy port (default: 8080)
 --pprof                     Enable pprof profiling server
 --pprof-port <PORT>         pprof server port (default: 6060)
 -h, --help                  Print help
```

Environment variables: `BOUNDARY_CONFIG`, `BOUNDARY_ALLOW`, `BOUNDARY_LOG_LEVEL`, `BOUNDARY_LOG_DIR`, `PROXY_PORT`, `BOUNDARY_PPROF`, `BOUNDARY_PPROF_PORT`

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

## License

MIT License - see LICENSE file for details.