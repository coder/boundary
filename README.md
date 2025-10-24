# boundary

Network isolation tool for monitoring and restricting HTTP/HTTPS requests from processes.

boundary creates an isolated network environment for target processes, intercepting HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.

## Features

- Process-level network isolation (Linux namespaces, macOS process groups)
- HTTP/HTTPS interception with transparent proxy and TLS certificate injection
- Wildcard pattern matching for URL patterns
- Request logging and monitoring
- Cross-platform support (Linux and macOS)
- Default deny-all security model

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/coder/boundary/main/install.sh | bash
```

> For installation options, manual installation, and release details, see [RELEASES.md](RELEASES.md).

## Usage

```bash
# Allow only requests to github.com
boundary --allow "domain=github.com" -- curl https://github.com

# Allow full access to GitHub issues API, but only GET/HEAD elsewhere on GitHub
boundary \
  --allow "domain=github.com path=/api/issues/*" \
  --allow "method=GET,HEAD domain=github.com" \
  -- npm install

# Default deny-all: everything is blocked unless explicitly allowed
boundary -- curl https://example.com
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
boundary --allow "domain=github.com" -- git pull
boundary --allow "domain=*.github.com" -- npm install           # GitHub subdomains
boundary --allow "method=GET,HEAD domain=api.github.com" -- curl https://api.github.com
boundary --allow "method=POST domain=api.example.com path=/users,/posts" -- ./app  # Multiple paths
boundary --allow "path=/api/v1/*,/api/v2/*" -- curl https://api.example.com/api/v1/users
```

Wildcards: `*` matches any characters. All traffic is denied unless explicitly allowed.

## Logging

```bash
boundary --log-level info --allow "method=*" -- npm install     # Show all requests
boundary --log-level debug --allow "domain=github.com" -- git pull  # Debug info
```

**Log Levels:** `error`, `warn` (default), `info`, `debug`

## Unprivileged Mode

When you can't or don't want to run with sudo privileges, use `--unprivileged`:

```bash
# Run without network isolation (uses HTTP_PROXY/HTTPS_PROXY environment variables)
boundary --unprivileged --allow "domain=github.com" -- npm install

# Useful in containers or restricted environments
boundary --unprivileged --allow "domain=*.npmjs.org" --allow "domain=registry.npmjs.org" -- npm install
```

**Unprivileged Mode:**
- No network namespaces or firewall rules
- Works without sudo privileges  
- Uses proxy environment variables instead
- Applications must respect HTTP_PROXY/HTTPS_PROXY settings
- Less secure but more compatible

## Platform Support

| Platform | Implementation | Sudo Required |
|----------|----------------|---------------|
| Linux    | Network namespaces + iptables | Yes |
| macOS    | Process groups + PF rules | Yes |
| Windows  | Not supported | - |

## Command-Line Options

```text
boundary [flags] -- command [args...]

--allow <SPEC>             Allow rule (repeatable)
--log-level <LEVEL>        Set log level (error, warn, info, debug)
--unprivileged             Run without network isolation
-h, --help                 Print help
```

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