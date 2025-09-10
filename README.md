# jail

**Network isolation tool for monitoring and restricting HTTP/HTTPS requests from processes**

jail creates an isolated network environment for target processes, intercepting all HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.

## Features

- 🔒 **Process-level network isolation** - Linux namespaces, macOS process groups
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🎯 **Wildcard pattern matching** - Simple `*` wildcards for URL patterns
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults
- 🛡️ **Default deny-all** - Secure by default, only allow what you explicitly permit

## Quick Start

### Installation

**From GitHub Releases (Recommended):**
```bash
# Download the latest release for your platform
wget https://github.com/coder/jail/releases/latest/download/jail-linux-amd64.tar.gz
tar -xzf jail-linux-amd64.tar.gz
chmod +x jail
sudo mv jail /usr/local/bin/
```

**Build from Source:**
```bash
git clone https://github.com/coder/jail
cd jail
make build  # or: go build -o jail .
```

### Usage

```bash
# Allow only requests to github.com
jail --allow "github.com" -- curl https://github.com

# Allow full access to GitHub issues API, but only GET/HEAD elsewhere on GitHub
jail \
  --allow "github.com/api/issues/*" \
  --allow "GET,HEAD github.com" \
  -- npm install

# Default deny-all: everything is blocked unless explicitly allowed
jail -- curl https://example.com
```

## Allow Rules

jail uses simple wildcard patterns for URL matching.

### Rule Format

```text
--allow "pattern"
--allow "METHOD[,METHOD] pattern"
```

- If only a pattern is provided, all HTTP methods are allowed
- If methods are provided, only those HTTP methods are allowed (case-insensitive)
- Patterns use wildcards: `*` (matches any characters)

### Examples

```bash
# Basic patterns
jail --allow "github.com" -- git pull

# Wildcard patterns
jail --allow "*.github.com" -- npm install    # GitHub subdomains
jail --allow "api.*" -- ./app                 # Any API domain

# Method-specific rules
jail --allow "GET,HEAD api.github.com" -- curl https://api.github.com
```

**Default Policy:** All traffic is denied unless explicitly allowed.

## Logging

```bash
# Monitor all requests with info logging
jail --log-level info --allow "*" -- npm install

# Debug logging for troubleshooting
jail --log-level debug --allow "github.com" -- git pull

# Error-only logging
jail --log-level error --allow "*" -- ./app
```

**Log Levels:**
- `error`: Shows only errors
- `warn`: Shows blocked requests and errors (default)
- `info`: Shows all requests (allowed and blocked)
- `debug`: Shows detailed information including TLS operations

## Blocked Request Messages

When a request is blocked, jail provides helpful guidance:

```
🚫 Request Blocked by Jail

Request: GET /
Host: google.com
Reason: No matching allow rules (default deny-all policy)

To allow this request, restart jail with:
  --allow "google.com"                    # Allow all methods to this host
  --allow "GET google.com"          # Allow only GET requests to this host

For more help: https://github.com/coder/jail
```

## Platform Support

| Platform | Implementation | Sudo Required |
|----------|----------------|---------------|
| Linux    | Network namespaces + iptables | Yes |
| macOS    | Process groups + PF rules | Yes |
| Windows  | Not supported | - |

## Installation

### From GitHub Releases (Recommended)

Download pre-built binaries from [GitHub Releases](https://github.com/coder/jail/releases):

```bash
# Linux x64
wget https://github.com/coder/jail/releases/latest/download/jail-linux-amd64.tar.gz
tar -xzf jail-linux-amd64.tar.gz
chmod +x jail
sudo mv jail /usr/local/bin/

# macOS (Intel)
wget https://github.com/coder/jail/releases/latest/download/jail-darwin-amd64.tar.gz
tar -xzf jail-darwin-amd64.tar.gz
chmod +x jail
sudo mv jail /usr/local/bin/

# macOS (Apple Silicon)
wget https://github.com/coder/jail/releases/latest/download/jail-darwin-arm64.tar.gz
tar -xzf jail-darwin-arm64.tar.gz
chmod +x jail
sudo mv jail /usr/local/bin/
```

### Build from Source

#### Prerequisites

**Linux:**
- Linux kernel 3.8+ (network namespace support)
- iptables
- Go 1.25+ (for building)
- sudo access

**macOS:**
- macOS 10.15+ (Catalina or later)
- pfctl (included)
- Go 1.25+ (for building)
- sudo access

#### Building

```bash
git clone https://github.com/coder/jail
cd jail

# Using Makefile (recommended)
make build

# Or directly with Go
go build -o jail .
```

## TLS Interception

jail automatically generates a Certificate Authority (CA) to intercept HTTPS traffic:

- CA stored in `~/.config/jail/` (or `$XDG_CONFIG_HOME/jail/`)
- CA certificate provided via `JAIL_CA_CERT` environment variable
- Certificates generated on-demand for intercepted domains
- CA expires after 1 year

### Disable TLS Interception

```bash
jail --no-tls-intercept --allow "*" -- ./app
```

## Command-Line Options

```text
jail [flags] -- command [args...]

OPTIONS:
    --allow <SPEC>             Allow rule (repeatable)
                               Format: "pattern" or "METHOD[,METHOD] pattern"
    --log-level <LEVEL>        Set log level (error, warn, info, debug)
    --no-tls-intercept         Disable HTTPS interception
    -h, --help                 Print help
```

## Development

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test

# Run tests with coverage
make test-coverage

# Clean build artifacts
make clean

# Format code
make fmt

# Lint code (requires golangci-lint)
make lint
```

### Manual Commands

```bash
# Build directly with Go
go build -o jail .

# Run tests
go test ./...

# Cross-compile manually
GOOS=linux GOARCH=amd64 go build -o jail-linux .
GOOS=darwin GOARCH=amd64 go build -o jail-macos .

# Use build script for all platforms
./scripts/build.sh
```

## License

MIT License - see LICENSE file for details.