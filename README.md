# boundary

**Network isolation tool for monitoring and restricting HTTP/HTTPS requests from processes**

boundary creates an isolated network environment for target processes, intercepting all HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.

## Features

- 🔒 **Process-level network isolation** - Linux namespaces, macOS process groups
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🎯 **Wildcard pattern matching** - Simple `*` wildcards for URL patterns
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults
- 🛡️ **Default deny-all** - Secure by default, only allow what you explicitly permit

## Quick Start

```bash
# Build the tool
go build -o boundary .

# Allow only requests to github.com
./boundary --allow "github.com" -- curl https://github.com

# Allow full access to GitHub issues API, but only GET/HEAD elsewhere on GitHub
./boundary \
  --allow "github.com/api/issues/*" \
  --allow "GET,HEAD github.com" \
  -- npm install

# Default deny-all: everything is blocked unless explicitly allowed
./boundary -- curl https://example.com
```

## Allow Rules

boundary uses simple wildcard patterns for URL matching.

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
boundary --allow "github.com" -- git pull

# Wildcard patterns
boundary --allow "*.github.com" -- npm install    # GitHub subdomains
boundary --allow "api.*" -- ./app                 # Any API domain

# Method-specific rules
boundary --allow "GET,HEAD api.github.com" -- curl https://api.github.com
```

**Default Policy:** All traffic is denied unless explicitly allowed.

## Logging

```bash
# Monitor all requests with info logging
boundary --log-level info --allow "*" -- npm install

# Debug logging for troubleshooting
boundary --log-level debug --allow "github.com" -- git pull

# Error-only logging
boundary --log-level error --allow "*" -- ./app
```

**Log Levels:**
- `error`: Shows only errors
- `warn`: Shows blocked requests and errors (default)
- `info`: Shows all requests (allowed and blocked)
- `debug`: Shows detailed information including TLS operations

## Blocked Request Messages

When a request is blocked, boundary provides helpful guidance:

```
🚫 Request Blocked by Boundary

Request: GET /
Host: google.com
Reason: No matching allow rules (default deny-all policy)

To allow this request, restart boundary with:
  --allow "google.com"                    # Allow all methods to this host
  --allow "GET google.com"          # Allow only GET requests to this host

For more help: https://github.com/coder/boundary
```

## Platform Support

| Platform | Implementation | Sudo Required |
|----------|----------------|---------------|
| Linux    | Network namespaces + iptables | Yes |
| macOS    | Process groups + PF rules | Yes |
| Windows  | Not supported | - |

## Installation

### Prerequisites

**Linux:**
- Linux kernel 3.8+ (network namespace support)
- iptables
- Go 1.21+ (for building)
- sudo access

**macOS:**
- macOS 10.15+ (Catalina or later)
- pfctl (included)
- Go 1.21+ (for building)
- sudo access

### Build from Source

```bash
git clone https://github.com/coder/boundary
cd boundary
go build -o boundary .
```

## TLS Interception

boundary automatically generates a Certificate Authority (CA) to intercept HTTPS traffic:

- CA stored in `~/.config/boundary/` (or `$XDG_CONFIG_HOME/boundary/`)
- CA certificate provided via `BOUNDARY_CA_CERT` environment variable
- Certificates generated on-demand for intercepted domains
- CA expires after 1 year

### Disable TLS Interception

```bash
boundary --no-tls-intercept --allow "*" -- ./app
```

## Command-Line Options

```text
boundary [flags] -- command [args...]

OPTIONS:
    --allow <SPEC>             Allow rule (repeatable)
                               Format: "pattern" or "METHOD[,METHOD] pattern"
    --log-level <LEVEL>        Set log level (error, warn, info, debug)
    --no-tls-intercept         Disable HTTPS interception
    -h, --help                 Print help
```

## Development

```bash
# Build
go build -o boundary .

# Test
go test ./...

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o boundary-linux .
GOOS=darwin GOARCH=amd64 go build -o boundary-macos .
```

## License

MIT License - see LICENSE file for details.