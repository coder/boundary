# Boundary Architecture

This document describes the architecture and components of boundary, a network isolation tool for monitoring and restricting HTTP/HTTPS requests.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               BOUNDARY SYSTEM                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ User Command:  boundary --allow "*.github.com" -- npm install               │
│                                     │                                       │
│                                     ▼                                       │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                            CLI LAYER                                    │ │
│ │  • Parse --allow rules                                                  │ │
│ │  • Configure log level                                                  │ │
│ │  • Setup components                                                     │ │
│ │  • Handle signals                                                       │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                       │
│                                     ▼                                       │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                        BOUNDARY CORE                                    │ │
│ │                                                                         │ │
│ │  ┌───────────────────┐    ┌─────────────────────┐                       │ │
│ │  │      JAILER       │    │    PROXY SERVER     │                       │ │
│ │  │                   │    │                     │                       │ │
│ │  │ Network Isolation │◄───┤ HTTP/HTTPS Handler  │                       │ │
│ │  │ Process Control   │    │ TLS Termination     │                       │ │
│ │  │                   │    │ Request Filtering   │                       │ │
│ │  └───────────────────┘    └─────────────────────┘                       │ │
│ │           │                          │                                  │ │
│ │           │                          ▼                                  │ │
│ │           │         ┌─────────────────────────────────────────────────┐ │ │
│ │           │         │            SUPPORT COMPONENTS                   │ │ │
│ │           │         │                                                 │ │ │
│ │           │         │  Rules Engine  │  Auditor  │  TLS Manager       │ │ │
│ │           │         │  • Pattern     │  • Log    │  • CA Certificate  │ │ │
│ │           │         │    Matching    │    Reqs   │  • Certificate     │ │ │
│ │           │         │  • Method      │  • Allow/ │    Generation      │ │ │
│ │           │         │    Filtering   │    Deny   │  • TLS Config      │ │ │
│ │           │         └─────────────────────────────────────────────────┘ │ │
│ │           │                                                             │ │
│ │           ▼                                                             │ │
│ │  ┌─────────────────────┐                                                │ │
│ │  │   TARGET COMMAND    │                                                │ │
│ │  │                     │                                                │ │
│ │  │   npm install       │  ◄── HTTP_PROXY/HTTPS_PROXY env vars           │ │
│ │  │   curl https://...  │  ◄── Network isolation (Linux/macOS)           │ │
│ │  │   git clone         │  ◄── DNS redirection                           │ │
│ │  │                     │                                                │ │
│ │  └─────────────────────┘                                                │ │
│ │                                                                         │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. CLI Layer
**Input**: Command line arguments (`--allow`, `--log-level`, `--unprivileged`, target command)
**Output**: Configured boundary instance and executed target command

**Responsibilities**:
- Parse and validate command line arguments
- Create rule engine from `--allow` specifications
- Setup logging configuration
- Initialize and coordinate all components
- Handle graceful shutdown on signals

### 2. Jailer Component
**Input**: Target command, proxy configuration
**Output**: Isolated process with network restrictions

Platform-specific implementations:

#### Linux Jailer
```
┌─────────────────────────────────────────────┐
│              LINUX JAILER                   │
├─────────────────────────────────────────────┤
│                                             │
│  Network Namespace Creation                 │
│  │                                          │
│  ├─ Create veth pair (host ↔ namespace)     │
│  ├─ Configure IP addresses                  │
│  ├─ Setup routing                           │
│  └─ Configure DNS resolution                │
│                                             │
│  iptables Rules                             │
│  │                                          │
│  ├─ REDIRECT all HTTP  → proxy (8080)       │
│  ├─ REDIRECT all HTTPS → proxy (8080)       │
│  └─ Allow localhost traffic                 │
│                                             │
│  Process Execution                          │
│  │                                          │
│  ├─ Set HTTP_PROXY env var                  │
│  ├─ Set HTTPS_PROXY env var                 │
│  ├─ Set SSL_CERT_FILE (custom CA)           │
│  └─ Execute in network namespace            │
│                                             │
└─────────────────────────────────────────────┘
```

#### macOS Jailer
```
┌─────────────────────────────────────────────┐
│              MACOS JAILER                   │
├─────────────────────────────────────────────┤
│                                             │
│  PF (Packet Filter) Rules                   │
│  │                                          │
│  ├─ Create custom anchor                    │
│  ├─ REDIRECT HTTP  → proxy (127.0.0.1:8080) │
│  ├─ REDIRECT HTTPS → proxy (127.0.0.1:8080) │
│  └─ Apply rules to specific process group   │
│                                             │
│  Process Group Isolation                    │
│  │                                          │
│  ├─ Create restricted group                 │
│  ├─ Set process group ID                    │
│  └─ Configure environment variables         │
│                                             │
│  Process Execution                          │
│  │                                          │
│  ├─ Set HTTP_PROXY env var                  │
│  ├─ Set HTTPS_PROXY env var                 │
│  ├─ Set SSL_CERT_FILE (custom CA)           │
│  └─ Execute with group restrictions         │
│                                             │
└─────────────────────────────────────────────┘
```

#### Unprivileged Jailer
```
┌─────────────────────────────────────────────┐
│           UNPRIVILEGED JAILER               │
├─────────────────────────────────────────────┤
│                                             │
│  Environment Variables Only                 │
│  │                                          │
│  ├─ Set HTTP_PROXY env var                  │
│  ├─ Set HTTPS_PROXY env var                 │
│  ├─ Set SSL_CERT_FILE (custom CA)           │
│  └─ No network isolation                    │
│                                             │
│  Process Execution                          │
│  │                                          │
│  ├─ Execute with proxy env vars             │
│  └─ Relies on application proxy support     │
│                                             │
│  Note: Less secure but works without sudo   │
│                                             │
└─────────────────────────────────────────────┘
```

### 3. Proxy Server Component
**Input**: HTTP/HTTPS requests from jailed processes
**Output**: Allowed requests forwarded to internet, denied requests blocked

```
┌─────────────────────────────────────────────────────────────────┐
│                        PROXY SERVER                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Connection Handler                                             │
│  │                                                              │
│  ├─ Listen on port 8080                                         │
│  ├─ Detect HTTP vs HTTPS (peek first byte)                      │
│  ├─ Route to appropriate handler                                │
│  └─ Handle connection errors                                    │
│                                                                 │
│  ┌─────────────────────┐  ┌───────────────────────────────────┐ │
│  │    HTTP HANDLER     │  │       HTTPS HANDLER               │ │
│  │                     │  │                                   │ │
│  │ • Direct requests   │  │ • CONNECT tunneling               │ │
│  │ • Apply rules       │  │ • TLS termination                 │ │
│  │ • Forward allowed   │  │ • Certificate generation          │ │
│  │ • Block denied      │  │ • Decrypt → HTTP → Re-encrypt     │ │
│  │                     │  │ • Apply rules to decrypted        │ │
│  └─────────────────────┘  └───────────────────────────────────┘ │
│           │                                │                    │
│           └────────────────┬───────────────┘                    │
│                            │                                    │
│                            ▼                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │               REQUEST PROCESSING                           │ │
│  │                                                            │ │
│  │  1. Extract method (GET, POST, etc.)                       │ │
│  │  2. Extract URL (https://github.com/user/repo)             │ │
│  │  3. Evaluate against rules                                 │ │
│  │  4. Audit request (log allow/deny decision)                │ │
│  │  5. Forward if allowed, block if denied                    │ │
│  │                                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Rules Engine
**Input**: HTTP method, URL, configured allow rules
**Output**: Allow/Deny decision with matching rule

```
┌─────────────────────────────────────────────────────────────────┐
│                       RULES ENGINE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Rule Structure                                                 │
│  │                                                              │
│  ├─ Pattern: "*.github.com", "api.*", "exact.com"               │
│  ├─ Methods: ["GET", "POST"] or nil (all methods)               │
│  └─ Raw: "allow GET,POST *.github.com" (for logging)            │
│                                                                 │
│  Pattern Matching                                               │
│  │                                                              │
│  ├─ Wildcard support: * matches any characters                  │
│  ├─ Case-insensitive matching                                   │
│  ├─ Protocol-agnostic: pattern "github.com" matches             │
│  │   both "http://github.com" and "https://github.com"          │
│  └─ Domain-only matching: "github.com" matches any path         │
│                                                                 │
│  Evaluation Process                                             │
│  │                                                              │
│  ├─ 1. Check each rule in order                                 │
│  ├─ 2. Verify method matches (if specified)                     │
│  ├─ 3. Apply wildcard pattern matching to URL                   │
│  ├─ 4. Return ALLOW + rule on first match                       │
│  └─ 5. Return DENY if no rules match (default deny-all)         │
│                                                                 │
│  Examples:                                                      │
│  • "*.github.com" → matches "api.github.com"                    │
│  • "GET github.com" → matches "GET https://github.com/user"     │
│  • "api.*" → matches "api.example.com"                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5. Auditor Component
**Input**: Request details and allow/deny decision
**Output**: Structured logs

```
┌──────────────────────────────────────────────────────────────────┐
│                         AUDITOR                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Request Information                                             │
│  │                                                               │
│  ├─ Method: GET, POST, PUT, DELETE, etc.                         │
│  ├─ URL: Full URL of the request                                 │
│  ├─ Allowed: boolean (true/false)                                │
│  └─ Rule: Matching rule string (if allowed)                      │
│                                                                  │
│  Log Output                                                      │
│  │                                                               │
│  ├─ ALLOW requests: INFO level                                   │
│  │   "ALLOW method=GET url=https://github.com rule=*.github.com" │
│  │                                                               │
│  └─ DENY requests: WARN level                                    │
│     "DENY method=GET url=https://example.com"                    │
│                                                                  │
│  Structured Logging                                              │
│  │                                                               │
│  ├─ Uses slog for structured output                              │
│  ├─ Machine-readable format                                      │
│  ├─ Filterable by log level                                      │
│  └─ Includes contextual information                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 6. TLS Manager
**Input**: Hostname from HTTPS requests
**Output**: Valid TLS certificates, CA certificate file

```
┌─────────────────────────────────────────────────────────────────┐
│                       TLS MANAGER                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Certificate Authority (CA)                                     │
│  │                                                              │
│  ├─ Generate root CA private key                                │
│  ├─ Create root CA certificate                                  │
│  ├─ Write CA cert to file system                                │
│  └─ Configure system to trust CA (via SSL_CERT_FILE)            │
│                                                                 │
│  Dynamic Certificate Generation                                 │
│  │                                                              │
│  ├─ On-demand cert creation per hostname                        │
│  ├─ Sign certificates with CA private key                       │
│  ├─ Cache certificates for reuse                                │
│  ├─ Include Subject Alternative Names (SAN)                     │
│  └─ Set appropriate validity periods                            │
│                                                                 │
│  TLS Termination                                                │
│  │                                                              │
│  ├─ Accept HTTPS connections                                    │
│  ├─ Present generated certificate                               │
│  ├─ Decrypt TLS traffic                                         │
│  ├─ Process as HTTP internally                                  │
│  └─ Re-encrypt for upstream connections                         │
│                                                                 │
│  Certificate Cache                                              │
│  │                                                              │
│  ├─ In-memory storage for performance                           │
│  ├─ Thread-safe access with mutex                               │
│  ├─ Key: hostname                                               │
│  └─ Value: *tls.Certificate                                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Request Flow Examples

### HTTP Request Flow
```
1. Target Process (npm install)
   ├─ Makes HTTP request to registry.npmjs.org
   ├─ HTTP_PROXY env var points to localhost:8080
   └─ Request sent to boundary proxy

2. Jailer (Network Isolation)
   ├─ iptables/PF rules intercept request
   ├─ Redirect to proxy server (port 8080)
   └─ Process isolated in namespace/group

3. Proxy Server
   ├─ Receive HTTP request
   ├─ Extract method=GET, url=http://registry.npmjs.org/package
   └─ Route to HTTP handler

4. Rules Engine
   ├─ Evaluate "GET http://registry.npmjs.org/package"
   ├─ Check against rules: ["*.npmjs.org"]
   ├─ Pattern "*.npmjs.org" matches "registry.npmjs.org"
   └─ Return: ALLOW + rule="*.npmjs.org"

5. Auditor
   ├─ Log: "ALLOW method=GET url=http://registry.npmjs.org/package rule=*.npmjs.org"
   └─ Output to structured log

6. Request Forwarding
   ├─ Create upstream HTTP request
   ├─ Forward to registry.npmjs.org
   ├─ Receive response
   └─ Return response to target process
```

### HTTPS Request Flow
```
1. Target Process (curl https://github.com)
   ├─ Makes HTTPS request to github.com
   ├─ HTTPS_PROXY env var points to localhost:8080
   └─ Sends CONNECT request to proxy

2. Jailer (Network Isolation)
   ├─ iptables/PF rules intercept CONNECT
   ├─ Redirect to proxy server (port 8080)
   └─ Process sees custom CA certificate

3. Proxy Server (CONNECT Handler)
   ├─ Receive "CONNECT github.com:443"
   ├─ Accept connection
   └─ Wait for TLS handshake

4. TLS Manager
   ├─ Generate certificate for "github.com"
   ├─ Sign with boundary CA
   ├─ Present certificate to client
   └─ Establish TLS connection

5. HTTPS Handler
   ├─ Decrypt TLS traffic
   ├─ Parse HTTP request: "GET / HTTP/1.1 Host: github.com"
   └─ Route to request processing

6. Rules Engine
   ├─ Evaluate "GET https://github.com/"
   ├─ Check against rules: ["*.github.com"]
   ├─ Pattern "*.github.com" matches "github.com"
   └─ Return: ALLOW + rule="*.github.com"

7. Auditor
   ├─ Log: "ALLOW method=GET url=https://github.com/ rule=*.github.com"
   └─ Output to structured log

8. Request Forwarding
   ├─ Create upstream HTTPS request
   ├─ Connect to real github.com:443
   ├─ Forward decrypted HTTP request
   ├─ Receive response
   ├─ Encrypt response with boundary TLS
   └─ Return to target process
```

### Denied Request Flow
```
1. Target Process (curl https://malicious.com)
   ├─ Makes HTTPS request to malicious.com
   └─ Request intercepted by boundary

2. Proxy Server Processing
   ├─ Extract method=GET, url=https://malicious.com/
   └─ Route to rules engine

3. Rules Engine
   ├─ Evaluate "GET https://malicious.com/"
   ├─ Check against rules: ["*.github.com", "*.npmjs.org"]
   ├─ No patterns match "malicious.com"
   └─ Return: DENY (default deny-all)

4. Auditor
   ├─ Log: "DENY method=GET url=https://malicious.com/"
   └─ Output to structured log

5. Request Blocking
   ├─ Return HTTP 403 Forbidden
   ├─ Include boundary error message
   └─ Close connection
```

## Platform Differences

| Aspect | Linux | macOS | Unprivileged |
|--------|--------|--------|--------------|
| **Isolation** | Network namespaces | Process groups + PF | Environment variables only |
| **Traffic Interception** | iptables REDIRECT | PF rdr rules | HTTP_PROXY/HTTPS_PROXY |
| **DNS** | Custom resolv.conf | System DNS + PF | System DNS |
| **Privileges** | Requires sudo | Requires sudo | No privileges required |
| **Security** | Strong isolation | Moderate isolation | Weak (app-dependent) |
| **Compatibility** | Linux kernel 3.8+ | macOS with PF | Any platform |
| **Process Control** | Network namespace | Process group | Standard process |

## Security Model

### Default Deny-All
- All network requests are blocked by default
- Only explicitly allowed patterns are permitted
- Fail-safe behavior: unknown requests are denied

### Network Isolation
- Process cannot bypass boundary (except in unprivileged mode)
- All traffic routed through proxy server
- TLS interception prevents encrypted bypass

### Certificate Authority
- Boundary acts as trusted CA for intercepted HTTPS
- Generated certificates signed by boundary CA
- Target processes trust boundary CA via SSL_CERT_FILE

### Audit Trail
- All requests (allowed and denied) are logged
- Structured logging for analysis
- Rule attribution for allowed requests
