# Boundary architecture

Boundary is a Linux network isolation tool that runs a child process with restricted network access. It intercepts HTTP and HTTPS traffic, evaluates each request against allow rules, and records an audit trail of what was allowed or denied.

The practical goal is simple: run an agent or command with a default-deny network policy while still letting approved HTTP and HTTPS requests work normally.

## High-level model

Boundary has three moving parts:

1. **CLI and configuration** parse rules, logging options, jail options, and the target command.
2. **Jail backend** starts the target command in a restricted environment.
3. **Proxy and policy engine** inspect HTTP and HTTPS requests, allow or block them, and emit audit logs.

```text
user shell
   |
   | boundary --allow "domain=github.com" [separator] command args...
   v
boundary parent process
   |
   | parses config, creates policy engine, starts proxy, starts jail
   v
restricted child process
   |
   | HTTP and HTTPS traffic
   v
boundary proxy
   |
   | evaluates method, host, path
   +--> allowed: forward to upstream server
   +--> denied: return HTTP 403 and audit the denial
```

## Repository map

| Path | Responsibility |
|------|----------------|
| `cmd/boundary/main.go` | Binary entrypoint. Builds and runs the CLI command. |
| `cli/` | Command-line interface, flags, environment variables, YAML config loading, and privilege setup. |
| `config/` | Runtime configuration, user information, and session-correlation settings. |
| `run/` | Platform dispatch. Linux runs a jail backend. Non-Linux returns an unsupported-platform error. |
| `rulesengine/` | Allow-rule parsing and matching. |
| `proxy/` | HTTP and HTTPS proxy, transparent TLS detection, CONNECT support, forwarding, blocking, auditing, and session-correlation header injection. |
| `audit/` | Structured stderr audit logging and optional Coder workspace-agent socket forwarding. |
| `tls/` | Local CA management and per-host certificate generation for HTTPS interception. |
| `nsjail_manager/` | Default jail backend using Linux network namespaces, veth pairs, iptables, and dummy DNS. |
| `landjail/` | Alternative jail backend using Landlock restrictions and proxy environment variables. |
| `privilege/` | Linux privilege escalation through `sudo` and `setpriv` for the default backend. |
| `dnsdummy/` | DNS server used by the namespace backend to prevent DNS exfiltration. |
| `e2e_tests/` | Linux integration tests that require sudo and can mutate host networking. |

## Startup flow

The startup path is:

```text
cmd/boundary/main.go
   -> cli.NewCommand
   -> config.NewAppConfigFromCliConfig
   -> privilege.EnsurePrivileges, for nsjail only
   -> log.SetupLogging
   -> run.Run
   -> nsjail_manager.Run or landjail.Run
```

The CLI builds a `config.AppConfig` from flags, environment variables, optional YAML, and the target command. Then `run.Run` assigns a new session UUID and dispatches to the requested jail backend.

The default jail type is `nsjail`. That backend needs Linux network privileges, so the CLI calls `privilege.EnsurePrivileges()` before entering the runtime. If the current process does not have the required capabilities, Boundary re-execs itself through `sudo` and `setpriv` with the minimal capabilities it needs for networking setup.

The `landjail` backend does not use the same privilege escalation path.

## Parent and child process model

Both jail backends use a parent and child process model. The selected backend checks the `CHILD=true` environment variable to decide which role the current process should run.

### Parent process

The parent process owns setup and cleanup:

1. Parse allow rules.
2. Create the rule engine.
3. Set up audit logging.
4. Create or load the local CA.
5. Start the HTTP proxy.
6. Start the child process.
7. Wait for the child process to exit or for a termination signal.
8. Stop the proxy.
9. Clean up backend-specific resources.

### Child process

The child process runs the target command inside the restricted environment. Backend-specific setup happens before the target command starts.

For `nsjail`, the child configures namespace networking and DNS behavior before running the target. For `landjail`, the child applies Landlock network restrictions before running the target.

## Policy model

Boundary uses a default-deny policy. Requests are allowed only when at least one allow rule matches.

Allow rules are strings made of key-value pairs:

```text
method=GET,HEAD domain=github.com path=/api/*
```

Supported keys are:

- `method`: one or more HTTP methods, comma-separated. `*` matches every method.
- `domain`: an exact host or wildcard host pattern.
- `path`: one or more path patterns, comma-separated.

Important matching rules:

- `domain=github.com` matches only `github.com`.
- `domain=github.com` does not match `api.github.com`.
- `domain=*.github.com` matches subdomains such as `api.github.com`.
- `domain=*.github.com` does not match `github.com`.
- To allow a base domain and its subdomains, configure both patterns.
- Path wildcards are segment-based. A wildcard must be a whole path segment.

The engine returns both the allow or deny decision and the matching rule, if one matched. Audit logs include the matched rule for allowed requests.

## Proxy model

The proxy is the enforcement point for HTTP and HTTPS traffic.

It supports two styles of traffic:

1. **Transparent traffic**, where the target process does not know about the proxy. The `nsjail` backend redirects TCP traffic to Boundary with iptables.
2. **Explicit proxy traffic**, where the target process uses `HTTP_PROXY` and `HTTPS_PROXY`. The `landjail` backend uses this model.

### HTTP requests

For plain HTTP, the proxy reads the request, reconstructs the full URL when needed, evaluates the method, host, and path, then either forwards the request or returns a 403 response.

### HTTPS requests

For HTTPS, Boundary acts as a local TLS endpoint so it can inspect the HTTP request inside the encrypted stream. It uses a local CA and generates per-host certificates on demand.

The target process must trust Boundary's CA. Boundary injects common CA environment variables into the child process so tools such as curl, git, Python requests, and Node can trust the generated certificates.

### CONNECT requests

When a client uses Boundary as an explicit HTTP proxy for HTTPS, it sends a CONNECT request. Boundary accepts the CONNECT tunnel, performs TLS with the client, reads HTTP requests from inside the tunnel, and evaluates each request independently.

### Forwarding and blocking

For allowed requests, the proxy creates a new upstream request, copies appropriate headers, optionally injects session-correlation headers, and writes the upstream response back to the client.

For denied requests, the proxy returns HTTP 403 with a short message and example allow rules.

Every request is audited before the allow or deny handling completes.

## nsjail backend

`nsjail` is the default backend. It provides transparent network interception with Linux networking primitives.

The backend creates a point-to-point network between the host and child namespace:

```text
host namespace                         child network namespace

boundary proxy :8080                   target command
        ^                                      |
        |                                      | TCP traffic
iptables REDIRECT                             v
        |                               veth jail side
veth host side
```

Key details:

- The host side of the veth pair uses `192.168.100.1/24`.
- The child side uses `192.168.100.2/24`.
- The fixed subnet is `192.168.100.0/24`.
- iptables NAT and REDIRECT rules send TCP traffic from the child namespace to the Boundary proxy.
- Non-TCP forwarding rules allow return traffic for non-TCP flows.
- A dummy DNS server can run inside the namespace to prevent DNS exfiltration.
- `--use-real-dns` intentionally disables the dummy DNS behavior.
- `--no-user-namespace` disables user namespace creation for restricted environments.

The parent process configures host-side networking before the child runs. Once the child process exists, the parent moves the jail-side veth into the child's network namespace. The child then configures its IP address, loopback, and default route.

Cleanup removes the iptables rules and veth interface created during setup.

## landjail backend

`landjail` is an alternative backend based on Linux Landlock network restrictions.

Unlike `nsjail`, it does not rely on transparent iptables redirection. Instead, it configures the child process to use Boundary as an explicit proxy:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `http_proxy`
- `https_proxy`

It also clears `NO_PROXY` and `no_proxy` so the target command cannot bypass Boundary through proxy bypass lists.

Landlock restricts the child so it can connect only to the Boundary proxy port. This means the backend depends on clients honoring proxy environment variables. A client that ignores those variables will generally fail to connect rather than bypass Boundary.

## TLS and certificate trust

Boundary uses TLS interception for HTTPS so it can evaluate host, path, method, and headers in the request.

The TLS manager:

1. Finds the user's Boundary config directory.
2. Loads an existing local CA if present.
3. Generates a new local CA if needed.
4. Writes the CA certificate for child processes to trust.
5. Generates per-host certificates for incoming TLS connections.

The jail backends set environment variables for common tools:

- `SSL_CERT_FILE`
- `SSL_CERT_DIR`
- `CURL_CA_BUNDLE`
- `GIT_SSL_CAINFO`
- `REQUESTS_CA_BUNDLE`
- `NODE_EXTRA_CA_CERTS`

When Boundary runs through sudo, ownership and paths must still refer to the original user, not root, where possible.

## Audit logging

Boundary audits every HTTP and HTTPS request that reaches the proxy.

An audit record includes:

- method
- URL
- host
- allowed or denied decision
- matching rule for allowed requests
- per-session sequence number

Boundary always creates a stderr log auditor. When running inside a compatible Coder workspace, it can also forward audit batches to the workspace agent over a Unix socket. The workspace agent then forwards the logs to coderd for centralized logging.

`--disable-audit-logs` disables socket forwarding. It does not remove stderr logging.

## Session correlation

The proxy package contains support for injecting session-correlation headers into selected outbound requests. This is intended for Coder AI Gateway flows where downstream services need to correlate a Boundary audit event with an upstream request.

The headers are defined in `config/session_correlation.go`:

- `X-Coder-Agent-Firewall-Session-Id`
- `X-Coder-Agent-Firewall-Sequence-Number`

Injection targets use the same rule engine semantics as normal allow rules. When changing this area, verify the end-to-end runtime path from CLI config through the selected jail backend into `proxy.Config`; unit tests for proxy support alone are not enough.

## Security properties and limitations

Boundary is designed for HTTP and HTTPS control. The default policy is deny, but the enforcement point is the proxy and the selected jail backend.

Important limitations:

- Boundary is Linux-only for runtime enforcement.
- The `nsjail` backend redirects TCP traffic, but the proxy understands HTTP, HTTPS, and CONNECT-style traffic. Arbitrary non-HTTP TCP protocols are not supported as normal allowed traffic.
- DNS behavior is backend-specific. The namespace backend uses dummy DNS by default to reduce DNS exfiltration. `--use-real-dns` changes that intentionally.
- The landjail backend depends on clients using proxy environment variables.
- The fixed namespace subnet can conflict with local networking in unusual environments.
- E2E tests can mutate host networking and require careful cleanup.

## Development notes

Useful commands:

```sh
make build
make unit-test
make fmt
make fmt-check
make lint
```

E2E tests require Linux and sudo:

```sh
make e2e-test
```

Read `docs/e2e-tests.md` before running or changing e2e tests.

## Diagrams and related work

The original design sketch is preserved here for context:

<img width="1228" height="604" alt="Boundary" src="https://github.com/user-attachments/assets/1b7c8c5b-7b8f-4adf-8795-325bd28715c6" />

Anthropic's sandbox runtime is a related architecture worth comparing when thinking about alternative isolation designs:

https://github.com/anthropic-experimental/sandbox-runtime

<img width="879" height="688" alt="SRT" src="https://github.com/user-attachments/assets/eec16099-d6a0-4fae-b2ac-b766053b5fe3" />
