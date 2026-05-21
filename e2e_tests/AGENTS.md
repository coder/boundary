# Boundary e2e test guidance

E2E tests in this directory are not normal unit tests. They can mutate host networking and require a suitable Linux sudo environment.

Read this file before changing or running e2e tests.

## Requirements

Expected tools and host features include:

- Linux
- sudo
- Go
- iptables
- ip
- nsenter
- curl
- dig
- nc
- Linux network namespaces
- Landlock support for landjail tests

## Safety rules

- Do not run e2e tests casually in a shared or fragile environment.
- Prefer focused package or test-name runs when debugging.
- Expect tests to create boundary binaries under temporary directories.
- Expect tests to create or inspect iptables rules, veth interfaces, and network namespaces.
- Check cleanup when a test fails or is interrupted.
- Do not delete unrelated host iptables rules during cleanup or debugging.

## Commands

The Makefile target is:

```sh
make e2e-test
```

It currently runs:

```sh
sudo $(which go) test -v -race ./e2e_tests -count=1
```

That target runs the root `e2e_tests` package only. It does not run every e2e subpackage. If you need subpackage coverage, choose the package deliberately and document what you ran.

Examples:

```sh
sudo $(which go) test -v -race ./e2e_tests/nsjail -count=1
sudo $(which go) test -v -race ./e2e_tests/landjail -count=1
```

## Common pitfalls

- DNS inside namespaces can fail if the host uses a stub resolver at `127.0.0.53`.
- iptables cleanup must remove exactly the rules added by setup.
- Port conflicts can occur when another boundary or proxy process is running.
- Existing sleeps in e2e helpers are not a pattern to copy. Prefer readiness checks when adding new tests.
- Some tests depend on external network behavior. Keep assertions focused and diagnostics clear.

## When editing tests

- Add targeted assertions for the behavior under test.
- Use unique ports, names, or temporary directories when tests can run concurrently.
- Preserve cleanup with `t.Cleanup` where possible.
- Capture enough diagnostics to debug host networking failures.
- Keep unit-level logic in package tests outside e2e when possible.
