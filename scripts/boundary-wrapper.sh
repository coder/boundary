#!/bin/bash
# Wrapper script for boundary that handles privilege escalation
# This makes it convenient to run boundary without typing the long sudo+setpriv command

# Find boundary binary
BOUNDARY_BIN=""
if [ -n "$BOUNDARY_BIN_PATH" ]; then
    BOUNDARY_BIN="$BOUNDARY_BIN_PATH"
elif command -v boundary >/dev/null 2>&1; then
    BOUNDARY_BIN="$(command -v boundary)"
else
    echo "Error: boundary binary not found. Please install boundary or set BOUNDARY_BIN_PATH." >&2
    exit 1
fi

# Run boundary with proper privilege handling
# Note: sys_admin is only needed in restricted environments (e.g., Docker with seccomp).
# If boundary works without it on your system, you can remove +sys_admin from both flags.
exec sudo -E env PATH="$PATH" setpriv \
    --reuid="$(id -u)" \
    --regid="$(id -g)" \
    --clear-groups \
    --inh-caps=+net_admin,+sys_admin \
    --ambient-caps=+net_admin,+sys_admin \
    "$BOUNDARY_BIN" "$@"

