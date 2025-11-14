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

# Check if we're already running as the target user (not root)
if [ "$(id -u)" -eq 0 ]; then
    echo "Error: This wrapper should not be run as root. It will handle privilege escalation automatically." >&2
    exit 1
fi

# Run boundary with proper privilege handling
exec sudo -E env PATH="$PATH" setpriv \
    --reuid="$(id -u)" \
    --regid="$(id -g)" \
    --clear-groups \
    --inh-caps=+net_admin \
    --ambient-caps=+net_admin \
    "$BOUNDARY_BIN" "$@"

