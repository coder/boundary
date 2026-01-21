//go:build !linux

package privilege

import (
	"fmt"
	"runtime"
)

// EnsurePrivileges is a no-op on non-Linux platforms.
func EnsurePrivileges() error {
	return fmt.Errorf("boundary is only supported on Linux, current platform: %s", runtime.GOOS)
}

