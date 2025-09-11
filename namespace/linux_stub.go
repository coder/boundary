//go:build !linux

package namespace

import (
	"fmt"
)

// NewLinux is not available on non-Linux platforms
func NewLinux(_ Config) (*noop, error) {
	return nil, fmt.Errorf("linux network jail not supported on this platform")
}
