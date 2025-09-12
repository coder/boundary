//go:build !linux

package namespace

import "fmt"

// NewUserNamespaceLinux is not available on non-Linux platforms
func NewUserNamespaceLinux(config Config) (Commander, error) {
	return nil, fmt.Errorf("user namespace jail not available on this platform")
}
