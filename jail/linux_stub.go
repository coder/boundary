//go:build !linux

package jail

import (
	"fmt"
)

// NewLinuxJail is not available on non-Linux platforms
func NewLinuxJail(_ Config) (Jailer, error) {
	return nil, fmt.Errorf("linux jail not supported on this platform")
}

// SetupChildNetworking is not available on non-Linux platforms
func SetupChildNetworking(vethNetJail string) error {
	return fmt.Errorf("child networking setup not supported on this platform")
}
