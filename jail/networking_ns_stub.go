//go:build !linux

package jail

import "fmt"

// SetupChildNetworking is a stub for non-Linux platforms
func SetupChildNetworking(vethNetJail string) error {
	return fmt.Errorf("boundary jail is only supported on Linux")
}
