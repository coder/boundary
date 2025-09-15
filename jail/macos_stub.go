//go:build !darwin

package jail

import "fmt"

// NewMacOSJail is not available on non-macOS platforms
func NewMacOSJail(_ Config) (Jailer, error) {
	return nil, fmt.Errorf("macOS jail not supported on this platform")
}