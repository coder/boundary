//go:build !darwin

package namespace

import (
	"github.com/coder/jail"
)

// newMacOSJail is not available on non-macOS platforms
func newMacOSJail(_ Config) (jail.Commander, error) {
	panic("macOS network jail not available on this platform")
}
