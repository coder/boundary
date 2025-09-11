//go:build !darwin

package namespace

// NewMacOS is not available on non-macOS platforms
func NewMacOS(_ Config) (*noop, error) {
	panic("macOS network jail not available on this platform")
}
