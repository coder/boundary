//go:build !linux

package jail

import (
	"fmt"
	"log/slog"
	"os/exec"
)

// LinuxJail is a stub for non-Linux platforms
type LinuxJail struct {
	logger *slog.Logger
}

func NewLinuxJail(config Config) (*LinuxJail, error) {
	return nil, fmt.Errorf("boundary jail is only supported on Linux")
}

func (l *LinuxJail) ConfigureBeforeCommandExecution() error {
	return fmt.Errorf("boundary jail is only supported on Linux")
}

func (l *LinuxJail) Command(command []string) *exec.Cmd {
	return nil
}

func (l *LinuxJail) ConfigureAfterCommandExecution(pidInt int) error {
	return fmt.Errorf("boundary jail is only supported on Linux")
}

func (l *LinuxJail) Close() error {
	return nil
}

// SimpleJail is a stub for non-Linux platforms
type SimpleJail struct {
	logger *slog.Logger
}

func NewSimpleJail(config Config) (*SimpleJail, error) {
	return nil, fmt.Errorf("boundary is only supported on Linux")
}

func (s *SimpleJail) ConfigureBeforeCommandExecution() error {
	return fmt.Errorf("boundary is only supported on Linux")
}

func (s *SimpleJail) Command(command []string) *exec.Cmd {
	return nil
}

func (s *SimpleJail) ConfigureAfterCommandExecution(pidInt int) error {
	return fmt.Errorf("boundary is only supported on Linux")
}

func (s *SimpleJail) Close() error {
	return nil
}
