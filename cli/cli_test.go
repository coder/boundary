package cli

import (
	"strings"
	"testing"

	"github.com/coder/serpent"
)

// MockPTY provides a simple mock for PTY-like testing
// This is a simplified version inspired by coder/coder's ptytest.
type MockPTY struct {
	t      *testing.T
	stdout strings.Builder
	stderr strings.Builder
}

// NewMockPTY creates a new mock PTY for testing
func NewMockPTY(t *testing.T) *MockPTY {
	return &MockPTY{t: t}
}

func (m *MockPTY) Attach(inv *serpent.Invocation) {
	inv.Stdout = &m.stdout
	inv.Stderr = &m.stderr
}

func (m *MockPTY) Stdout() string {
	return m.stdout.String()
}

func (m *MockPTY) Stderr() string {
	return m.stderr.String()
}

func (m *MockPTY) Clear() {
	m.stdout = strings.Builder{}
	m.stderr = strings.Builder{}
}

func TestPtySetupWorks(t *testing.T) {
	cmd := NewCommand()
	inv := cmd.Invoke("--help")

	pty := NewMockPTY(t)
	pty.Attach(inv)

	if err := inv.Run(); err != nil {
		t.Fatalf("could not run with simple --help arg: %v", err)
	}

	// TODO: A snapshot test setup is usually a good idea for CLI messages like this
	if !strings.Contains(pty.Stdout(), "Monitor and restrict HTTP/HTTPS requests from processes") {
		t.Fatalf("expected help to display summary, got: %s", pty.Stdout())
	}
}

func TestCurlGithub(t *testing.T) {
	cmd := NewCommand()
	inv := cmd.Invoke("--allow", "\"github.com\"", "--", "curl", "https://github.com")

	pty := NewMockPTY(t)
	pty.Attach(inv)

	if err := inv.Run(); err != nil {
		t.Fatalf("error curling github: %v", err)
	}
}
