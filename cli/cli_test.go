package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/coder/serpent"
)

func ensureSudo(t *testing.T) {
	t.Helper()
	if os.Getgid() != 0 {
		t.Fatal("test requires root priviledges")
	}
}

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

func (m *MockPTY) ExpectMatch(content string) {
	if !strings.Contains(m.stdout.String(), content) {
		m.t.Fatalf("expected \"%s\", got: %s", content, m.stdout.String())
	}
}

func (m *MockPTY) ExpectError(content string) {
	if !strings.Contains(m.stderr.String(), content) {
		m.t.Fatalf("expected error with \"%s\", got: %s", content, m.stderr.String())
	}
}

func (m *MockPTY) RequireError() {
	if m.stderr.String() == "" {
		m.t.Fatal("expected error")
	}
}

func (m *MockPTY) RequireNoError() {
	if m.stderr.String() != "" {
		m.t.Fatalf("expected nothing in stderr, but got: %s", m.stderr.String())
	}
}

func TestPtySetupWorks(t *testing.T) {
	cmd := NewCommand()
	inv := cmd.Invoke("--help")

	pty := NewMockPTY(t)
	pty.Attach(inv)

	if err := inv.Run(); err != nil {
		t.Fatalf("could not run with simple --help arg: %v", err)
	}

	pty.RequireNoError()
	pty.ExpectMatch("Monitor and restrict HTTP/HTTPS requests from processes")
}

func TestCurlGithub(t *testing.T) {
	ensureSudo(t)

	cmd := NewCommand()
	inv := cmd.Invoke("--allow", "\"github.com\"", "--", "curl", "https://github.com")

	pty := NewMockPTY(t)
	pty.Attach(inv)

	if err := inv.Run(); err != nil {
		t.Fatalf("error curling github: %v", err)
	}

	pty.RequireNoError()
	pty.ExpectMatch("")
}
