package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/coder/serpent"
)

func ensureRoot(t *testing.T) {
	t.Helper()
	if os.Getgid() != 0 {
		t.Skip("skipping test because no root privileges")
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

func (m *MockPTY) ExpectInStdout(content string) {
	if !strings.Contains(m.stdout.String(), content) {
		m.t.Fatalf("expected \"%s\", got: %s", content, m.stdout.String())
	}
}

func (m *MockPTY) ExpectInStderr(content string) {
	if !strings.Contains(m.stderr.String(), content) {
		m.t.Fatalf("expected \"%s\", got: %s", content, m.stderr.String())
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

	pty.ExpectInStdout("Monitor and restrict HTTP/HTTPS requests from processes")
}

// For these tests, I have a fixture in the form of a pastebin: https://pastebin.com/raw/2q6kyAyQ
func TestCurlPastebin(t *testing.T) {
	ensureRoot(t)
	cmd := NewCommand()
	inv := cmd.Invoke("--allow", "\"pastebin.com\"", "--", "curl", "https://pastebin.com/raw/2q6kyAyQ")

	pty := NewMockPTY(t)
	pty.Attach(inv)

	if err := inv.Run(); err != nil {
		t.Fatalf("error curling pastebin test fixture: %v", err)
	}
	pty.ExpectInStdout("foo")
	pty.Clear()

	// Allowing all with a glob should allow the request
	inv = cmd.Invoke("--allow", "*", "--", "curl", "https://pastebin.com/raw/2q6kyAyQ")
	pty.Attach(inv)
	if err := inv.Run(); err != nil {
		t.Fatalf("error curling pastebin test fixture: %v", err)
	}
	pty.ExpectInStdout("foo")
	pty.Clear()
}
