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
	m.stderr = strings.Builder{}
	m.stdout = strings.Builder{}
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

	t.Run("help command", func(t *testing.T) {
		inv := NewCommand().Invoke("--help")
		pty := NewMockPTY(t)
		pty.Attach(inv)
		if err := inv.Run(); err != nil {
			t.Fatalf("could not run with simple --help arg: %v", err)
		}
		pty.ExpectInStdout("Monitor and restrict HTTP/HTTPS requests from processes")
	})

	t.Run("just a url", func(t *testing.T) {
		inv := NewCommand().Invoke("--allow", "\"pastebin.com\"", "--", "curl", "https://pastebin.com/raw/2q6kyAyQ")
		pty := NewMockPTY(t)
		pty.Attach(inv)
		if err := inv.Run(); err != nil {
			t.Fatalf("error curling pastebin test fixture: %v", err)
		}
		pty.ExpectInStdout("foo")
	})

	t.Run("allow all with asterisk", func(t *testing.T) {
		inv := NewCommand().Invoke("--allow", "\"*\"", "--", "curl", "https://pastebin.com/raw/2q6kyAyQ")
		pty := NewMockPTY(t)
		pty.Attach(inv)
		if err := inv.Run(); err != nil {
			t.Fatalf("error curling pastebin test fixture: %v", err)
		}
		pty.ExpectInStdout("foo")
	})
}
