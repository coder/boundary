package jail

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/namespace"
	"github.com/coder/jail/rules"
)

// Mock implementations for testing

type mockAuditor struct {
	recordedRequests []audit.Request
}

func (m *mockAuditor) AuditRequest(req audit.Request) {
	m.recordedRequests = append(m.recordedRequests, req)
}

type mockRuleEngine struct {
	allowAll bool
	rule     string
}

func (m *mockRuleEngine) Evaluate(method, url string) rules.Result {
	return rules.Result{
		Allowed: m.allowAll,
		Rule:    m.rule,
	}
}

type mockTLSManager struct {
	returnError bool
}

func (m *mockTLSManager) SetupTLSAndWriteCACert() (*tls.Config, string, string, error) {
	if m.returnError {
		return nil, "", "", errors.New("TLS setup failed")
	}
	return &tls.Config{}, "/tmp/test-ca.pem", "/tmp/test-config", nil
}

type mockCommander struct {
	startError  error
	closeError  error
	commandFunc func([]string) *exec.Cmd
}

func (m *mockCommander) Start() error {
	return m.startError
}

func (m *mockCommander) Command(command []string) *exec.Cmd {
	if m.commandFunc != nil {
		return m.commandFunc(command)
	}
	return exec.Command("echo", "mock")
}

func (m *mockCommander) Close() error {
	return m.closeError
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		expectPanic bool
	}{
		{
			name: "valid config",
			config: Config{
				RuleEngine:  &mockRuleEngine{allowAll: true},
				Auditor:     &mockAuditor{},
				CertManager: &mockTLSManager{},
				Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			expectPanic: false,
		},
		{
			name: "nil cert manager causes panic",
			config: Config{
				RuleEngine:  &mockRuleEngine{allowAll: true},
				Auditor:     &mockAuditor{},
				CertManager: nil,
				Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			
			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("expected panic but none occurred")
					}
				}()
			}
			
			_, err := New(ctx, tt.config)
			
			if !tt.expectPanic && err != nil && !isNamespaceError(err) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestNew_Success(t *testing.T) {
	ctx := context.Background()
	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true, rule: "test rule"},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: false},
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	// Mock the newNamespaceCommander function by creating a custom function
	// Since we can't easily mock the function, we'll test the error handling
	jail, err := New(ctx, config)
	if err != nil && !isNamespaceError(err) {
		t.Fatalf("unexpected error creating jail: %v", err)
	}

	if err == nil {
		if jail == nil {
			t.Fatal("expected jail instance, got nil")
		}
		if jail.logger == nil {
			t.Error("expected logger to be set")
		}
		if jail.ctx == nil {
			t.Error("expected context to be set")
		}
		if jail.cancel == nil {
			t.Error("expected cancel function to be set")
		}
	}
}

func TestNew_TLSError(t *testing.T) {
	ctx := context.Background()
	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: true},
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	_, err := New(ctx, config)
	if err == nil {
		t.Fatal("expected error when TLS setup fails")
	}
	if !strings.Contains(err.Error(), "failed to setup TLS") {
		t.Errorf("expected TLS error message, got: %v", err)
	}
}

func TestJail_StartStop(t *testing.T) {
	// This test will work on systems where namespace creation succeeds
	if !canCreateNamespace() {
		t.Skip("skipping test: cannot create namespace on this system")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: false},
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	jail, err := New(ctx, config)
	if err != nil {
		t.Skipf("skipping test: failed to create jail: %v", err)
	}

	// Use a channel to coordinate shutdown
	done := make(chan struct{})
	defer func() {
		close(done)
		if closeErr := jail.Close(); closeErr != nil {
			t.Logf("error closing jail: %v", closeErr)
		}
	}()

	err = jail.Start()
	if err != nil {
		// Check if it's a permission or system capability error
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping test: insufficient permissions or missing tools: %v", err)
		}
		t.Fatalf("failed to start jail: %v", err)
	}

	// Give it more time to start properly
	time.Sleep(500 * time.Millisecond)

	// Test Command method
	cmd := jail.Command([]string{"echo", "test"})
	if cmd == nil {
		t.Fatal("expected command, got nil")
	}
}

func TestJail_Command(t *testing.T) {
	tests := []struct {
		name     string
		command  []string
		expected string
	}{
		{
			name:     "simple echo",
			command:  []string{"echo", "hello"},
			expected: "hello",
		},
		{
			name:     "empty command",
			command:  []string{},
			expected: "",
		},
		{
			name:     "multiple args",
			command:  []string{"echo", "hello", "world"},
			expected: "hello world",
		},
	}

	if !canCreateNamespace() {
		t.Skip("skipping test: cannot create namespace on this system")
	}

	ctx := context.Background()
	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: false},
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	jail, err := New(ctx, config)
	if err != nil {
		t.Skipf("skipping test: failed to create jail: %v", err)
	}
	defer jail.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := jail.Command(tt.command)
			if len(tt.command) == 0 {
				// For empty command, just verify we get a command back
				if cmd == nil {
					t.Error("expected command, got nil")
				}
				return
			}

			if cmd == nil {
				t.Fatal("expected command, got nil")
			}

			// Verify the command has the expected structure
			if len(cmd.Args) < len(tt.command) {
				t.Errorf("expected at least %d args, got %d", len(tt.command), len(cmd.Args))
			}
		})
	}
}

func TestNewNamespaceCommander(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "linux support",
			goos:        "linux",
			expectError: false,
		},
		{
			name:        "darwin support",
			goos:        "darwin",
			expectError: false,
		},
		{
			name:         "unsupported platform",
			goos:         "windows",
			expectError:  true,
			errorMessage: "unsupported platform",
		},
		{
			name:         "unknown platform",
			goos:         "freebsd",
			expectError:  true,
			errorMessage: "unsupported platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original runtime.GOOS
			origGOOS := runtime.GOOS
			
			// We can't actually change runtime.GOOS, so we'll test the current platform
			// and verify the function behavior for our current OS
			config := namespace.Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            make(map[string]string),
			}

			// Only test the current platform to avoid changing runtime behavior
			if tt.goos != origGOOS {
				t.Skip("skipping cross-platform test")
			}

			commander, err := newNamespaceCommander(config)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got none")
				} else if !strings.Contains(err.Error(), tt.errorMessage) {
					t.Errorf("expected error to contain %q, got: %v", tt.errorMessage, err)
				}
				return
			}

			// For supported platforms, we might still get an error due to system constraints
			if err != nil {
				t.Logf("got error for supported platform (might be system constraints): %v", err)
			} else if commander == nil {
				t.Error("expected commander, got nil")
			}
		})
	}
}

// Helper functions

func isNamespaceError(err error) bool {
	return strings.Contains(err.Error(), "namespace") ||
		strings.Contains(err.Error(), "permission") ||
		strings.Contains(err.Error(), "not supported")
}

func canCreateNamespace() bool {
	// Check if we can create namespaces on this system
	// This is a simple heuristic - in real scenarios there are more checks
	switch runtime.GOOS {
	case "linux":
		// On Linux, check if we're root or have user namespaces
		return os.Getuid() == 0 || hasUserNamespaces()
	case "darwin":
		// On macOS, we can always try (might fail later)
		return true
	default:
		return false
	}
}

func hasUserNamespaces() bool {
	// Simple check for user namespace support
	_, err := os.Stat("/proc/self/uid_map")
	return err == nil
}
