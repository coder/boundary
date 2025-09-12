package jail

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
)

// Mock implementations for testing
type mockRuleEngine struct {
	allowAll bool
}

func (m *mockRuleEngine) IsAllowed(method, url string) bool {
	return m.allowAll
}

func (m *mockRuleEngine) GetMatchingRule(method, url string) string {
	if m.allowAll {
		return "allow *"
	}
	return ""
}

type mockAuditor struct {
	requests []audit.Request
}

func (m *mockAuditor) AuditRequest(req audit.Request) {
	m.requests = append(m.requests, req)
}

type mockTLSManager struct {
	returnError bool
}

func (m *mockTLSManager) SetupTLS() error {
	if m.returnError {
		return os.ErrPermission
	}
	return nil
}

func (m *mockTLSManager) GetTLSConfig() (*tls.Config, error) {
	if m.returnError {
		return nil, os.ErrPermission
	}
	return &tls.Config{}, nil
}

func (m *mockTLSManager) GetCACertPEM() ([]byte, error) {
	if m.returnError {
		return nil, os.ErrPermission
	}
	return []byte("fake-ca-cert"), nil
}

// Helper function to check if we can create namespaces
func canCreateNamespace() bool {
	// Only test on Linux where we might have permissions
	return runtime.GOOS == "linux"
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				RuleEngine:  &mockRuleEngine{allowAll: true},
				Auditor:     &mockAuditor{},
				CertManager: &mockTLSManager{returnError: false},
				Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			wantErr: false,
		},
		{
			name: "nil cert manager causes panic",
			config: Config{
				RuleEngine:  &mockRuleEngine{allowAll: true},
				Auditor:     &mockAuditor{},
				CertManager: nil, // This should cause issues
				Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			_, err := New(ctx, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew_Success(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: false},
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	jail, err := New(ctx, config)
	if err != nil {
		// In test environments, namespace creation may fail due to permissions
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping due to insufficient permissions: %v", err)
		}
		t.Fatalf("New() failed: %v", err)
	}

	if jail == nil {
		t.Fatal("expected jail instance, got nil")
	}

	// Clean up
	if err := jail.Close(); err != nil {
		t.Logf("error closing jail: %v", err)
	}
}

func TestNew_TLSError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: true}, // This will cause TLS setup to fail
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	_, err := New(ctx, config)
	if err == nil {
		t.Error("expected error due to TLS setup failure, got nil")
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
		name string
		args []string
		want bool // whether we expect a non-nil command
	}{
		{
			name: "simple echo",
			args: []string{"echo", "hello"},
			want: true,
		},
		{
			name: "empty command",
			args: []string{},
			want: true, // Should still return a command object
		},
		{
			name: "multiple args",
			args: []string{"ls", "-la", "/tmp"},
			want: true,
		},
	}

	// Create a simple jail instance for testing Command method
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	config := Config{
		RuleEngine:  &mockRuleEngine{allowAll: true},
		Auditor:     &mockAuditor{},
		CertManager: &mockTLSManager{returnError: false},
		Logger:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	jail, err := New(ctx, config)
	if err != nil {
		// Skip if we can't create jail due to system constraints
		if strings.Contains(err.Error(), "permission denied") ||
			strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping due to insufficient permissions: %v", err)
		}
		t.Fatalf("failed to create jail: %v", err)
	}
	defer jail.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := jail.Command(tt.args)
			got := cmd != nil
			if got != tt.want {
				t.Errorf("Command() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewNamespaceCommander(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		wantType string
		skip     bool
	}{
		{
			name:     "linux support",
			goos:     "linux",
			wantType: "*namespace.Linux",
			skip:     runtime.GOOS != "linux",
		},
		{
			name:     "darwin support", 
			goos:     "darwin",
			wantType: "*namespace.Darwin",
			skip:     runtime.GOOS != "darwin",
		},
		{
			name:     "unsupported platform",
			goos:     "windows",
			wantType: "",
			skip:     runtime.GOOS == "windows", // Would error in real scenario
		},
		{
			name:     "unknown platform",
			goos:     "plan9",
			wantType: "",
			skip:     true, // Always skip this fictional case
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip("skipping cross-platform test")
			}

			// Test the current platform's implementation
			commander, err := NewNamespaceCommander(UserInfo{
				Username: "testuser",
				UID:      1000,
				GID:      1000,
			}, slog.New(slog.NewTextHandler(os.Stdout, nil)))

			if tt.goos == runtime.GOOS {
				// Should work on current platform
				if err != nil {
					// May fail due to permissions, which is okay
					if strings.Contains(err.Error(), "permission denied") {
						t.Skipf("skipping due to insufficient permissions: %v", err)
					}
				}
				if commander == nil && err == nil {
					t.Error("expected commander or error, got neither")
				}
			}
		})
	}
}
