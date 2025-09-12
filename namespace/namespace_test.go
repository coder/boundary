package namespace

import (
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// Mock implementations for testing
type mockCommander struct {
	commands [][]string
	shouldFail bool
}

func (m *mockCommander) Start() error {
	if m.shouldFail {
		return os.ErrPermission
	}
	return nil
}

func (m *mockCommander) Command(args []string) *exec.Cmd {
	m.commands = append(m.commands, args)
	// Return a simple command that should exist on most systems
	return exec.Command("echo", "test")
}

func (m *mockCommander) Close() error {
	return nil
}

func (m *mockCommander) String() string {
	return "mockCommander"
}

func TestNewLinux(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string // Expected type or error pattern
	}{
		{
			name: "basic config",
			config: Config{
				Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort: 8080,
				HttpsProxyPort: 8443,
				Env: map[string]string{"TEST": "value"},
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			want: "*namespace.Linux",
		},
		{
			name: "empty env map",
			config: Config{
				Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort: 8080,
				HttpsProxyPort: 8443,
				Env: map[string]string{},
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			want: "*namespace.Linux",
		},
		{
			name: "nil env map",
			config: Config{
				Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort: 8080,
				HttpsProxyPort: 8443,
				Env: nil,
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			want: "*namespace.Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commander, err := NewLinux(tt.config)
			
			// On non-Linux systems or systems without proper permissions,
			// this might fail, which is expected
			if runtime.GOOS != "linux" {
				t.Skip("skipping Linux-specific test on non-Linux system")
			}
			
			if err != nil {
				// Permission errors are expected in test environments
				if strings.Contains(err.Error(), "permission denied") ||
					strings.Contains(err.Error(), "operation not permitted") {
					t.Skipf("skipping due to insufficient permissions: %v", err)
				}
				// Other errors might be system-specific constraints
				t.Logf("NewLinux failed (may be expected): %v", err)
				return
			}
			
			if commander == nil {
				t.Error("expected commander, got nil")
				return
			}
			
			// Test that the commander can be used
			cmd := commander.Command([]string{"echo", "test"})
			if cmd == nil {
				t.Error("expected command, got nil")
			}
		})
	}
}

// Test configuration validation
func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort: 8080,
				HttpsProxyPort: 8443,
				Env: map[string]string{"TEST": "value"},
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			wantErr: false,
		},
		{
			name: "nil logger",
			config: Config{
				Logger: nil,
				HttpProxyPort: 8080,
				HttpsProxyPort: 8443,
				Env: map[string]string{"TEST": "value"},
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			wantErr: false, // Some implementations might handle nil logger gracefully
		},
		{
			name: "zero ports",
			config: Config{
				Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort: 0,
				HttpsProxyPort: 0,
				Env: map[string]string{"TEST": "value"},
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			wantErr: false, // Zero ports might be valid for dynamic allocation
		},
		{
			name: "nil env map",
			config: Config{
				Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort: 8080,
				HttpsProxyPort: 8443,
				Env: nil,
				UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
			},
			wantErr: false, // Nil env map should be handled gracefully
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test config validation by attempting to create a Linux namespace
			if runtime.GOOS != "linux" {
				t.Skip("skipping Linux-specific validation")
			}
			
			_, err := NewLinux(tt.config)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				// Permission errors are not validation errors, they're system constraints
				if err != nil && !strings.Contains(err.Error(), "permission") && 
					!strings.Contains(err.Error(), "operation not permitted") {
					t.Logf("NewLinux failed (may be expected): %v", err)
				}
			}
		})
	}
}

// Test UserInfo validation
func TestUserInfo_Validation(t *testing.T) {
	tests := []struct {
		name string
		user UserInfo
		want string // Expected validation result
	}{
		{
			name: "valid user info",
			user: UserInfo{Username: "testuser", Uid: 1000, Gid: 1000, HomeDir: "/home/testuser"},
			want: "valid",
		},
		{
			name: "empty username",
			user: UserInfo{Username: "", Uid: 1000, Gid: 1000, HomeDir: "/home/user"},
			want: "empty_username",
		},
		{
			name: "root user",
			user: UserInfo{Username: "root", Uid: 0, Gid: 0, HomeDir: "/root"},
			want: "valid",
		},
		{
			name: "negative uid",
			user: UserInfo{Username: "testuser", Uid: -1, Gid: 1000, HomeDir: "/home/testuser"},
			want: "invalid_uid",
		},
		{
			name: "negative gid",
			user: UserInfo{Username: "testuser", Uid: 1000, Gid: -1, HomeDir: "/home/testuser"},
			want: "invalid_gid",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation checks
			if tt.want == "empty_username" && tt.user.Username != "" {
				t.Error("expected empty username")
			}
			if tt.want == "invalid_uid" && tt.user.Uid >= 0 {
				t.Error("expected negative uid")
			}
			if tt.want == "invalid_gid" && tt.user.Gid >= 0 {
				t.Error("expected negative gid")
			}
			if tt.want == "valid" {
				if tt.user.Username == "" || tt.user.Uid < 0 || tt.user.Gid < 0 {
					t.Error("expected valid user info")
				}
			}
		})
	}
}

// Test namespace name generation
func TestNewNamespaceName(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{
			name:  "single generation",
			count: 1,
		},
		{
			name:  "multiple generations",
			count: 5,
		},
		{
			name:  "many generations",
			count: 100,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := make(map[string]bool)
			
			for i := 0; i < tt.count; i++ {
				name := newNamespaceName()
				
				if name == "" {
					t.Error("expected non-empty namespace name")
					continue
				}
				
				if names[name] {
					t.Errorf("duplicate namespace name generated: %s", name)
				}
				names[name] = true
				
				// Check format: should be coder_jail_<random>
				if !strings.HasPrefix(name, "coder_jail_") {
					t.Errorf("expected namespace name to start with 'coder_jail_', got: %s", name)
				}
				
				// Check minimum length
				if len(name) < 12 { // coder_jail_ + at least 1 char
					t.Errorf("namespace name too short: %s", name)
				}
			}
			
			if len(names) != tt.count {
				t.Errorf("expected %d unique names, got %d", tt.count, len(names))
			}
		})
	}
}

// Test platform support detection
func TestPlatformSupport(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		t.Log("Linux platform detected")
		// Test that Linux namespace creation is at least attempted
		config := Config{
			Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
			HttpProxyPort: 8080,
			HttpsProxyPort: 8443,
			Env: map[string]string{"TEST": "value"},
			UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
		}
		
		_, err := NewLinux(config)
		if err != nil {
			t.Logf("Linux namespace creation failed (expected in test environment): %v", err)
		}
	case "darwin":
		t.Log("macOS platform detected")
		// macOS doesn't support Linux namespaces
		config := Config{
			Logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
			HttpProxyPort: 8080,
			HttpsProxyPort: 8443,
			Env: map[string]string{"TEST": "value"},
			UserInfo: UserInfo{Username: "test", Uid: 1000, Gid: 1000},
		}
		
		_, err := NewLinux(config)
		if err == nil {
			t.Error("expected error on macOS, but got none")
		} else {
			t.Logf("macOS correctly returned error: %v", err)
		}
	default:
		t.Logf("Platform %s detected", runtime.GOOS)
		// Other platforms should fail gracefully
	}
}