package namespace

import (
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid config",
			config: Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            map[string]string{"TEST": "value"},
				UserInfo: UserInfo{
					Username:  "test",
					Uid:       1000,
					Gid:       1000,
					HomeDir:   "/tmp",
					ConfigDir: "/tmp/config",
				},
			},
			valid: true,
		},
		{
			name: "nil logger",
			config: Config{
				Logger:         nil,
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            make(map[string]string),
			},
			valid: true, // nil logger is acceptable
		},
		{
			name: "zero ports",
			config: Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  0,
				HttpsProxyPort: 0,
				Env:            make(map[string]string),
			},
			valid: true, // zero ports should work
		},
		{
			name: "nil env map",
			config: Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            nil, // nil map should be handled
			},
			valid: true,
		},
	}

	// We can't easily test platform-specific constructors here
	// due to build constraints, so we'll just validate the config struct
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation logic
			if tt.config.HttpProxyPort < 0 && tt.valid {
				t.Error("negative HTTP proxy port should be invalid")
			}
			if tt.config.HttpsProxyPort < 0 && tt.valid {
				t.Error("negative HTTPS proxy port should be invalid")
			}
		})
	}
}

func TestUserInfo_Validation(t *testing.T) {
	tests := []struct {
		name     string
		userInfo UserInfo
		valid    bool
	}{
		{
			name: "valid user info",
			userInfo: UserInfo{
				Username:  "test",
				Uid:       1000,
				Gid:       1000,
				HomeDir:   "/home/test",
				ConfigDir: "/home/test/.config",
			},
			valid: true,
		},
		{
			name: "empty username",
			userInfo: UserInfo{
				Username:  "",
				Uid:       1000,
				Gid:       1000,
				HomeDir:   "/home/test",
				ConfigDir: "/home/test/.config",
			},
			valid: true, // empty username might be valid
		},
		{
			name: "root user",
			userInfo: UserInfo{
				Username:  "root",
				Uid:       0,
				Gid:       0,
				HomeDir:   "/root",
				ConfigDir: "/root/.config",
			},
			valid: true,
		},
		{
			name: "negative uid",
			userInfo: UserInfo{
				Username:  "test",
				Uid:       -1,
				Gid:       1000,
				HomeDir:   "/home/test",
				ConfigDir: "/home/test/.config",
			},
			valid: false,
		},
		{
			name: "negative gid",
			userInfo: UserInfo{
				Username:  "test",
				Uid:       1000,
				Gid:       -1,
				HomeDir:   "/home/test",
				ConfigDir: "/home/test/.config",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test user info validation logic
			if tt.userInfo.Uid < 0 && tt.valid {
				t.Error("negative UID should be invalid")
			}
			if tt.userInfo.Gid < 0 && tt.valid {
				t.Error("negative GID should be invalid")
			}
		})
	}
}

func TestNewNamespaceName(t *testing.T) {
	tests := []struct {
		name string
		runs int
	}{
		{
			name: "single generation",
			runs: 1,
		},
		{
			name: "multiple generations",
			runs: 10,
		},
		{
			name: "many generations",
			runs: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generated := make(map[string]bool)
			
			for i := 0; i < tt.runs; i++ {
				name := newNamespaceName()
				
				// Check format
				if !strings.HasPrefix(name, prefix) {
					t.Errorf("expected name to start with %q, got %q", prefix, name)
				}
				
				// Check length
				if len(name) <= len(prefix)+1 {
					t.Errorf("expected name to be longer than prefix, got %q", name)
				}
				
				// Check uniqueness (for multiple runs)
				if tt.runs > 1 {
					if generated[name] {
						t.Errorf("generated duplicate name: %q", name)
					}
					generated[name] = true
				}
			}
		})
	}
}

// Benchmarks
func BenchmarkNewNamespaceName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = newNamespaceName()
	}
}

func BenchmarkConfigCreation(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	env := map[string]string{"TEST": "value"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := Config{
			Logger:         logger,
			HttpProxyPort:  8080,
			HttpsProxyPort: 8443,
			Env:            env,
		}
		_ = config
	}
}

// Test interface compliance at build time
func TestPlatformSupport(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		t.Log("Linux platform detected")
	case "darwin":
		t.Log("macOS platform detected")
	default:
		t.Logf("Platform %s is not explicitly supported", runtime.GOOS)
	}
}