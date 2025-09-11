//go:build linux

package namespace

import (
	"log/slog"
	"os"
	"testing"
)

func TestNewLinux(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		check  func(*testing.T, *Linux, error)
	}{
		{
			name: "basic config",
			config: Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            map[string]string{"TEST": "value"},
			},
			check: func(t *testing.T, linux *Linux, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if linux == nil {
					t.Error("expected Linux instance, got nil")
					return
				}
				if linux.httpProxyPort != 8080 {
					t.Errorf("expected HTTP port 8080, got %d", linux.httpProxyPort)
				}
				if linux.httpsProxyPort != 8443 {
					t.Errorf("expected HTTPS port 8443, got %d", linux.httpsProxyPort)
				}
				if linux.namespace == "" {
					t.Error("expected namespace name to be set")
				}
				if linux.preparedEnv["TEST"] != "value" {
					t.Error("expected environment variable to be copied")
				}
			},
		},
		{
			name: "empty env map",
			config: Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            make(map[string]string),
			},
			check: func(t *testing.T, linux *Linux, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if linux.preparedEnv == nil {
					t.Error("expected preparedEnv to be initialized")
				}
			},
		},
		{
			name: "nil env map",
			config: Config{
				Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
				HttpProxyPort:  8080,
				HttpsProxyPort: 8443,
				Env:            nil,
			},
			check: func(t *testing.T, linux *Linux, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if linux.preparedEnv == nil {
					t.Error("expected preparedEnv to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linux, err := NewLinux(tt.config)
			tt.check(t, linux, err)
		})
	}
}

func TestLinuxCommander(t *testing.T) {
	// Test that Linux implements Commander interface
	var _ Commander = (*Linux)(nil)

	config := Config{
		Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
		HttpProxyPort:  8080,
		HttpsProxyPort: 8443,
		Env:            make(map[string]string),
	}

	linux, err := NewLinux(config)
	if err != nil {
		t.Errorf("failed to create Linux commander: %v", err)
		return
	}

	if linux == nil {
		t.Error("expected Linux commander, got nil")
		return
	}

	// Test Command method
	cmd := linux.Command([]string{"echo", "test"})
	if cmd == nil {
		t.Error("Command method should return a command")
	}

	// Test Start and Close methods (might fail due to permissions)
	err = linux.Start()
	if err != nil {
		t.Logf("Start failed (expected on systems without proper permissions): %v", err)
	}

	// Always try to clean up
	closeErr := linux.Close()
	if closeErr != nil {
		t.Logf("Close failed: %v", closeErr)
	}
}
