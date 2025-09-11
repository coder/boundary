//go:build darwin

package namespace

import (
	"log/slog"
	"os"
	"testing"
)

func TestNewMacOS(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		check  func(*testing.T, *MacOSNetJail, error)
	}{
		{
			name: "basic config",
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
			check: func(t *testing.T, macos *MacOSNetJail, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if macos == nil {
					t.Error("expected MacOSNetJail instance, got nil")
					return
				}
				if macos.httpProxyPort != 8080 {
					t.Errorf("expected HTTP port 8080, got %d", macos.httpProxyPort)
				}
				if macos.httpsProxyPort != 8443 {
					t.Errorf("expected HTTPS port 8443, got %d", macos.httpsProxyPort)
				}
				if macos.pfRulesPath == "" {
					t.Error("expected PF rules path to be set")
				}
				if macos.mainRulesPath == "" {
					t.Error("expected main rules path to be set")
				}
				if macos.preparedEnv["TEST"] != "value" {
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
			check: func(t *testing.T, macos *MacOSNetJail, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if macos.preparedEnv == nil {
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
			check: func(t *testing.T, macos *MacOSNetJail, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if macos.preparedEnv == nil {
					t.Error("expected preparedEnv to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			macos, err := NewMacOS(tt.config)
			tt.check(t, macos, err)
		})
	}
}

func TestMacOSCommander(t *testing.T) {
	// Test that MacOSNetJail implements Commander interface
	var _ Commander = (*MacOSNetJail)(nil)

	config := Config{
		Logger:         slog.New(slog.NewTextHandler(os.Stdout, nil)),
		HttpProxyPort:  8080,
		HttpsProxyPort: 8443,
		Env:            make(map[string]string),
		UserInfo: UserInfo{
			Username:  "test",
			Uid:       1000,
			Gid:       1000,
			HomeDir:   "/tmp",
			ConfigDir: "/tmp/config",
		},
	}

	macos, err := NewMacOS(config)
	if err != nil {
		t.Errorf("failed to create macOS commander: %v", err)
		return
	}

	if macos == nil {
		t.Error("expected macOS commander, got nil")
		return
	}

	// Test Command method
	cmd := macos.Command([]string{"echo", "test"})
	if cmd == nil {
		t.Error("Command method should return a command")
	}

	// Test Start and Close methods (might fail due to permissions)
	err = macos.Start()
	if err != nil {
		t.Logf("Start failed (expected on systems without proper permissions): %v", err)
	}

	// Always try to clean up
	closeErr := macos.Close()
	if closeErr != nil {
		t.Logf("Close failed: %v", closeErr)
	}
}
