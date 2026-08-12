package landjail

import (
	"strings"
	"testing"

	"github.com/coder/boundary/config"
)

func TestGetEnvsForTargetProcessStripsUpstreamProxy(t *testing.T) {
	t.Setenv(config.UpstreamProxyEnv, "http://user:pass@proxy.corp:3128")
	t.Setenv("BOUNDARY_TEST_KEEP", "keep")

	env := getEnvsForTargetProcess("/tmp/boundary-config", "/tmp/boundary-config/ca.pem", 18080)

	if containsEnvKey(env, config.UpstreamProxyEnv) {
		t.Fatalf("target environment includes %s", config.UpstreamProxyEnv)
	}
	if !containsEnv(env, "BOUNDARY_TEST_KEEP=keep") {
		t.Fatal("target environment did not preserve unrelated variables")
	}
	if !containsEnv(env, "HTTP_PROXY=http://localhost:18080") {
		t.Fatal("target environment did not include Boundary HTTP proxy")
	}
	if !containsEnv(env, "SSL_CERT_FILE=/tmp/boundary-config/ca.pem") {
		t.Fatal("target environment did not include CA certificate path")
	}
}

func containsEnv(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}

func containsEnvKey(env []string, want string) bool {
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok && key == want {
			return true
		}
	}
	return false
}
