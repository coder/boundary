package namespace

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	prefix = "coder_jail"
)

func newNamespaceName() string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano()%10000000)
}

func getEnvs(configDir string, caCertPath string) []string {
	e := os.Environ()

	e = mergeEnvs(e, map[string]string{
		// Set standard CA certificate environment variables for common tools
		// This makes tools like curl, git, etc. trust our dynamically generated CA
		"SSL_CERT_FILE":       caCertPath, // OpenSSL/LibreSSL-based tools
		"SSL_CERT_DIR":        configDir,  // OpenSSL certificate directory
		"CURL_CA_BUNDLE":      caCertPath, // curl
		"GIT_SSL_CAINFO":      caCertPath, // Git
		"REQUESTS_CA_BUNDLE":  caCertPath, // Python requests
		"NODE_EXTRA_CA_CERTS": caCertPath, // Node.js
	})

	return e
}

func mergeEnvs(base []string, extra map[string]string) []string {
	envMap := make(map[string]string)
	for _, env := range base {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	for key, value := range extra {
		envMap[key] = value
	}

	merged := make([]string, 0, len(envMap))
	for key, value := range envMap {
		merged = append(merged, key+"="+value)
	}

	return merged
}
