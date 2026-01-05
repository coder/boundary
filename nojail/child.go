package nojail

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/coder/boundary/config"
	"github.com/coder/boundary/util"
)

func RunChild(logger *slog.Logger, config config.AppConfig) error {
	logger.Debug("Running child process in nojail mode (no network restrictions)")

	// Build command
	cmd := exec.Command(config.TargetCMD[0], config.TargetCMD[1:]...)
	cmd.Env = getEnvsForTargetProcess(config.UserInfo.ConfigDir, config.UserInfo.CACertPath(), int(config.ProxyPort))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Info("Executing target command", "command", config.TargetCMD)

	// Run the command - this will block until it completes
	err := cmd.Run()
	if err != nil {
		// Check if this is a normal exit with non-zero status code
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode := exitError.ExitCode()
			logger.Debug("Command exited with non-zero status", "exit_code", exitCode)
			return fmt.Errorf("command exited with code %d", exitCode)
		}
		// This is an unexpected error
		logger.Error("Command execution failed", "error", err)
		return fmt.Errorf("command execution failed: %v", err)
	}

	logger.Debug("Command completed successfully")
	return nil
}

func getEnvsForTargetProcess(configDir string, caCertPath string, httpProxyPort int) []string {
	e := os.Environ()

	proxyAddr := fmt.Sprintf("http://localhost:%d", httpProxyPort)
	e = util.MergeEnvs(e, map[string]string{
		// Set standard CA certificate environment variables for common tools
		// This makes tools like curl, git, etc. trust our dynamically generated CA
		"SSL_CERT_FILE":       caCertPath, // OpenSSL/LibreSSL-based tools
		"SSL_CERT_DIR":        configDir,  // OpenSSL certificate directory
		"CURL_CA_BUNDLE":      caCertPath, // curl
		"GIT_SSL_CAINFO":      caCertPath, // Git
		"REQUESTS_CA_BUNDLE":  caCertPath, // Python requests
		"NODE_EXTRA_CA_CERTS": caCertPath, // Node.js

		"HTTP_PROXY":  proxyAddr,
		"HTTPS_PROXY": proxyAddr,
		"http_proxy":  proxyAddr,
		"https_proxy": proxyAddr,
	})

	return e
}
