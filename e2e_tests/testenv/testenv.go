package testenv

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/boundary/util"
	"github.com/stretchr/testify/require"
)

// TestEnv represents a boundary test environment that can be set up and torn down
type TestEnv struct {
	t               *testing.T
	binaryPath      string
	boundaryCmd     *exec.Cmd
	cancel          context.CancelFunc
	allowRules      []string
	certPath        string
	initialIPTables *iptablesSnapshot
}

// iptablesSnapshot captures iptables state for cleanup verification
type iptablesSnapshot struct {
	filterRules string
	natRules    string
}

// TestEnvOption configures a TestEnv
type TestEnvOption func(*TestEnv)

// WithAllowRule adds an allow rule (e.g., "domain=example.com", "domain=*.github.com path=/api/*")
func WithAllowRule(rule string) TestEnvOption {
	return func(env *TestEnv) {
		env.allowRules = append(env.allowRules, rule)
	}
}

// NewTestEnv creates a new test environment with the given options. It exects
// that TestMain in the calling package has placed  uses a shared binary built once for all tests.
func NewTestEnv(t *testing.T, opts ...TestEnvOption) *TestEnv {
	t.Helper()

	// E2E tests require Linux for network namespaces
	if runtime.GOOS != "linux" {
		t.Skipf("E2E tests require Linux (current OS: %s)", runtime.GOOS)
	}

	// This is tightly coupled to e2e_test/main_test.go.
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	binPath, err := filepath.Abs(filepath.Join(dir, "../boundary-test"))
	if err != nil {
		t.Fatalf("Failed to get absolute path for boundary binary: %v", err)
	}

	env := &TestEnv{
		t:          t,
		binaryPath: binPath,
	}

	for _, opt := range opts {
		opt(env)
	}

	_, _, _, _, configDir := util.GetUserInfo()
	env.certPath = filepath.Join(configDir, "ca-cert.pem")
	env.initialIPTables = snapshotIPTables(env.t)
	return env
}

// snapshotIPTables snapshots the current state of iptables rules.
func snapshotIPTables(t *testing.T) *iptablesSnapshot {
	t.Helper()

	filterRules, err := getIPTablesRules("filter")
	require.NoError(t, err, "Failed to capture filter rules")

	natRules, err := getIPTablesRules("nat")
	require.NoError(t, err, "Failed to capture NAT rules")

	return &iptablesSnapshot{
		filterRules: filterRules,
		natRules:    natRules,
	}
}

// getIPTablesRules retrieves iptables rules for a given table.
func getIPTablesRules(tableName string) (string, error) {
	cmd := exec.Command("sudo", "iptables", "-L", "-n", "-t", tableName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get iptables rules for table %s: %w", tableName, err)
	}
	return string(output), nil
}

// Start starts the boundary process with a long-running child command.
func (env *TestEnv) Start() {
	env.t.Helper()
	var ctx context.Context
	ctx, env.cancel = context.WithTimeout(env.t.Context(), 30*time.Second)

	// Build command arguments
	args := []string{}
	for _, rule := range env.allowRules {
		args = append(args, "--allow", rule)
	}
	args = append(args, "--log-level", "debug")
	// Add the child command that boundary will execute inside the namespace
	// Use sleep infinity to keep the process alive for the entire test duration
	args = append(args, "--", "sleep", "infinity")

	// Start boundary process (binary has cap_net_admin capability set, so no sudo needed)
	env.boundaryCmd = exec.CommandContext(ctx, env.binaryPath, args...)
	env.boundaryCmd.Stdin = os.Stdin
	env.boundaryCmd.Stdout = os.Stdout
	env.boundaryCmd.Stderr = os.Stderr

	err := env.boundaryCmd.Start()
	require.NoError(env.t, err, "Failed to start boundary process")

	// Wait for boundary to be ready and for child process to be created
	time.Sleep(2 * time.Second)

	// The child process (with the network namespace) is created by boundary
	// We need to find its PID to use with nsenter
	env.t.Logf("Parent boundary PID: %d", env.boundaryCmd.Process.Pid)
}

// getChildPID finds the child process PID (the one with the network namespace)
func (env *TestEnv) getChildPID() (int, error) {
	parentPID := env.boundaryCmd.Process.Pid

	// Find child process using ps
	cmd := exec.Command("ps", "--ppid", strconv.Itoa(parentPID), "-o", "pid", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to find child process: %w", err)
	}

	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" {
		return 0, fmt.Errorf("no child process found for parent PID %d", parentPID)
	}

	// If multiple children, take the first one
	pids := strings.Fields(pidStr)
	if len(pids) == 0 {
		return 0, fmt.Errorf("no child process found for parent PID %d", parentPID)
	}

	childPID, err := strconv.Atoi(pids[0])
	if err != nil {
		return 0, fmt.Errorf("failed to parse child PID: %w", err)
	}

	return childPID, nil
}

// ExecInNamespace executes a command inside the network namespace
func (env *TestEnv) ExecInNamespace(command string, args ...string) (string, error) {
	// Get the child process PID (the one with the network namespace)
	childPID, err := env.getChildPID()
	if err != nil {
		return "", err
	}

	pidStr := strconv.Itoa(childPID)
	nsenterArgs := []string{"nsenter", "-t", pidStr, "-n", "--"}
	nsenterArgs = append(nsenterArgs, command)
	nsenterArgs = append(nsenterArgs, args...)

	cmd := exec.Command("sudo", nsenterArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// CurlHTTP makes an HTTP request using curl inside the network namespace.
func (env *TestEnv) CurlHTTP(url string, extraArgs ...string) (string, error) {
	env.t.Helper()

	args := append([]string{url}, extraArgs...)
	return env.ExecInNamespace("curl", args...)
}

// CurlHTTPS makes an HTTPS request using curl inside the network namespace with
// boundary's CA cert.
func (env *TestEnv) CurlHTTPS(url string, extraArgs ...string) (string, error) {
	env.t.Helper()

	// Build command with SSL_CERT_FILE environment variable
	pidStr := strconv.Itoa(env.boundaryCmd.Process.Pid)
	nsenterArgs := []string{"nsenter", "-t", pidStr, "-n", "--",
		"env", fmt.Sprintf("SSL_CERT_FILE=%s", env.certPath), "curl"}
	nsenterArgs = append(nsenterArgs, extraArgs...)
	nsenterArgs = append(nsenterArgs, url)

	cmd := exec.Command("sudo", nsenterArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// makeRequest makes an HTTP or HTTPS request based on the URL scheme
func (env *TestEnv) makeRequest(targetURL string, extraArgs ...string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	if parsedURL.Scheme == "https" {
		return env.CurlHTTPS(targetURL, extraArgs...)
	}
	return env.CurlHTTP(targetURL, extraArgs...)
}

// AssertAllowed verifies that a request to the given URL succeeds
// The method automatically detects HTTP vs HTTPS based on the URL scheme
func (env *TestEnv) AssertAllowed(targetURL string) {
	env.t.Helper()

	output, err := env.makeRequest(targetURL)
	require.NoError(env.t, err, "Request should succeed for allowed domain: %s", targetURL)
	require.NotContains(env.t, output, "Request Blocked by Boundary",
		"Request should not be blocked for URL: %s", targetURL)
}

// AssertBlocked verifies that a request to the given URL is blocked
// The method automatically detects HTTP vs HTTPS based on the URL scheme
func (env *TestEnv) AssertBlocked(targetURL string) {
	env.t.Helper()

	output, err := env.makeRequest(targetURL, "-s")
	require.NoError(env.t, err, "Curl command should execute successfully")
	require.Contains(env.t, output, "Request Blocked by Boundary",
		"Request should be blocked for URL: %s", targetURL)
}

// AssertHTTPBlocked is deprecated: use AssertBlocked instead
func (env *TestEnv) AssertHTTPBlocked(url string) {
	env.t.Helper()
	env.AssertBlocked(url)
}

// AssertHTTPSBlocked is deprecated: use AssertBlocked instead
func (env *TestEnv) AssertHTTPSBlocked(url string) {
	env.t.Helper()
	env.AssertBlocked(url)
}

// AssertResponseContains verifies that an HTTP response contains expected content
// The method automatically detects HTTP vs HTTPS based on the URL scheme
func (env *TestEnv) AssertResponseContains(targetURL string, expectedContent string) {
	env.t.Helper()

	output, err := env.makeRequest(targetURL, "-s")
	require.NoError(env.t, err, "Request should succeed for URL: %s", targetURL)
	require.Contains(env.t, output, expectedContent,
		"Response should contain expected content for URL: %s", targetURL)
}

// AssertResponseEquals verifies that an HTTP response exactly matches expected content
// The method automatically detects HTTP vs HTTPS based on the URL scheme
func (env *TestEnv) AssertResponseEquals(targetURL string, expectedContent string) {
	env.t.Helper()

	output, err := env.makeRequest(targetURL, "-s")
	require.NoError(env.t, err, "Request should succeed for URL: %s", targetURL)
	require.Equal(env.t, expectedContent, output,
		"Response should exactly match expected content for URL: %s", targetURL)
}

// Cleanup tears down the test environment
func (env *TestEnv) Cleanup() {
	env.t.Helper()

	if env.cancel != nil {
		env.cancel()
	}

	if env.boundaryCmd != nil {
		err := env.boundaryCmd.Wait()
		if err != nil {
			env.t.Logf("Boundary process finished with error: %v", err)
		}
	}

	// Note: We don't remove the binary here because it's shared across all tests.
}

// PID returns the process ID of the child process in the namespace.
func (env *TestEnv) PID() int {
	return env.boundaryCmd.Process.Pid
}

// CertPath returns the path to the CA certificate for HTTPS requests
func (env *TestEnv) CertPath() string {
	return env.certPath
}
