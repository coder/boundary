package e2e_tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/boundary/util"
	"github.com/stretchr/testify/require"
)

// BoundaryTest is a high-level test framework for boundary e2e tests
type BoundaryTest struct {
	t              *testing.T
	projectRoot    string
	binaryPath     string
	allowedDomains []string
	logLevel       string
	ctx            context.Context
	cancel         context.CancelFunc
	cmd            *exec.Cmd
	pid            int
	startupDelay   time.Duration
	commandTimeout time.Duration
}

// BoundaryTestOption is a function that configures BoundaryTest
type BoundaryTestOption func(*BoundaryTest)

// NewBoundaryTest creates a new BoundaryTest instance
func NewBoundaryTest(t *testing.T, opts ...BoundaryTestOption) *BoundaryTest {
	projectRoot := findProjectRoot(t)
	binaryPath := "/tmp/boundary-test"

	bt := &BoundaryTest{
		t:              t,
		projectRoot:    projectRoot,
		binaryPath:     binaryPath,
		allowedDomains: []string{},
		logLevel:       "warn",
		startupDelay:   2 * time.Second,
		commandTimeout: 30 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(bt)
	}

	return bt
}

// WithAllowedDomain adds an allowed domain rule
func WithAllowedDomain(domain string) BoundaryTestOption {
	return func(bt *BoundaryTest) {
		bt.allowedDomains = append(bt.allowedDomains, fmt.Sprintf("domain=%s", domain))
	}
}

// WithAllowedRule adds a full allow rule (e.g., "method=GET domain=example.com path=/api/*")
func WithAllowedRule(rule string) BoundaryTestOption {
	return func(bt *BoundaryTest) {
		bt.allowedDomains = append(bt.allowedDomains, rule)
	}
}

// WithLogLevel sets the log level
func WithLogLevel(level string) BoundaryTestOption {
	return func(bt *BoundaryTest) {
		bt.logLevel = level
	}
}

// WithStartupDelay sets how long to wait after starting boundary before making requests
func WithStartupDelay(delay time.Duration) BoundaryTestOption {
	return func(bt *BoundaryTest) {
		bt.startupDelay = delay
	}
}

// WithCommandTimeout sets the timeout for the boundary command
func WithCommandTimeout(timeout time.Duration) BoundaryTestOption {
	return func(bt *BoundaryTest) {
		bt.commandTimeout = timeout
	}
}

// Build builds the boundary binary
func (bt *BoundaryTest) Build() *BoundaryTest {
	buildCmd := exec.Command("go", "build", "-o", bt.binaryPath, "./cmd/...")
	buildCmd.Dir = bt.projectRoot
	err := buildCmd.Run()
	require.NoError(bt.t, err, "Failed to build boundary binary")
	return bt
}

// Start starts the boundary process with a long-running command
func (bt *BoundaryTest) Start(command ...string) *BoundaryTest {
	if len(command) == 0 {
		// Default: sleep for a long time to keep the process alive
		command = []string{"/bin/bash", "-c", "/usr/bin/sleep 100 && /usr/bin/echo 'Root boundary process exited'"}
	}

	bt.ctx, bt.cancel = context.WithTimeout(context.Background(), bt.commandTimeout)

	// Build command args
	args := []string{
		"--log-level", bt.logLevel,
	}
	for _, domain := range bt.allowedDomains {
		args = append(args, "--allow", domain)
	}
	args = append(args, "--")
	args = append(args, command...)

	bt.cmd = exec.CommandContext(bt.ctx, bt.binaryPath, args...)
	bt.cmd.Stdin = os.Stdin
	
	stdout, _ := bt.cmd.StdoutPipe()
	stderr, _ := bt.cmd.StderrPipe()
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	err := bt.cmd.Start()
	require.NoError(bt.t, err, "Failed to start boundary process")

	// Wait for boundary to start
	time.Sleep(bt.startupDelay)

	// Get the child process PID
	bt.pid = getChildProcessPID(bt.t)

	return bt
}

// Stop gracefully stops the boundary process
func (bt *BoundaryTest) Stop() {
	if bt.cmd == nil || bt.cmd.Process == nil {
		return
	}

	// Send interrupt signal
	err := bt.cmd.Process.Signal(os.Interrupt)
	if err != nil {
		bt.t.Logf("Failed to interrupt boundary process: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Cancel context
	if bt.cancel != nil {
		bt.cancel()
	}

	// Wait for process to finish
	if bt.cmd != nil {
		err = bt.cmd.Wait()
		if err != nil {
			bt.t.Logf("Boundary process finished with error: %v", err)
		}
	}

	// Clean up binary
	err = os.Remove(bt.binaryPath)
	if err != nil {
		bt.t.Logf("Failed to remove boundary binary: %v", err)
	}
}

// ExpectAllowed makes an HTTP/HTTPS request and expects it to be allowed with the given response body
func (bt *BoundaryTest) ExpectAllowed(url string, expectedBody string) {
	bt.t.Helper()
	output := bt.makeRequest(url, false)
	require.Equal(bt.t, expectedBody, string(output), "Expected response body does not match")
}

// ExpectAllowedContains makes an HTTP/HTTPS request and expects it to be allowed, checking that response contains the given text
func (bt *BoundaryTest) ExpectAllowedContains(url string, containsText string) {
	bt.t.Helper()
	output := bt.makeRequest(url, false)
	require.Contains(bt.t, string(output), containsText, "Response does not contain expected text")
}

// ExpectDeny makes an HTTP/HTTPS request and expects it to be denied
func (bt *BoundaryTest) ExpectDeny(url string) {
	bt.t.Helper()
	output := bt.makeRequest(url, false)
	require.Contains(bt.t, string(output), "Request Blocked by Boundary", "Expected request to be blocked")
}

// makeRequest makes an HTTP/HTTPS request from inside the namespace
// Always sets SSL_CERT_FILE for HTTPS support (harmless for HTTP requests)
func (bt *BoundaryTest) makeRequest(url string, silent bool) []byte {
	bt.t.Helper()

	pid := fmt.Sprintf("%v", bt.pid)
	_, _, _, _, configDir := util.GetUserInfo()
	certPath := fmt.Sprintf("%v/ca-cert.pem", configDir)

	args := []string{"nsenter", "-t", pid, "-n", "--",
		"env", fmt.Sprintf("SSL_CERT_FILE=%v", certPath), "curl"}
	if silent {
		args = append(args, "-s")
	}
	args = append(args, url)

	curlCmd := exec.Command("sudo", args...)

	var stderr bytes.Buffer
	curlCmd.Stderr = &stderr
	output, err := curlCmd.Output()

	if err != nil {
		bt.t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
	}

	return output
}

// getChildProcessPID gets the PID of the boundary child process
func getChildProcessPID(t *testing.T) int {
	cmd := exec.Command("pgrep", "-f", "boundary-test", "-n")
	output, err := cmd.Output()
	require.NoError(t, err)

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	require.NoError(t, err)
	return pid
}

// findProjectRoot finds the project root by looking for go.mod file
func findProjectRoot(t *testing.T) string {
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Start from current directory and walk up until we find go.mod
	dir := cwd
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			t.Fatalf("Could not find go.mod file starting from %s", cwd)
		}
		dir = parent
	}
}
