package nsjail

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/boundary/config"
	"github.com/coder/boundary/e2e_tests/util"
	"github.com/stretchr/testify/require"
)

// NSJailTest is a high-level test framework for boundary e2e tests using nsjail
type NSJailTest struct {
	t              *testing.T
	projectRoot    string
	binaryPath     string
	allowedDomains []string
	logLevel       string
	cmd            *exec.Cmd
	pid            int
	startupDelay   time.Duration
}

// NSJailTestOption is a function that configures NSJailTest
type NSJailTestOption func(*NSJailTest)

// NewNSJailTest creates a new NSJailTest instance
func NewNSJailTest(t *testing.T, opts ...NSJailTestOption) *NSJailTest {
	projectRoot := util.FindProjectRoot(t)
	binaryPath := "/tmp/boundary-test"

	nt := &NSJailTest{
		t:              t,
		projectRoot:    projectRoot,
		binaryPath:     binaryPath,
		allowedDomains: []string{},
		logLevel:       "warn",
		startupDelay:   2 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(nt)
	}

	return nt
}

// WithNSJailAllowedDomain adds an allowed domain rule
func WithNSJailAllowedDomain(domain string) NSJailTestOption {
	return func(nt *NSJailTest) {
		nt.allowedDomains = append(nt.allowedDomains, fmt.Sprintf("domain=%s", domain))
	}
}

// WithNSJailAllowedRule adds a full allow rule (e.g., "method=GET domain=example.com path=/api/*")
func WithNSJailAllowedRule(rule string) NSJailTestOption {
	return func(nt *NSJailTest) {
		nt.allowedDomains = append(nt.allowedDomains, rule)
	}
}

// WithNSJailLogLevel sets the log level
func WithNSJailLogLevel(level string) NSJailTestOption {
	return func(nt *NSJailTest) {
		nt.logLevel = level
	}
}

// WithNSJailStartupDelay sets how long to wait after starting boundary before making requests
func WithNSJailStartupDelay(delay time.Duration) NSJailTestOption {
	return func(nt *NSJailTest) {
		nt.startupDelay = delay
	}
}

// Build builds the boundary binary
func (nt *NSJailTest) Build() *NSJailTest {
	buildCmd := exec.Command("go", "build", "-o", nt.binaryPath, "./cmd/...")
	buildCmd.Dir = nt.projectRoot
	err := buildCmd.Run()
	require.NoError(nt.t, err, "Failed to build boundary binary")
	return nt
}

// Start starts the boundary process with a long-running command
func (nt *NSJailTest) Start(command ...string) *NSJailTest {
	if len(command) == 0 {
		// Default: sleep for a long time to keep the process alive
		command = []string{"/bin/bash", "-c", "/usr/bin/sleep 100 && /usr/bin/echo 'Root boundary process exited'"}
	}

	// Build command args
	args := []string{
		"--log-level", nt.logLevel,
		"--jail-type", "nsjail",
	}
	for _, domain := range nt.allowedDomains {
		args = append(args, "--allow", domain)
	}
	args = append(args, "--")
	args = append(args, command...)

	nt.cmd = exec.Command(nt.binaryPath, args...)
	nt.cmd.Stdin = os.Stdin

	stdout, _ := nt.cmd.StdoutPipe()
	stderr, _ := nt.cmd.StderrPipe()
	go io.Copy(os.Stdout, stdout) //nolint:errcheck
	go io.Copy(os.Stderr, stderr) //nolint:errcheck

	err := nt.cmd.Start()
	require.NoError(nt.t, err, "Failed to start boundary process")

	// Wait for boundary to start
	time.Sleep(nt.startupDelay)

	// Get the child process PID
	nt.pid = getTargetProcessPID(nt.t)

	return nt
}

// Stop gracefully stops the boundary process
func (nt *NSJailTest) Stop() {
	if nt.cmd == nil || nt.cmd.Process == nil {
		return
	}

	// Send interrupt signal
	err := nt.cmd.Process.Signal(os.Interrupt)
	if err != nil {
		nt.t.Logf("Failed to interrupt boundary process: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Wait for process to finish
	if nt.cmd != nil {
		err = nt.cmd.Wait()
		if err != nil {
			nt.t.Logf("Boundary process finished with error: %v", err)
		}
	}

	// Clean up binary
	err = os.Remove(nt.binaryPath)
	if err != nil {
		nt.t.Logf("Failed to remove boundary binary: %v", err)
	}
}

// ExpectAllowed makes an HTTP/HTTPS request and expects it to be allowed with the given response body
func (nt *NSJailTest) ExpectAllowed(url string, expectedBody string) {
	nt.t.Helper()
	output := nt.makeRequest(url)
	require.Equal(nt.t, expectedBody, string(output), "Expected response body does not match")
}

// ExpectAllowedContains makes an HTTP/HTTPS request and expects it to be allowed, checking that response contains the given text
func (nt *NSJailTest) ExpectAllowedContains(url string, containsText string) {
	nt.t.Helper()
	output := nt.makeRequest(url)
	require.Contains(nt.t, string(output), containsText, "Response does not contain expected text")
}

// ExpectDeny makes an HTTP/HTTPS request and expects it to be denied
func (nt *NSJailTest) ExpectDeny(url string) {
	nt.t.Helper()
	output := nt.makeRequest(url)
	require.Contains(nt.t, string(output), "Request Blocked by Boundary", "Expected request to be blocked")
}

// makeRequest makes an HTTP/HTTPS request from inside the namespace
// Always sets SSL_CERT_FILE for HTTPS support (harmless for HTTP requests)
func (nt *NSJailTest) makeRequest(url string) []byte {
	nt.t.Helper()

	pid := fmt.Sprintf("%v", nt.pid)
	userInfo := config.GetUserInfo()

	args := []string{"nsenter", "-t", pid, "-n", "--",
		"env", fmt.Sprintf("SSL_CERT_FILE=%v", userInfo.CACertPath()), "curl", "-sS", url}

	curlCmd := exec.Command("sudo", args...)

	var stderr bytes.Buffer
	curlCmd.Stderr = &stderr
	output, err := curlCmd.Output()

	if err != nil {
		nt.t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
	}

	return output
}

// ExpectDenyContains makes an HTTP/HTTPS request and expects it to be denied, checking that response contains the given text
func (nt *NSJailTest) ExpectDenyContains(url string, containsText string) {
	nt.t.Helper()
	output := nt.makeRequest(url)
	require.Contains(nt.t, string(output), containsText, "Response does not contain expected denial text")
}

// sendUDP sends a UDP packet from inside the namespace to the given address:port
func (nt *NSJailTest) sendUDP(addr string, port int, message string) error {
	nt.t.Helper()

	pid := fmt.Sprintf("%v", nt.pid)
	args := []string{"nsenter", "-t", pid, "-n", "--",
		"sh", "-c", fmt.Sprintf("echo '%s' | nc -u -w 1 %s %d", message, addr, port)}

	cmd := exec.Command("sudo", args...)
	return cmd.Run()
}

// getTargetProcessPID gets the PID of the boundary target process.
// Target process is associated with a network namespace, so you can exec into it, using this PID.
// pgrep -f boundary-test -n is doing two things:
// -f = match against the full command line
// -n = return the newest (most recently started) matching process
func getTargetProcessPID(t *testing.T) int {
	cmd := exec.Command("pgrep", "-f", "boundary-test", "-n")
	output, err := cmd.Output()
	require.NoError(t, err)

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	require.NoError(t, err)
	return pid
}
