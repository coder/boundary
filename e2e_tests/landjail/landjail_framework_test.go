package landjail

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/coder/boundary/e2e_tests/util"
	"github.com/stretchr/testify/require"
)

// LandjailTest is a high-level test framework for boundary e2e tests using landjail
type LandjailTest struct {
	t              *testing.T
	projectRoot    string
	binaryPath     string
	allowedDomains []string
	logLevel       string
	cmd            *exec.Cmd
	startupDelay   time.Duration
	// Pipes to communicate with the bash process
	bashStdin  io.WriteCloser
	bashStdout io.ReadCloser
	bashStderr io.ReadCloser
}

// LandjailTestOption is a function that configures LandjailTest
type LandjailTestOption func(*LandjailTest)

// NewLandjailTest creates a new LandjailTest instance
func NewLandjailTest(t *testing.T, opts ...LandjailTestOption) *LandjailTest {
	projectRoot := util.FindProjectRoot(t)
	binaryPath := "/tmp/boundary-landjail-test"

	lt := &LandjailTest{
		t:              t,
		projectRoot:    projectRoot,
		binaryPath:     binaryPath,
		allowedDomains: []string{},
		logLevel:       "warn",
		startupDelay:   2 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(lt)
	}

	return lt
}

// WithAllowedDomain adds an allowed domain rule
func WithLandjailAllowedDomain(domain string) LandjailTestOption {
	return func(lt *LandjailTest) {
		lt.allowedDomains = append(lt.allowedDomains, fmt.Sprintf("domain=%s", domain))
	}
}

// WithAllowedRule adds a full allow rule (e.g., "method=GET domain=example.com path=/api/*")
func WithLandjailAllowedRule(rule string) LandjailTestOption {
	return func(lt *LandjailTest) {
		lt.allowedDomains = append(lt.allowedDomains, rule)
	}
}

// WithLogLevel sets the log level
func WithLandjailLogLevel(level string) LandjailTestOption {
	return func(lt *LandjailTest) {
		lt.logLevel = level
	}
}

// WithStartupDelay sets how long to wait after starting boundary before making requests
func WithLandjailStartupDelay(delay time.Duration) LandjailTestOption {
	return func(lt *LandjailTest) {
		lt.startupDelay = delay
	}
}

// Build builds the boundary binary
func (lt *LandjailTest) Build() *LandjailTest {
	buildCmd := exec.Command("go", "build", "-o", lt.binaryPath, "./cmd/...")
	buildCmd.Dir = lt.projectRoot
	err := buildCmd.Run()
	require.NoError(lt.t, err, "Failed to build boundary binary")
	return lt
}

// Start starts the boundary process with a bash process that reads commands from stdin
func (lt *LandjailTest) Start(command ...string) *LandjailTest {
	// Build command args
	args := []string{
		"--log-level", lt.logLevel,
		"--jail-type", "landjail",
	}
	for _, domain := range lt.allowedDomains {
		args = append(args, "--allow", domain)
	}
	args = append(args, "--")

	// Bash command that reads and executes commands from stdin
	// Each command should end with a newline, and we use a marker to detect completion
	// Using a unique marker to avoid conflicts with command output
	if len(command) == 0 {
		command = []string{"/bin/bash", "-c", "while IFS= read -r cmd; do if [ \"$cmd\" = \"exit\" ]; then exit 0; fi; eval \"$cmd\"; echo \"__BOUNDARY_CMD_DONE__\"; done"}
	}
	args = append(args, command...)

	lt.cmd = exec.Command(lt.binaryPath, args...)

	// Capture pipes for communication with bash
	var err error
	lt.bashStdin, err = lt.cmd.StdinPipe()
	require.NoError(lt.t, err, "Failed to create stdin pipe for landjail")

	lt.bashStdout, err = lt.cmd.StdoutPipe()
	require.NoError(lt.t, err, "Failed to create stdout pipe for landjail")

	lt.bashStderr, err = lt.cmd.StderrPipe()
	require.NoError(lt.t, err, "Failed to create stderr pipe for landjail")

	// Forward stderr to os.Stderr for debugging
	go io.Copy(os.Stderr, lt.bashStderr) //nolint:errcheck

	err = lt.cmd.Start()
	require.NoError(lt.t, err, "Failed to start boundary process with landjail")

	// Wait for boundary to start
	time.Sleep(lt.startupDelay)

	return lt
}

// Stop gracefully stops the boundary process
func (lt *LandjailTest) Stop() {
	if lt.cmd == nil || lt.cmd.Process == nil {
		return
	}

	// Send "exit" command to bash, then close stdin
	if lt.bashStdin != nil {
		_, _ = lt.bashStdin.Write([]byte("exit\n"))
		lt.bashStdin.Close() //nolint:errcheck
	}

	time.Sleep(1 * time.Second)

	// Wait for process to finish
	if lt.cmd != nil {
		err := lt.cmd.Wait()
		if err != nil {
			lt.t.Logf("Boundary process finished with error: %v", err)
		}
	}

	// Close pipes if they're still open
	if lt.bashStdout != nil {
		lt.bashStdout.Close() //nolint:errcheck
	}
	if lt.bashStderr != nil {
		lt.bashStderr.Close() //nolint:errcheck
	}

	// Clean up binary
	err := os.Remove(lt.binaryPath)
	if err != nil {
		lt.t.Logf("Failed to remove boundary binary: %v", err)
	}
}

// ExpectAllowed makes an HTTP/HTTPS request and expects it to be allowed with the given response body
func (lt *LandjailTest) ExpectAllowed(url string, expectedBody string) {
	lt.t.Helper()
	output := lt.makeRequest(url)
	require.Equal(lt.t, expectedBody, string(output), "Expected response body does not match")
}

// ExpectAllowedContains makes an HTTP/HTTPS request and expects it to be allowed, checking that response contains the given text
func (lt *LandjailTest) ExpectAllowedContains(url string, containsText string) {
	lt.t.Helper()
	output := lt.makeRequest(url)
	require.Contains(lt.t, string(output), containsText, "Response does not contain expected text")
}

// ExpectDeny makes an HTTP/HTTPS request and expects it to be denied
func (lt *LandjailTest) ExpectDeny(url string) {
	lt.t.Helper()
	output := lt.makeRequest(url)
	require.Contains(lt.t, string(output), "Request Blocked by Boundary", "Expected request to be blocked")
}

// ExpectDenyContains makes an HTTP/HTTPS request and expects it to be denied, checking that response contains the given text
func (lt *LandjailTest) ExpectDenyContains(url string, containsText string) {
	lt.t.Helper()
	output := lt.makeRequest(url)
	require.Contains(lt.t, string(output), containsText, "Response does not contain expected denial text")
}

// makeRequest executes a curl command in the landjail bash process
// Always sets SSL_CERT_FILE for HTTPS support (harmless for HTTP requests)
func (lt *LandjailTest) makeRequest(url string) []byte {
	lt.t.Helper()

	if lt.bashStdin == nil || lt.bashStdout == nil {
		lt.t.Fatalf("landjail pipes not initialized")
	}

	// Build curl command with SSL_CERT_FILE and proxy environment variables
	curlCmd := fmt.Sprintf("curl -sS %s\n", url)

	// Write command to stdin
	_, err := lt.bashStdin.Write([]byte(curlCmd))
	require.NoError(lt.t, err, "Failed to write command to landjail stdin")

	// Read output until we see the completion marker
	var output bytes.Buffer
	doneMarker := []byte("__BOUNDARY_CMD_DONE__")
	buf := make([]byte, 4096)

	for {
		n, err := lt.bashStdout.Read(buf)
		if n > 0 {
			// Check if we've received the completion marker
			data := buf[:n]
			if idx := bytes.Index(data, doneMarker); idx != -1 {
				// Found the marker, add everything before it to output
				output.Write(data[:idx])
				// Remove the marker and newline
				remaining := data[idx+len(doneMarker):]
				if len(remaining) > 0 && remaining[0] == '\n' {
					remaining = remaining[1:]
				}
				if len(remaining) > 0 {
					output.Write(remaining)
				}
				break
			}
			output.Write(data)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			lt.t.Fatalf("Failed to read from landjail stdout: %v", err)
		}
	}

	return output.Bytes()
}
