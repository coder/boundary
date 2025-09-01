package squeeze

import (
	"fmt"
	"os"
	"syscall"
)

const (
	CLONE_NEWNET  = 0x40000000 // Network namespace
	CLONE_NEWNS   = 0x00020000 // Mount namespace
	CLONE_NEWUSER = 0x10000000 // User namespace
)

// IsolationConfig holds the configuration for running a process in isolated namespaces
type IsolationConfig struct {
	ProxyAddr     string   // Address where the transparent HTTP proxy will listen
	AllowedPaths  []string // Filesystem paths that will be visible in the mount namespace
	Command       []string // Command and arguments to execute in isolation
	WorkingDir    string   // Working directory for the isolated process
}

// Option is a functional option for configuring IsolationConfig
type Option func(*IsolationConfig)

// WithProxy sets the address where the transparent HTTP proxy will listen.
// All network traffic from the isolated process will be routed through this proxy.
func WithProxy(addr string) Option {
	return func(c *IsolationConfig) {
		c.ProxyAddr = addr
	}
}

// WithAllowedPath adds a filesystem path that will be visible in the mount namespace.
// This can be called multiple times to allow access to multiple paths.
func WithAllowedPath(path string) Option {
	return func(c *IsolationConfig) {
		c.AllowedPaths = append(c.AllowedPaths, path)
	}
}

// WithCommand sets the command and arguments to execute in the isolated environment.
func WithCommand(cmd string, args ...string) Option {
	return func(c *IsolationConfig) {
		c.Command = append([]string{cmd}, args...)
	}
}

// WithWorkingDir sets the working directory for the isolated process.
func WithWorkingDir(dir string) Option {
	return func(c *IsolationConfig) {
		c.WorkingDir = dir
	}
}

// NewConfig creates a new IsolationConfig with the given options applied.
// It returns a configuration with sensible defaults that can be customized
// using the provided functional options.
func NewConfig(options ...Option) *IsolationConfig {
	config := &IsolationConfig{
		ProxyAddr:  "127.0.0.1:0", // Let OS choose port
		WorkingDir: "/tmp",        // Safe default working directory
	}
	
	for _, option := range options {
		option(config)
	}
	
	return config
}

// RunIsolated executes the configured command in isolated namespaces.
// The parent process remains in the original namespaces while the child
// runs in isolation with network, mount, and user namespace separation.
func (c *IsolationConfig) RunIsolated() error {
	if len(c.Command) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Fork a child process
	pid, err := syscall.ForkExec(
		"/proc/self/exe", // Re-execute ourselves
		[]string{"squeeze-child"}, // Special arg to indicate child mode
		&syscall.ProcAttr{
			Dir:   c.WorkingDir,
			Env:   os.Environ(),
			Files: []uintptr{0, 1, 2}, // stdin, stdout, stderr
		},
	)
	if err != nil {
		return fmt.Errorf("failed to fork child process: %w", err)
	}

	// Parent: wait for child to complete
	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to wait for child: %w", err)
	}

	if !status.Exited() || status.ExitStatus() != 0 {
		return fmt.Errorf("child process failed with status: %d", status.ExitStatus())
	}

	return nil
}
