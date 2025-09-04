package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	// Check if we have at least one argument (the command to run)
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s -- <command> [args...]\n", os.Args[0])
		os.Exit(1)
	}

	// Look for the -- separator
	separatorIndex := -1
	for i, arg := range os.Args[1:] {
		if arg == "--" {
			separatorIndex = i + 1
			break
		}
	}

	if separatorIndex == -1 {
		fmt.Fprintf(os.Stderr, "Usage: %s -- <command> [args...]\n", os.Args[0])
		os.Exit(1)
	}

	// Get the command and its arguments after the --
	command := os.Args[separatorIndex+1]
	args := os.Args[separatorIndex+2:]
	args = append([]string{"netns", "exec", "ns1", command}, args...)

	// Create the command
	cmd := exec.Command(
		"ip",
		args...,
	)

	// Set up stdin, stdout, stderr to be inherited from parent
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cleanUpNamespace()
	setupNamespace()

	// Start the child process
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting command: %v\n", err)
		os.Exit(1)
	}

	// Wait for the child process to finish
	if err := cmd.Wait(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			os.Exit(exitError.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Process error: %v\n", err)
		os.Exit(1)
	}

	cleanUpNamespace()
}
