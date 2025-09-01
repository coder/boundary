package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/coder/squeeze/squeeze"
)

// runChildProcess handles the child process execution in isolated namespaces
func runChildProcess() {
	// TODO: We need to pass config data from parent to child
	// For now, just create namespaces and exit to test
	
	if err := squeeze.CreateNamespaces(); err != nil {
		fmt.Fprintf(os.Stderr, "Child: failed to create namespaces: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("Child: successfully created namespaces\n")
	os.Exit(0)
}

func main() {
	// Check if we're running as the child process for namespace setup
	if len(os.Args) > 1 && os.Args[1] == "squeeze-child" {
		runChildProcess()
		return
	}

	var configFile = flag.String("config", "", "path to configuration file")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] -- command [args...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}
	
	flag.Parse()
	command := flag.Args()

	if len(command) < 1 {
		fmt.Fprintf(os.Stderr, "Error: no command specified after --\n")
		flag.Usage()
		os.Exit(1)
	}
	
	// Create basic config for testing (config file loading not implemented yet)
	config := squeeze.NewConfig(
		squeeze.WithCommand(command[0], command[1:]...),
		squeeze.WithWorkingDir("."),
	)

	if *configFile != "" {
		fmt.Printf("Config file specified: %s (not implemented yet)\n", *configFile)
	}
	
	fmt.Printf("Running isolated: %s\n", strings.Join(command, " "))
	
	if err := config.RunIsolated(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}