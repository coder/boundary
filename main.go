package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/coder/squeeze/squeeze"
)

func main() {
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