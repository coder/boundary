package main

import (
	"fmt"
	"os"

	"github.com/coder/jail/cli"
)

// Version information injected at build time
var (
	version = "dev" // Set via -ldflags "-X main.version=v1.0.0"
)

func main() {
	cmd := cli.NewCommand()

	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
