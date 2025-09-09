package main

import (
	"fmt"
	"os"

	"github.com/coder/jail/cli"
)

func main() {
	cmd := cli.NewCommand()

	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
