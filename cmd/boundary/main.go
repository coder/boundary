package main

import (
	"fmt"
	"log"
	"os"

	"github.com/coder/boundary/cli"
)

import (
	"net/http"
	_ "net/http/pprof"
)

func init() {
	go func() {
		log.Println("pprof listening on :6060")
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()
}

// Version information injected at build time
var (
	//nolint:unused
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
