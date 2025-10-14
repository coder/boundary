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
		//time.Sleep(time.Millisecond * time.Duration(rand.Intn(1000)))
		log.Println("Going to listen on 6060 or 6061")

		if err := http.ListenAndServe("0.0.0.0:6060", nil); err != nil {
			if err := http.ListenAndServe("0.0.0.0:6061", nil); err != nil {
				log.Println("pprof failed to start on both ports:", err)
				return
			}
			log.Println("pprof listening on :6061")
			return
		}
		log.Println("pprof listening on :6060")
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
