package main

import (
	"fmt"
)

// Version information injected at build time
var (
	//nolint:unused
	version = "dev" // Set via -ldflags "-X main.version=v1.0.0"
)

func main() {
	fmt.Println("(づ｡◕‿◕｡)づ Boundary version:", version)
}
