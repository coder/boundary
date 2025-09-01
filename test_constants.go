package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func main() {
	fmt.Printf("CLONE_NEWUSER: %x\n", unix.CLONE_NEWUSER)
	fmt.Printf("CLONE_NEWNS: %x\n", unix.CLONE_NEWNS)  
	fmt.Printf("CLONE_NEWNET: %x\n", unix.CLONE_NEWNET)
}