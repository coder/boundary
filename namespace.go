package main

import (
	"fmt"
	"log"
	"os/exec"
)

type command struct {
	name string
	args []string
}

func setupNamespace() {
	commands := []*command{
		// Create netns
		{name: "ip", args: []string{"netns", "add", "ns1"}},

		// Create veth pair: veth-host <-> veth-ns
		{name: "ip", args: []string{"link", "add", "veth-host", "type", "veth", "peer", "name", "veth-ns"}},

		// Move one end into the namespace
		{name: "ip", args: []string{"link", "set", "veth-ns", "netns", "ns1"}},

		// Host side addressing
		{name: "ip", args: []string{"addr", "add", "10.200.1.1/24", "dev", "veth-host"}},
		{name: "ip", args: []string{"link", "set", "veth-host", "up"}},

		// Namespace side addressing
		{name: "ip", args: []string{"netns", "exec", "ns1", "ip", "addr", "add", "10.200.1.2/24", "dev", "veth-ns"}},
		{name: "ip", args: []string{"netns", "exec", "ns1", "ip", "link", "set", "lo", "up"}},
		{name: "ip", args: []string{"netns", "exec", "ns1", "ip", "link", "set", "veth-ns", "up"}},

		// Default route in the namespace -> host-side veth
		{name: "ip", args: []string{"netns", "exec", "ns1", "ip", "route", "add", "default", "via", "10.200.1.1"}},

		// Enable IP forwarding on the host
		{name: "sysctl", args: []string{"-w", "net.ipv4.ip_forward=1"}},
		// Add iptables rules for NAT/masquerading

		// Redirect traffic from namespace to L7 proxy
		{name: "iptables", args: []string{"-t", "nat", "-A", "PREROUTING", "-i", "veth-host", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "8888"}},

		{name: "iptables", args: []string{"-t", "nat", "-A", "POSTROUTING", "-s", "10.200.1.0/24", "-j", "MASQUERADE"}},
	}
	for _, command := range commands {
		cmd := exec.Command(command.name, command.args...)
		output, err := cmd.Output()
		if err != nil {
			log.Fatalf("can't execute command %v %v: %v - %v", command.name, command.args, err, output)
		}
	}
}

func cleanUpNamespace() {
	commands := []*command{
		// Remove iptables rules

		{name: "iptables", args: []string{"-t", "nat", "-D", "PREROUTING", "-i", "veth-host", "-p", "tcp", "-j", "DNAT", "--to", "127.0.0.1:8888"}},

		// delete the ns
		{name: "ip", args: []string{"netns", "delete", "ns1"}},

		// veth-pair is deleted automatically
		// route inside ns is deleted automatically
	}
	for _, command := range commands {
		cmd := exec.Command(command.name, command.args...)
		err := cmd.Run()
		if err != nil {
			//fmt.Printf("can't execute command %v %v: %v", command.name, command.args, err)
			fmt.Printf("warning during cleanup\n")
		}
	}
}
