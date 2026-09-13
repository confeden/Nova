// Command nova-go is Nova PC's Go helper: WARP registration and endpoint scanning, MASQUE
// registration and a MASQUE SOCKS5 proxy. Each subcommand group lives in its own file.
package main

import (
	"fmt"
	"os"
)

// version is stamped at build time with -ldflags "-X main.version=<CURRENT_VERSION>".
var version = "dev"

type group struct {
	name string
	help string
	run  func(args []string) int
}

var groups []group

func register(g group) { groups = append(groups, g) }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nova-go <group> <command> [flags]")
	for _, g := range groups {
		fmt.Fprintf(os.Stderr, "  %-8s %s\n", g.name, g.help)
	}
	fmt.Fprintln(os.Stderr, "  version  print the helper version")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version", "-version":
		fmt.Println("nova-go " + version)
		return
	case "help", "-h", "--help":
		usage()
		return
	}
	for _, g := range groups {
		if g.name == os.Args[1] {
			os.Exit(g.run(os.Args[2:]))
		}
	}
	usage()
	os.Exit(2)
}
