// Command nova-xray runs one Xray-core instance from a JSON configuration and nothing else.
//
// It is deliberately thin. Every decision about a node — parsing a vless:// link, choosing a
// transport, building the outbound — is made in Python (resources/nova_vless.py) and arrives here
// as a finished Xray configuration, exactly the way wireproxy-awg receives a finished .conf. That
// keeps the protocol knowledge in one place, under pytest, instead of splitting it across a Go
// binary that can only be tested by running it.
//
// Contract with nova.pyw, matching the wireproxy backend it stands beside:
//
//	nova-xray run --config <path> [--log <path>] [--parent-pid N] [--ready-file <path>]
//	nova-xray check --config <path>      validate a configuration without opening a socket
//	nova-xray version
//
// Readiness is the listening SOCKS port: nova.pyw probes it the same way it probes 1370 for
// wireproxy and MASQUE, so no event protocol is needed here. The ready file is written after the
// instance starts, for a parent that wants a witness rather than a probe.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "nova-pc/nova-xray/registry"
)

// version is stamped at build time with -ldflags "-X main.version=<CURRENT_VERSION>".
var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nova-xray <run|check|version> [flags]")
	fmt.Fprintln(os.Stderr, "  run     start Xray from --config and serve until stopped")
	fmt.Fprintln(os.Stderr, "  check   load --config and exit (no socket is opened)")
	fmt.Fprintln(os.Stderr, "  version print the helper and Xray-core versions")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runCmd(os.Args[2:]))
	case "check":
		os.Exit(checkCmd(os.Args[2:]))
	case "version", "--version", "-version":
		fmt.Printf("nova-xray %s (xray-core %s)\n", version, core.Version())
		return
	case "help", "-h", "--help":
		usage()
		return
	}
	usage()
	os.Exit(2)
}

// loadConfig reads the configuration file and turns it into an Xray config.
//
// The file is read whole first so that a half-written file gives a parse error naming the file
// rather than an EOF from inside the JSON decoder: nova.pyw writes it atomically, but a user
// editing profiles/.runtime by hand is exactly who needs the better message.
func loadConfig(path string) (*core.Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--config is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	config, err := serial.LoadJSONConfig(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("cannot load %s: %w", path, err)
	}
	return config, nil
}

func checkCmd(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	configPath := fs.String("config", "", "Xray JSON configuration to validate")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := loadConfig(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "nova-xray: "+err.Error())
		return 1
	}
	fmt.Println("ok")
	return 0
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "Xray JSON configuration to run")
	logPath := fs.String("log", "", "append Xray's own output here instead of stderr")
	readyFile := fs.String("ready-file", "", "written once the instance has started")
	parentPID := fs.Int("parent-pid", 0, "exit when this process is gone")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	closeLog, err := redirectLog(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nova-xray: "+err.Error())
		return 1
	}
	defer closeLog()

	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nova-xray: "+err.Error())
		return 1
	}

	// A stale ready file from a previous run must never be read as this run's readiness.
	if *readyFile != "" {
		if err := os.Remove(*readyFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "nova-xray: cannot remove a stale ready file %s: %v\n", *readyFile, err)
		}
	}

	instance, err := core.New(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nova-xray: cannot build the instance: "+err.Error())
		return 1
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		fmt.Fprintln(os.Stderr, "nova-xray: cannot start: "+err.Error())
		return 1
	}
	fmt.Fprintf(os.Stderr, "nova-xray %s started (xray-core %s), config %s\n",
		version, core.Version(), *configPath)

	if *readyFile != "" {
		writeReadyFile(*readyFile)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	parentGone := watchParent(*parentPID)

	select {
	case <-stop:
		fmt.Fprintln(os.Stderr, "nova-xray: stopping on a signal")
	case <-parentGone:
		fmt.Fprintln(os.Stderr, "nova-xray: parent process is gone, stopping")
	}

	instance.Close()
	if *readyFile != "" {
		if err := os.Remove(*readyFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "nova-xray: cannot remove the ready file %s: %v\n", *readyFile, err)
		}
	}
	return 0
}

// redirectLog sends this process's stderr to `path` when one is given.
//
// Xray writes through the standard logger, so pointing os.Stderr at the file catches its output and
// ours in one place — the same arrangement wireproxy-awg has with temp/wireproxy-awg.log.
func redirectLog(path string) (func(), error) {
	if strings.TrimSpace(path) == "" {
		return func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("cannot create the log folder %s: %w", dir, err)
		}
	}
	// Truncated per run, like the other helper logs: a log that only grows is a log nobody reads.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("cannot open the log %s: %w", path, err)
	}
	previous := os.Stderr
	os.Stderr = file
	return func() {
		os.Stderr = previous
		_ = file.Close()
	}, nil
}

func writeReadyFile(path string) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "nova-xray: cannot create the ready folder %s: %v\n", dir, err)
			return
		}
	}
	// Written through a temporary name so a reader never sees half of it.
	temporary := path + ".tmp"
	payload := fmt.Sprintf(`{"v":1,"pid":%d,"version":%q,"xray":%q,"at":%d}`+"\n",
		os.Getpid(), version, core.Version(), time.Now().Unix())
	if err := os.WriteFile(temporary, []byte(payload), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "nova-xray: cannot write the ready file %s: %v\n", temporary, err)
		return
	}
	if err := os.Rename(temporary, path); err != nil {
		fmt.Fprintf(os.Stderr, "nova-xray: cannot publish the ready file %s: %v\n", path, err)
		_ = os.Remove(temporary)
	}
}

// watchParent closes the returned channel once process `pid` is gone.
//
// Nova stops this helper itself, so this is the backstop for the case it cannot: Nova killed, Nova
// crashed, or a stop that did not reach us. Without it an orphaned Xray would keep the SOCKS port
// and the next start would fail to bind. `pid` 0 disables the watch.
func watchParent(pid int) <-chan struct{} {
	gone := make(chan struct{})
	if pid <= 0 {
		return gone
	}
	go func() {
		defer close(gone)
		for {
			if !processAlive(pid) {
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
	return gone
}
