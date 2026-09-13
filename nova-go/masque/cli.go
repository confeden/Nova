// Package masque implements `nova-go masque …`: Cloudflare MASQUE registration and a SOCKS5 proxy
// over a CONNECT-IP tunnel, ported from Nova Android's nova-core/engine (masque.go, masque_h2.go,
// masque_probe.go, register.go) for Windows. Contract: and-masque.md §8 / DESIGN.md §8.
//
// stdout carries only `NOVA_MASQUE {json}` event lines; stderr carries the human log.
package masque

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"nova-pc/nova-go/internal/events"
	"nova-pc/nova-go/internal/parentwatch"
)

// EventPrefix starts every stdout event line.
const EventPrefix = "NOVA_MASQUE"

type cliEnv struct {
	stdout  io.Writer
	stderr  io.Writer
	version string
}

// Main runs `nova-go masque <subcommand> [flags]` and returns the process exit code.
func Main(args []string, version string) (code int) {
	env := &cliEnv{stdout: os.Stdout, stderr: os.Stderr, version: version}
	return env.main(args)
}

func (env *cliEnv) main(args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(env.stderr, "masque: internal error: %v\n%s", r, debug.Stack())
			events.New(EventPrefix, env.stdout).Emit("exit", events.F("code", ExitInternal),
				events.F("class", "panic"), events.F("attempts", 0), events.F("err", fmt.Sprint(r)))
			code = ExitInternal
		}
	}()
	if len(args) == 0 {
		env.usage()
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "register":
		return runRegister(rest, env)
	case "enroll":
		return runEnroll(rest, env)
	case "socks":
		return runSocks(rest, env)
	case "probe":
		return runProbe(rest, env)
	case "check":
		return runCheck(rest, env)
	case "help", "-h", "--help":
		env.usage()
		return ExitOK
	}
	fmt.Fprintf(env.stderr, "unknown masque command %q\n", sub)
	env.usage()
	return ExitUsage
}

func (env *cliEnv) usage() {
	fmt.Fprintln(env.stderr, "usage: nova-go masque <command> [flags]")
	fmt.Fprintln(env.stderr, "  register  create a Cloudflare device and enroll a MASQUE key (--out, --accept-tos)")
	fmt.Fprintln(env.stderr, "  enroll    re-key or activate an existing profile (--config)")
	fmt.Fprintln(env.stderr, "  socks     run the MASQUE tunnel as a SOCKS5 proxy (--config, --bind)")
	fmt.Fprintln(env.stderr, "  probe     dial up to the CONNECT-IP status, no data plane (--config, --sni)")
	fmt.Fprintln(env.stderr, "  check     validate a profile and print a secrets-free summary (--config)")
	fmt.Fprintln(env.stderr, "run `nova-go masque <command> -h` for the flags of a command")
}

// commonOptions are accepted by every subcommand.
type commonOptions struct {
	logLevel   string
	parentPID  int
	eventsFile string
}

func (c *commonOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&c.logLevel, "log-level", "info", "info|debug")
	fs.IntVar(&c.parentPID, "parent-pid", 0, "exit when this process exits")
	fs.StringVar(&c.eventsFile, "events-file", "", "also append event lines to this file")
}

// setup builds the logger and the event emitter. A non-zero code means "exit with it".
func (env *cliEnv) setup(c commonOptions, sub string) (*Logger, *events.Emitter, func(), int) {
	level := strings.ToLower(strings.TrimSpace(c.logLevel))
	if level != "info" && level != "debug" {
		fmt.Fprintf(env.stderr, "unknown --log-level %q (info|debug)\n", c.logLevel)
		return nil, nil, nil, ExitUsage
	}
	log := NewLogger(env.stderr, level == "debug")
	InstallStdlogBridge(log)
	em := events.New(EventPrefix, env.stdout)
	if c.eventsFile != "" {
		if err := em.SetFile(c.eventsFile); err != nil {
			log.Error("cannot open the events file", "path", c.eventsFile, "err", err)
			return nil, nil, nil, ExitUsage
		}
	}
	log.Debug("nova-go masque", "command", sub, "version", env.version)
	cleanup := func() {
		if err := em.Close(); err != nil {
			log.Warn("closing the events file failed", "err", err)
		}
	}
	return log, em, cleanup, ExitOK
}

// startStopWatch cancels ctx on Ctrl+C and when the parent process exits. stop=true means the
// command must exit now with code (parent already gone: 0; parent cannot be watched: 1 — an
// unwatched helper would outlive Nova and keep port 1370).
func (env *cliEnv) startStopWatch(ctx context.Context, cancel context.CancelCauseFunc, parentPID int, log *Logger) (int, bool) {
	installSignalStop(ctx, cancel)
	if parentPID <= 0 {
		return ExitOK, false
	}
	done, err := parentwatch.Watch(parentPID)
	if errors.Is(err, parentwatch.ErrGone) {
		log.Info("parent process is already gone", "parent_pid", parentPID)
		return ExitOK, true
	}
	if err != nil {
		log.Error("cannot watch the parent process", "parent_pid", parentPID, "err", err)
		return ExitInternal, true
	}
	go func() {
		select {
		case <-done:
			log.Info("parent process exited", "parent_pid", parentPID)
			cancel(errParentGone)
		case <-ctx.Done():
		}
	}()
	return ExitOK, false
}

func stopClass(code int) string {
	if code == ExitOK {
		return errParentGone.Error()
	}
	return "parent_watch"
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func randRead(b []byte) (int, error) { return rand.Read(b) }

// parseFlags parses a FlagSet with stderr output and rejects positional arguments. ok=false means
// "exit with code" (0 after -h, 2 on a bad flag).
func (env *cliEnv) parseFlags(fs *flag.FlagSet, args []string) (ok bool, code int) {
	fs.SetOutput(env.stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, ExitOK
		}
		return false, ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.stderr, "unexpected arguments: %v\n", fs.Args())
		return false, ExitUsage
	}
	return true, ExitOK
}
