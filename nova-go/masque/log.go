package masque

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Logger writes the human log on stderr, one line per record:
//
//	2026-09-13T10:00:00.123Z INF masque: <message> key=value …
//
// The helper log is English; Nova's Russian strings live in nova.pyw. Secret-bearing keys are
// redacted to `<N chars>` no matter what the caller passes (and-masque.md §8.4).
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	debug bool
	now   func() time.Time
}

// NewLogger creates a logger; debug enables DBG records.
func NewLogger(out io.Writer, debug bool) *Logger {
	return &Logger{out: out, debug: debug, now: time.Now}
}

// DebugEnabled reports whether DBG records are written.
func (l *Logger) DebugEnabled() bool { return l != nil && l.debug }

func (l *Logger) Debug(msg string, kv ...any) {
	if l.DebugEnabled() {
		l.write("DBG", msg, kv)
	}
}
func (l *Logger) Info(msg string, kv ...any)  { l.write("INF", msg, kv) }
func (l *Logger) Warn(msg string, kv ...any)  { l.write("WRN", msg, kv) }
func (l *Logger) Error(msg string, kv ...any) { l.write("ERR", msg, kv) }

// secretKeys are always redacted, whatever value is passed.
var secretKeys = map[string]bool{
	"private_key": true, "access_token": true, "token": true, "license": true,
	"password": true, "jwt": true, "authorization": true,
}

// Redact renders a secret as its length only.
func Redact(secret string) string { return fmt.Sprintf("<%d chars>", len(secret)) }

func (l *Logger) write(level, msg string, kv []any) {
	if l == nil || l.out == nil {
		return
	}
	var b strings.Builder
	b.WriteString(l.now().UTC().Format("2006-01-02T15:04:05.000Z"))
	b.WriteByte(' ')
	b.WriteString(level)
	b.WriteString(" masque: ")
	b.WriteString(oneLine(msg))
	for i := 0; i < len(kv); i += 2 {
		key := fmt.Sprint(kv[i])
		var value string
		if i+1 < len(kv) {
			value = fmt.Sprint(kv[i+1])
		} else {
			value = "<missing>"
		}
		if secretKeys[strings.ToLower(key)] {
			value = Redact(value)
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(quoteIfNeeded(oneLine(value)))
	}
	b.WriteByte('\n')
	l.mu.Lock()
	_, _ = io.WriteString(l.out, b.String())
	l.mu.Unlock()
}

func oneLine(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(s)
}

func quoteIfNeeded(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\"=") {
		return strconv.Quote(s)
	}
	return s
}

// stdlogBridge routes the standard `log` package (used by connect-ip-go and quic-go) into the
// helper log format, so stderr stays one format. Per-packet library chatter goes to DBG.
type stdlogBridge struct {
	l   *Logger
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *stdlogBridge) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Write(p)
	for {
		line, err := b.buf.ReadString('\n')
		if err != nil {
			// Incomplete line: keep it for the next Write.
			b.buf.Reset()
			b.buf.WriteString(line)
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		// Expected chatter: per-packet drops, the request dump, and quic-go noting that the wrapped
		// socket (trackedPacketConn, on purpose) hides the UDP buffer knobs.
		if strings.HasPrefix(line, "dropping proxied packet") || strings.HasPrefix(line, "CONNECT-IP ") ||
			strings.Contains(line, "receive buffer size") || strings.Contains(line, "send buffer size") {
			b.l.Debug("lib: " + line)
		} else {
			b.l.Info("lib: " + line)
		}
	}
	return len(p), nil
}

// InstallStdlogBridge sends the standard logger's output through l.
func InstallStdlogBridge(l *Logger) {
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(&stdlogBridge{l: l})
}
