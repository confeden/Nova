// Package events writes the machine-readable event lines of nova-go helpers.
//
// A line is `<PREFIX> <one-line JSON object>`; the object always starts with `"v":1` and `"ev"`,
// followed by the event fields in the order the caller gave them. Callers (nova.pyw) split the line
// on the first space and parse the rest as JSON, so field order is cosmetic, but a stable order keeps
// logs diffable and matches the documented examples verbatim.
package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Version is the value of the "v" key of every event object.
const Version = 1

// Field is one key/value pair of an event, kept in caller order.
type Field struct {
	Key   string
	Value any
}

// F builds a Field.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Format renders the JSON object of an event (without the line prefix).
//
// A value that cannot be marshalled (a channel, a func) is rendered as its fmt.Sprint text instead
// of failing the whole line: an event that says a little less is better than no event.
func Format(ev string, fields ...Field) string {
	var buf bytes.Buffer
	buf.WriteString(`{"v":`)
	fmt.Fprintf(&buf, "%d", Version)
	buf.WriteString(`,"ev":`)
	buf.Write(encodeValue(ev))
	for _, f := range fields {
		if f.Key == "" || f.Key == "v" || f.Key == "ev" {
			continue
		}
		buf.WriteByte(',')
		buf.Write(encodeValue(f.Key))
		buf.WriteByte(':')
		buf.Write(encodeValue(f.Value))
	}
	buf.WriteByte('}')
	return buf.String()
}

func encodeValue(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		buf.Reset()
		enc = json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(fmt.Sprint(v)) // a string always encodes
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// Emitter writes event lines to an output (stdout) and optionally appends them to a file.
type Emitter struct {
	prefix string

	mu      sync.Mutex
	out     io.Writer
	file    *os.File
	lastErr error
}

// New creates an emitter writing `<prefix> {json}` lines to out.
func New(prefix string, out io.Writer) *Emitter {
	return &Emitter{prefix: strings.TrimSpace(prefix), out: out}
}

// SetFile additionally appends every line to path (created if missing).
func (e *Emitter) SetFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open events file: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		_ = e.file.Close()
	}
	e.file = f
	return nil
}

// Emit writes one event line and returns the rendered JSON object.
//
// Write errors are remembered (LastError) rather than returned: the event stream is diagnostics
// for the parent, and a closed stdout means the parent is gone, which the parent watchdog handles.
func (e *Emitter) Emit(ev string, fields ...Field) string {
	obj := Format(ev, fields...)
	line := e.prefix + " " + obj + "\n"
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.out != nil {
		if _, err := io.WriteString(e.out, line); err != nil && e.lastErr == nil {
			e.lastErr = err
		}
	}
	if e.file != nil {
		if _, err := e.file.WriteString(line); err != nil && e.lastErr == nil {
			e.lastErr = err
		}
	}
	return obj
}

// LastError returns the first write error seen, if any.
func (e *Emitter) LastError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastErr
}

// Close closes the events file, if one was set.
func (e *Emitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		return nil
	}
	err := e.file.Close()
	e.file = nil
	return err
}
