package events

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatKeepsVersionEventAndFieldOrder(t *testing.T) {
	got := Format("attempt",
		F("n", 1),
		F("endpoint", "162.159.198.2:443"),
		F("transport", "h2"),
		F("sni", "yastatic.net"),
	)
	want := `{"v":1,"ev":"attempt","n":1,"endpoint":"162.159.198.2:443","transport":"h2","sni":"yastatic.net"}`
	if got != want {
		t.Fatalf("Format:\n got %s\nwant %s", got, want)
	}
}

func TestFormatDoesNotEscapeHTMLAndEscapesPaths(t *testing.T) {
	got := Format("registered", F("path", `profiles\MASQUE\cf-masque-1.json`), F("err", "a<b>&c"))
	want := `{"v":1,"ev":"registered","path":"profiles\\MASQUE\\cf-masque-1.json","err":"a<b>&c"}`
	if got != want {
		t.Fatalf("Format:\n got %s\nwant %s", got, want)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if decoded["path"] != `profiles\MASQUE\cf-masque-1.json` {
		t.Fatalf("path round trip: %v", decoded["path"])
	}
}

func TestFormatSkipsReservedKeysAndSurvivesUnmarshalableValues(t *testing.T) {
	got := Format("x", F("v", 9), F("ev", "y"), F("", 1), F("bad", make(chan int)), F("ok", true))
	if !strings.HasPrefix(got, `{"v":1,"ev":"x","bad":"`) || !strings.HasSuffix(got, `,"ok":true}`) {
		t.Fatalf("unexpected rendering: %s", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
}

func TestEmitterWritesPrefixedLinesToOutputAndFile(t *testing.T) {
	var out bytes.Buffer
	em := New("NOVA_MASQUE", &out)
	path := filepath.Join(t.TempDir(), "events.log")
	if err := em.SetFile(path); err != nil {
		t.Fatal(err)
	}
	em.Emit("start", F("pid", 42))
	em.Emit("exit", F("code", 0))
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	want := "NOVA_MASQUE {\"v\":1,\"ev\":\"start\",\"pid\":42}\nNOVA_MASQUE {\"v\":1,\"ev\":\"exit\",\"code\":0}\n"
	if out.String() != want {
		t.Fatalf("stdout:\n got %q\nwant %q", out.String(), want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("file:\n got %q\nwant %q", string(data), want)
	}
	// The parser contract: split on the first space, the rest is one JSON object.
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		prefix, obj, ok := strings.Cut(line, " ")
		if !ok || prefix != "NOVA_MASQUE" {
			t.Fatalf("bad line %q", line)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(obj), &decoded); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
	}
}
