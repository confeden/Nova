// Package apifail turns a pile of per-attempt transport errors of the Cloudflare API client into one
// short, readable summary ("direct 104.16.24.84: 2xtls-timeout; proxy: proxy-dial"). Both API
// clients (nova-go/warp and nova-go/masque) use it, so the two log the same words.
//
// The summary leads the error text because callers truncate that text (the Python side keeps 240
// characters), and a line of socket addresses says nothing about the cause.
package apifail

import (
	"fmt"
	"strings"
)

// Entry is one failed attempt: Group names the route family ("direct 104.16.24.84", "proxy",
// "plain"), Class is a short reason from ClassifyText or the caller's own sentinel errors.
type Entry struct {
	Group string
	Class string
}

// Superseded is the class of an attempt abandoned because another one had answered; it is not a
// failure of its route and Summarize leaves it out.
const Superseded = "superseded"

// ClassifyText names a transport failure in one short word from its message.
func ClassifyText(text string) string {
	text = strings.ToLower(text)
	has := func(parts ...string) bool {
		for _, p := range parts {
			if strings.Contains(text, p) {
				return true
			}
		}
		return false
	}
	switch {
	case has("proxy refused connect"):
		return "proxy-refused"
	case has("proxy unreachable", "proxyconnect"):
		return "proxy-dial"
	case has("tcp dial"):
		return "tcp-dial"
	case has("tls handshake") && has("i/o timeout", "deadline exceeded", "timeout"):
		return "tls-timeout"
	case has("connection reset", "forcibly closed"):
		return "reset"
	case has("eof"):
		return "eof"
	case has("certificate", "x509"):
		return "cert"
	case has("unusable body", "not a json"):
		return "bad-body"
	case has("skipped", "quarantine"):
		return "skipped"
	case has("i/o timeout", "deadline exceeded", "timeout"):
		return "timeout"
	}
	return "other"
}

// Summarize groups entries in first-seen order: "direct 104.16.24.84: 2xtls-timeout,tcp-dial; proxy: proxy-dial".
func Summarize(entries []Entry) string {
	type group struct {
		name   string
		counts map[string]int
		order  []string
	}
	var groups []*group
	byName := make(map[string]*group)
	for _, e := range entries {
		if e.Class == Superseded {
			continue
		}
		g := byName[e.Group]
		if g == nil {
			g = &group{name: e.Group, counts: map[string]int{}}
			byName[e.Group] = g
			groups = append(groups, g)
		}
		if g.counts[e.Class] == 0 {
			g.order = append(g.order, e.Class)
		}
		g.counts[e.Class]++
	}
	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		classes := make([]string, 0, len(g.order))
		for _, c := range g.order {
			if n := g.counts[c]; n > 1 {
				classes = append(classes, fmt.Sprintf("%dx%s", n, c))
			} else {
				classes = append(classes, c)
			}
		}
		parts = append(parts, g.name+": "+strings.Join(classes, ","))
	}
	return strings.Join(parts, "; ")
}
