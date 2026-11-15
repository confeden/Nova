package apifail

import "testing"

func TestClassifyText(t *testing.T) {
	cases := map[string]string{
		"tls handshake failed: read tcp4 1.2.3.4:5->6.7.8.9:443: i/o timeout": "tls-timeout",
		"tls handshake: read tcp 1.2.3.4:5->6.7.8.9:443: i/o timeout":         "tls-timeout",
		"tcp dial: dial tcp4 6.7.8.9:443: i/o timeout":                        "tcp-dial",
		"Post: proxyconnect tcp: dial tcp 62.60.230.61:2053: i/o timeout":     "proxy-dial",
		"proxy unreachable: dial tcp 62.60.230.61:2053: i/o timeout":          "proxy-dial",
		"proxy refused CONNECT: 407 Proxy Authentication Required":            "proxy-refused",
		"read: connection reset by peer":                                      "reset",
		"tls handshake failed: EOF":                                           "eof",
		"x509: certificate signed by unknown authority":                       "cert",
		"200 with unusable body: body is not a JSON object":                   "bad-body",
		"skipped, it did not accept a connection recently":                    "skipped",
		"Get: context deadline exceeded":                                      "timeout",
		"something nobody has seen":                                           "other",
	}
	for text, want := range cases {
		if got := ClassifyText(text); got != want {
			t.Errorf("ClassifyText(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestSummarizeGroupsInFirstSeenOrderAndDropsSuperseded(t *testing.T) {
	got := Summarize([]Entry{
		{"direct 1.1.1.1", "tls-timeout"},
		{"proxy", "proxy-dial"},
		{"direct 1.1.1.1", "tls-timeout"},
		{"direct 1.1.1.1", "tcp-dial"},
		{"direct 2.2.2.2", Superseded},
	})
	want := "direct 1.1.1.1: 2xtls-timeout,tcp-dial; proxy: proxy-dial"
	if got != want {
		t.Fatalf("Summarize = %q, want %q", got, want)
	}
	if Summarize(nil) != "" {
		t.Fatal("no failures must give an empty summary")
	}
}
