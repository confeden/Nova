package warp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

// testPublicKey is base64 of bytes 0x01..0x20.
func testPublicKey() string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestRegistrationBodyGolden(t *testing.T) {
	now := time.Date(2026, 9, 13, 15, 34, 56, 789_000_000, time.FixedZone("MSK", 3*3600))
	body, err := BuildRegistrationBody(testPublicKey(), "", "", "0123456789abcdef", now)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","install_id":"","fcm_token":"",` +
		`"tos":"2026-09-13T12:34:56.789+00:00","model":"PC","serial_number":"0123456789abcdef",` +
		`"os_version":"","key_type":"curve25519","tunnel_type":"wireguard","locale":"en-US"}`
	if string(body) != want {
		t.Fatalf("body mismatch\n got: %s\nwant: %s", body, want)
	}

	custom, err := BuildRegistrationBody(" "+testPublicKey()+" ", "Workstation", "ru-RU", "ffffffffffffffff", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"model":"Workstation"`, `"locale":"ru-RU"`, `"key":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="`} {
		if !strings.Contains(string(custom), fragment) {
			t.Errorf("custom body lacks %s: %s", fragment, custom)
		}
	}
}

func TestCloudflareTimeIsLongFormUTC(t *testing.T) {
	cases := []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "2026-01-02T03:04:05.000+00:00"},
		{time.Date(2026, 9, 13, 0, 30, 0, 123_456_789, time.FixedZone("MSK", 3*3600)), "2026-09-12T21:30:00.123+00:00"},
		{time.Date(2026, 12, 31, 23, 59, 59, 999_999_999, time.FixedZone("PST", -8*3600)), "2027-01-01T07:59:59.999+00:00"},
	}
	for _, c := range cases {
		if got := CloudflareTime(c.in); got != c.want {
			t.Errorf("CloudflareTime(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := CloudflareTime(time.Now()); !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00$`).MatchString(got) {
		t.Errorf("tos %q is not the long form", got)
	}
}

func TestRandomSerialFormat(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	a, err := RandomSerial()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomSerial()
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString(a) || !re.MatchString(b) {
		t.Fatalf("serials %q %q are not 16 lowercase hex chars", a, b)
	}
	if a == b {
		t.Fatalf("two serials are equal: %q", a)
	}
}

func TestAPIRequestHeadersGolden(t *testing.T) {
	req, err := newAPIHTTPRequest(context.Background(), APIRequest{Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	want := "POST /v0a4471/reg HTTP/1.1\r\n" +
		"Host: api.cloudflareclient.com\r\n" +
		"User-Agent: WARP for Android\r\n" +
		"Content-Length: 2\r\n" +
		"Accept: application/json\r\n" +
		"Accept-Encoding: identity\r\n" +
		"CF-Client-Version: a-6.35-4471\r\n" +
		"Connection: close\r\n" +
		"Content-Type: application/json; charset=UTF-8\r\n" +
		"\r\n" +
		"{}"
	if wire.String() != want {
		t.Fatalf("request mismatch\n got: %q\nwant: %q", wire.String(), want)
	}

	authed, err := newAPIHTTPRequest(context.Background(), APIRequest{Method: "put", Path: "v0a4471/reg/dev/account", AuthToken: " tok "})
	if err != nil {
		t.Fatal(err)
	}
	if authed.Method != http.MethodPut || authed.URL.Path != "/v0a4471/reg/dev/account" {
		t.Errorf("method/path = %s %s", authed.Method, authed.URL.Path)
	}
	if got := authed.Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestProfileTableMatchesAndroid(t *testing.T) {
	profiles := defaultProfiles()
	if len(profiles) != 15 {
		t.Fatalf("profiles = %d, want 15", len(profiles))
	}
	wantLabels := []string{
		"android-okhttp-multisplit-512", "android-okhttp-multisplit-664", "chrome-multisplit-681",
		"chrome-multisplit-540", "firefox-multisplit-681", "firefox-multisplit-540",
		"randomized-noalpn-multisplit-664", "randomized-noalpn-multisplit-540", "android-okhttp-split-16",
		"android-okhttp-split-32", "chrome-split-32", "firefox-split-24", "randomized-noalpn-split-24",
		"chrome-split-16", "android-okhttp-split-24",
	}
	for i, p := range profiles {
		if p.label != wantLabels[i] {
			t.Errorf("profile %d label %q, want %q", i, p.label, wantLabels[i])
		}
		if p.handshakeTimeout < 6*time.Second || p.handshakeTimeout > 9*time.Second {
			t.Errorf("%s handshake timeout %s", p.label, p.handshakeTimeout)
		}
		if p.fragmentDelay < 4*time.Millisecond || p.fragmentDelay > 5*time.Millisecond {
			t.Errorf("%s delay %s", p.label, p.fragmentDelay)
		}
		sum := 0
		for _, n := range p.splitPlan {
			sum += n
		}
		if len(p.splitPlan) > 0 && sum != p.fragmentBytes {
			t.Errorf("%s split plan sums to %d, fragmentBytes %d", p.label, sum, p.fragmentBytes)
		}
		if len(p.splitPlan) == 0 && (p.fragmentSize <= 0 || p.fragmentBytes <= 0) {
			t.Errorf("%s cuts nothing", p.label)
		}
	}
}

func TestPinnedAddressesAndBootstrapDNS(t *testing.T) {
	wantIPs := []netip.Addr{netip.MustParseAddr("104.16.24.84"), netip.MustParseAddr("104.16.192.82")}
	if len(registrationPinnedIPs) != 2 || registrationPinnedIPs[0] != wantIPs[0] || registrationPinnedIPs[1] != wantIPs[1] {
		t.Fatalf("pinned = %v", registrationPinnedIPs)
	}
	wantDNS := "111.88.96.50:53,111.88.96.51:53,1.1.1.1:53,1.0.0.1:53,8.8.8.8:53,8.8.4.4:53"
	if got := strings.Join(registrationDNS, ","); got != wantDNS {
		t.Fatalf("dns = %s", got)
	}
	if isPinnedIP(netip.MustParseAddr("162.159.137.105")) || !isPinnedIP(wantIPs[1]) {
		t.Fatal("isPinnedIP disagrees with the pinned list")
	}
}

func TestDecodeKeyNeverEchoesInput(t *testing.T) {
	secret := "c2VjcmV0LXByaXZhdGUta2V5LXRoYXQtaXMtbG9uZw" // not padded, not 32 bytes
	for _, in := range []string{secret, "!!!not-base64!!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		_, err := DecodeKey(in)
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("DecodeKey(%q) err = %v, want ErrUsage", in, err)
		}
		if strings.Contains(err.Error(), in) {
			t.Fatalf("error %q echoes the key", err)
		}
	}
	if _, err := DecodeKey(" " + testPublicKey() + "\r\n"); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeAuto, "AUTO": ModeAuto, "direct": ModeDirect, " proxy ": ModeProxy, "plain": ModePlain} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("tor"); !errors.Is(err, ErrUsage) {
		t.Errorf("ParseMode(tor) err = %v", err)
	}
}

func TestDefinitiveStatus(t *testing.T) {
	for code, want := range map[int]bool{200: false, 400: true, 401: true, 404: true, 422: true, 429: false,
		403: false, 407: false, 408: false, 421: false, 425: false, 500: false, 503: false} {
		if got := definitiveStatus(code); got != want {
			t.Errorf("definitiveStatus(%d) = %t, want %t", code, got, want)
		}
	}
	// A rate limit is per client address: it ends the tier, not the search.
	for code, want := range map[int]bool{429: true, 400: false, 403: false, 500: false, 503: false, 200: false} {
		if got := tierEndingStatus(code); got != want {
			t.Errorf("tierEndingStatus(%d) = %t, want %t", code, got, want)
		}
	}
}

func TestRegisterRejectsBadPublicKey(t *testing.T) {
	_, err := Register(context.Background(), RegisterOptions{PublicKey: "abc"})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err = %v, want ErrUsage", err)
	}
}
