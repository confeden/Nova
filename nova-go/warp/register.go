// Package warp registers a WARP device with Cloudflare and finds WARP endpoints that complete a real
// WireGuard handshake for that device. It is the Go half of Nova PC's own-WARP profile generator: the
// Python side (resources/nova_warp_generator.py) owns keys, config assembly and the re-issue policy.
//
// Registration is a port of Nova Android nova-core/engine/register.go: the same endpoint, headers,
// long-form tos, uTLS profile table with ClientHello fragmentation and pinned API addresses. The
// Android-only pieces (local proxy default, plain-through-tunnel switch, cancel hook) are left out;
// an explicit HTTP CONNECT proxy tier replaces the proxy default.
package warp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	// APIHost is the Cloudflare client API. It is SNI-filtered from Russia, hence the tiers below.
	APIHost = "api.cloudflareclient.com"
	// RegistrationPath pairs with ClientVersion; the warp-plus copy (v0a4005) is stale.
	RegistrationPath = "/v0a4471/reg"
	ClientVersion    = "a-6.35-4471"
	UserAgent        = "WARP for Android"

	// maxResponseBytes caps any API body we buffer.
	maxResponseBytes = 512 * 1024
)

// Logf receives the helper's human log lines. Messages never carry keys, tokens or proxy credentials.
type Logf func(format string, args ...any)

func (l Logf) printf(format string, args ...any) {
	if l != nil {
		l(format, args...)
	}
}

// ErrUsage marks a caller mistake (bad key, bad proxy URL, bad mode); the CLI maps it to exit 2.
var ErrUsage = errors.New("usage")

var (
	// registrationDNS is the bootstrap resolver list of register.go. The answers only confirm the
	// pinned addresses: anything else is ignored, exactly as on Android.
	registrationDNS = []string{
		"111.88.96.50:53",
		"111.88.96.51:53",
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
	}
	registrationPinnedIPs = []netip.Addr{
		netip.MustParseAddr("104.16.24.84"),
		netip.MustParseAddr("104.16.192.82"),
	}
)

// registrationRequest is the body of POST /reg. Field order is the wire order.
type registrationRequest struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OsVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

// registrationProfile is one direct attempt shape: a uTLS fingerprint plus how the first bytes of
// the ClientHello are cut. splitPlan is a list of chunk sizes; fragmentSize cuts evenly; either way
// only the first fragmentBytes bytes are cut, the rest of the record goes out in one write.
type registrationProfile struct {
	label            string
	helloID          utls.ClientHelloID
	splitPlan        []int
	fragmentSize     int
	fragmentBytes    int
	fragmentDelay    time.Duration
	handshakeTimeout time.Duration
}

// defaultProfiles is register.go's defaultCloudflareProfiles, unchanged in content and order.
func defaultProfiles() []registrationProfile {
	return []registrationProfile{
		{label: "android-okhttp-multisplit-512", helloID: utls.HelloAndroid_11_OkHttp, splitPlan: []int{1, 255, 256}, fragmentBytes: 512, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "android-okhttp-multisplit-664", helloID: utls.HelloAndroid_11_OkHttp, splitPlan: []int{1, 663}, fragmentBytes: 664, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "chrome-multisplit-681", helloID: utls.HelloChrome_Auto, splitPlan: []int{1, 680}, fragmentBytes: 681, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "chrome-multisplit-540", helloID: utls.HelloChrome_Auto, splitPlan: []int{1, 269, 270}, fragmentBytes: 540, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "firefox-multisplit-681", helloID: utls.HelloFirefox_Auto, splitPlan: []int{1, 680}, fragmentBytes: 681, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "firefox-multisplit-540", helloID: utls.HelloFirefox_Auto, splitPlan: []int{1, 269, 270}, fragmentBytes: 540, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "randomized-noalpn-multisplit-664", helloID: utls.HelloRandomizedNoALPN, splitPlan: []int{1, 663}, fragmentBytes: 664, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "randomized-noalpn-multisplit-540", helloID: utls.HelloRandomizedNoALPN, splitPlan: []int{1, 269, 270}, fragmentBytes: 540, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 9 * time.Second},
		{label: "android-okhttp-split-16", helloID: utls.HelloAndroid_11_OkHttp, fragmentSize: 16, fragmentBytes: 640, fragmentDelay: 5 * time.Millisecond, handshakeTimeout: 8 * time.Second},
		{label: "android-okhttp-split-32", helloID: utls.HelloAndroid_11_OkHttp, fragmentSize: 32, fragmentBytes: 768, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 8 * time.Second},
		{label: "chrome-split-32", helloID: utls.HelloChrome_Auto, fragmentSize: 32, fragmentBytes: 896, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 8 * time.Second},
		{label: "firefox-split-24", helloID: utls.HelloFirefox_Auto, fragmentSize: 24, fragmentBytes: 768, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 8 * time.Second},
		{label: "randomized-noalpn-split-24", helloID: utls.HelloRandomizedNoALPN, fragmentSize: 24, fragmentBytes: 768, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 8 * time.Second},
		{label: "chrome-split-16", helloID: utls.HelloChrome_Auto, fragmentSize: 16, fragmentBytes: 640, fragmentDelay: 4 * time.Millisecond, handshakeTimeout: 8 * time.Second},
		{label: "android-okhttp-split-24", helloID: utls.HelloAndroid_11_OkHttp, fragmentSize: 24, fragmentBytes: 736, fragmentDelay: 5 * time.Millisecond, handshakeTimeout: 6 * time.Second},
	}
}

// proxyProfile is a TLS shape used inside a CONNECT tunnel. The hop to the proxy already hides the
// name, so the ClientHello is not fragmented there.
type proxyProfile struct {
	label   string
	helloID utls.ClientHelloID
}

func defaultProxyProfiles() []proxyProfile {
	return []proxyProfile{
		{label: "android-okhttp", helloID: utls.HelloAndroid_11_OkHttp},
		{label: "chrome", helloID: utls.HelloChrome_Auto},
	}
}

// CloudflareTime renders the long-form tos timestamp: milliseconds and a numeric offset, always UTC
// ("2026-09-13T12:34:56.000+00:00"). The short "...Z" form registers a device that is never served.
func CloudflareTime(now time.Time) string {
	return now.UTC().Format("2006-01-02T15:04:05.000-07:00")
}

// RandomSerial returns 16 lowercase hex characters, as the Android client's serial_number.
func RandomSerial() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random serial: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// DecodeKey decodes a standard-base64 WireGuard key and checks it is 32 bytes. The error never
// echoes the input, so it is safe for private keys.
func DecodeKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("%w: key is not valid base64", ErrUsage)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("%w: key decodes to %d bytes, want 32", ErrUsage, len(raw))
	}
	return raw, nil
}

// BuildRegistrationBody renders the POST /reg JSON body. Empty model/locale take the Android
// defaults "PC" and "en-US".
func BuildRegistrationBody(publicKey, model, locale, serial string, now time.Time) ([]byte, error) {
	if strings.TrimSpace(model) == "" {
		model = "PC"
	}
	if strings.TrimSpace(locale) == "" {
		locale = "en-US"
	}
	return json.Marshal(registrationRequest{
		Key:       strings.TrimSpace(publicKey),
		InstallID: "",
		FcmToken:  "",
		Tos:       CloudflareTime(now),
		Model:     strings.TrimSpace(model),
		Serial:    serial,
		OsVersion: "",
		KeyType:   "curve25519",
		TunType:   "wireguard",
		Locale:    strings.TrimSpace(locale),
	})
}

// RegisterOptions configures Register.
type RegisterOptions struct {
	PublicKey string // base64 X25519 public key
	Model     string // default "PC"
	Locale    string // default "en-US"
	API       APIOptions
}

// Register creates a WARP device for PublicKey. On HTTP 200 with a JSON object body it returns the
// response; a non-200 answer comes back as *StatusError (with the response), transport exhaustion
// as an error wrapping ErrUnreachable, bad options as ErrUsage.
func Register(ctx context.Context, opts RegisterOptions) (*APIResponse, error) {
	if _, err := DecodeKey(opts.PublicKey); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	body, err := BuildRegistrationBody(opts.PublicKey, opts.Model, opts.Locale, serial, time.Now())
	if err != nil {
		return nil, fmt.Errorf("encode registration request: %w", err)
	}
	return DoAPIRequest(ctx, APIRequest{
		Label:      "warp-register",
		Method:     http.MethodPost,
		Path:       RegistrationPath,
		Body:       body,
		ValidateOK: requireJSONObject,
	}, opts.API)
}

// requireJSONObject rejects a 200 whose body is not a JSON object — a proxy's HTML page, for one —
// so the next tier is tried instead of handing garbage to the caller.
func requireJSONObject(body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return errors.New("empty body")
	}
	if !strings.HasPrefix(trimmed, "{") || !json.Valid([]byte(trimmed)) {
		return fmt.Errorf("body is not a JSON object (%d bytes)", len(body))
	}
	return nil
}
