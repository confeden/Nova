package warp

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"
)

// Live checks against the real api.cloudflareclient.com. Skipped unless NOVA_WARP_LIVE=1; the proxy
// case also needs NOVA_WARP_LIVE_PROXY (e.g. http://127.0.0.1:1371). They send GET for a device id
// that does not exist, so no device is created: any HTTP answer proves the transport and profile.

const liveMissingDevice = RegistrationPath + "/00000000-0000-0000-0000-000000000000"

func liveOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("NOVA_WARP_LIVE") != "1" {
		t.Skip("set NOVA_WARP_LIVE=1 to run live checks")
	}
}

func TestLiveEveryDirectProfileGetsAnAnswer(t *testing.T) {
	liveOnly(t)
	for _, profile := range defaultProfiles() {
		for _, ip := range registrationPinnedIPs {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			resp, err := DoAPIRequest(ctx, APIRequest{Label: "live", Method: http.MethodGet, Path: liveMissingDevice}, APIOptions{
				Mode:  ModeDirect,
				Logf:  t.Logf,
				hooks: &testHooks{pinnedIPs: []netip.Addr{ip}, profiles: []registrationProfile{profile}},
			})
			cancel()
			if resp == nil {
				t.Errorf("%s @ %s: no HTTP answer: %v", profile.label, ip, err)
				continue
			}
			t.Logf("%s @ %s: %s %s", profile.label, ip, resp.Proto, resp.Status)
		}
	}
}

func TestLiveProxyProfilesGetAnAnswer(t *testing.T) {
	liveOnly(t)
	proxyURL := os.Getenv("NOVA_WARP_LIVE_PROXY")
	if proxyURL == "" {
		t.Skip("set NOVA_WARP_LIVE_PROXY to run the proxy live check")
	}
	for _, profile := range defaultProxyProfiles() {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		resp, err := DoAPIRequest(ctx, APIRequest{Label: "live", Method: http.MethodGet, Path: liveMissingDevice}, APIOptions{
			Mode:     ModeProxy,
			ProxyURL: proxyURL,
			Logf:     t.Logf,
			hooks:    &testHooks{proxyProfiles: []proxyProfile{profile}},
		})
		cancel()
		if resp == nil {
			t.Errorf("proxy/%s: no HTTP answer: %v", profile.label, err)
			continue
		}
		t.Logf("proxy/%s: %s %s", profile.label, resp.Proto, resp.Status)
	}
}
