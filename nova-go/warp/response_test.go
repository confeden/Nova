package warp

import (
	"strings"
	"testing"
)

const sampleDevice = `{
  "id": "11111111-2222-3333-4444-555555555555",
  "type": "a",
  "name": "",
  "key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
  "account": {"id": "acc", "account_type": "free", "warp_plus": false, "premium_data": 0, "quota": 0, "license": "lic-0123456789"},
  "config": {
    "client_id": "q1b2",
    "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
               "endpoint": {"v4": "162.159.192.1:0", "v6": "[2606:4700:d0::a29f:c001]:0", "host": "engage.cloudflareclient.com:2408", "ports": [2408, 500]}}],
    "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a36::1"}},
    "services": {"http_proxy": "172.16.0.1:2480"}
  },
  "token": "tok-secret-value",
  "warp_enabled": false,
  "place": 0,
  "locale": "en-US"
}`

func TestParseRegistrationBare(t *testing.T) {
	reg, err := ParseRegistration([]byte(sampleDevice))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Wrapped {
		t.Error("bare object reported as wrapped")
	}
	checks := map[string][2]string{
		"id":           {reg.ID, "11111111-2222-3333-4444-555555555555"},
		"token":        {reg.Token, "tok-secret-value"},
		"account_type": {reg.AccountType, "free"},
		"license":      {reg.License, "lic-0123456789"},
		"peer":         {reg.PeerPublicKey, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="},
		"endpoint_v4":  {reg.EndpointV4, "162.159.192.1:0"},
		"endpoint_v6":  {reg.EndpointV6, "[2606:4700:d0::a29f:c001]:0"},
		"host":         {reg.EndpointHost, "engage.cloudflareclient.com:2408"},
		"address_v4":   {reg.AddressV4, "172.16.0.2"},
		"address_v6":   {reg.AddressV6, "2606:4700:110:8a36::1"},
		"client_id":    {reg.ClientID, "q1b2"},
	}
	for name, pair := range checks {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
	// "q1b2" decodes to ab 56 f6.
	if got := reg.ReservedCSV(); got != "171,86,246" {
		t.Errorf("reserved = %q, want 171,86,246", got)
	}
	if reg.Peers != 1 || reg.WarpEnabled {
		t.Errorf("peers=%d warp_enabled=%t", reg.Peers, reg.WarpEnabled)
	}
	if !strings.Contains(strings.Join(reg.Keys, ","), "account,config,id,key,locale,name,place,token,type,warp_enabled") {
		t.Errorf("keys = %v", reg.Keys)
	}
	summary := reg.Summary()
	for _, secret := range []string{reg.ID, reg.Token, reg.License, reg.PeerPublicKey, reg.AddressV6, reg.ClientID} {
		if strings.Contains(summary, secret) {
			t.Errorf("summary leaks %q: %s", secret, summary)
		}
	}
	if !strings.Contains(summary, "token=<16 chars>") || !strings.Contains(summary, "account_type=free") {
		t.Errorf("summary = %s", summary)
	}
}

func TestParseRegistrationResultWrapped(t *testing.T) {
	wrapped := `{"success": true, "errors": [], "messages": [], "result": ` + sampleDevice + `}`
	reg, err := ParseRegistration([]byte(wrapped))
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Wrapped || reg.ID != "11111111-2222-3333-4444-555555555555" || reg.ReservedCSV() != "171,86,246" {
		t.Fatalf("wrapped parse: wrapped=%t id=%q reserved=%q", reg.Wrapped, reg.ID, reg.ReservedCSV())
	}
	for _, key := range reg.Keys {
		if key == "success" || key == "result" {
			t.Fatalf("keys come from the wrapper, not the device: %v", reg.Keys)
		}
	}
}

func TestParseRegistrationReservedNeedsThreeBytes(t *testing.T) {
	for clientID, want := range map[string]string{
		"":         "",
		"AAE=":     "",      // 2 bytes
		"AAEC":     "0,1,2", // exactly 3
		"AAECAw==": "0,1,2", // 4 bytes: first three
		"AAECAw":   "0,1,2", // unpadded
		"%%%":      "",      // not base64
	} {
		body := strings.Replace(sampleDevice, `"client_id": "q1b2"`, `"client_id": "`+clientID+`"`, 1)
		reg, err := ParseRegistration([]byte(body))
		if err != nil {
			t.Fatalf("client_id %q: %v", clientID, err)
		}
		if got := reg.ReservedCSV(); got != want {
			t.Errorf("client_id %q reserved = %q, want %q", clientID, got, want)
		}
	}
}

func TestParseRegistrationRejectsUnusable(t *testing.T) {
	cases := map[string]string{
		"not json":       `<html>blocked</html>`,
		"array":          `[1,2,3]`,
		"null":           `null`,
		"no config":      `{"id":"x","token":"y"}`,
		"no peers":       strings.Replace(sampleDevice, `"peers": [`, `"peers_": [`, 1),
		"bad peer key":   strings.Replace(sampleDevice, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "c2hvcnQ=", 1),
		"no v4 address":  strings.Replace(sampleDevice, `"v4": "172.16.0.2"`, `"v4": ""`, 1),
		"wrong id type":  strings.Replace(sampleDevice, `"id": "11111111-2222-3333-4444-555555555555"`, `"id": 5`, 1),
		"wrapped broken": `{"result": {"config": 7}}`,
	}
	for name, body := range cases {
		if _, err := ParseRegistration([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRequireJSONObject(t *testing.T) {
	if err := requireJSONObject([]byte(" {\"a\":1}\n")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "  ", "<html></html>", "[]", "{broken"} {
		if requireJSONObject([]byte(bad)) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
