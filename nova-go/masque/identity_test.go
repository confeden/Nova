package masque

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	usquemodels "github.com/Diniboy1123/usque/models"
)

// testKeys returns a base64 SEC1 private key and a PEM endpoint public key for profile fixtures.
func testKeys(t *testing.T) (privB64, peerPEM string) {
	t.Helper()
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, peerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peerPub}))
}

func TestParseIdentityAndroidShape(t *testing.T) {
	priv, peer := testKeys(t)
	raw, _ := json.Marshal(map[string]any{
		"private_key":            priv,
		"endpoint_v4":            "162.159.198.2:0",
		"endpoint_v6":            "[2606:4700:103::2]:0",
		"endpoint_v4_candidates": []string{"162.159.198.2", "10.0.0.1:443", "2606:4700:103::9", "bogus"},
		"endpoint_pub_key":       peer,
		"endpoint_host":          "engage.cloudflareclient.com:2408",
		"ipv4":                   "172.16.0.2",
		"ipv6":                   "2606:4700:110:8a36::2/128",
		"ports":                  []int{8095, 8443, 4443, 1701, 4500, 500, 443, 0, 70000},
		"access_token":           "tok",
		"device_id":              "  dev-1  ",
		"issued_at":              1757757600,
		"last_port":              8443,
	})
	id, err := ParseIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if id.EndpointV4 != "162.159.198.2" || id.EndpointV6 != "2606:4700:103::2" {
		t.Fatalf("endpoints not normalized: %q %q", id.EndpointV4, id.EndpointV6)
	}
	// Primary first, then valid IPv4 candidates, then the known sibling; wrong family and junk dropped.
	wantV4 := []string{"162.159.198.2", "10.0.0.1", "162.159.198.1"}
	if !reflect.DeepEqual(id.EndpointV4Candidates, wantV4) {
		t.Fatalf("v4 candidates = %v, want %v", id.EndpointV4Candidates, wantV4)
	}
	wantV6 := []string{"2606:4700:103::2", "2606:4700:103::1"}
	if !reflect.DeepEqual(id.EndpointV6Candidates, wantV6) {
		t.Fatalf("v6 candidates = %v, want %v", id.EndpointV6Candidates, wantV6)
	}
	// File order is kept (an Android export stays Android-ordered), invalid ports dropped.
	wantPorts := []int{8095, 8443, 4443, 1701, 4500, 500, 443}
	if !reflect.DeepEqual(id.Ports, wantPorts) {
		t.Fatalf("ports = %v, want %v", id.Ports, wantPorts)
	}
	if id.IPv6 != "2606:4700:110:8a36::2" || id.DeviceID != "dev-1" || id.IssuedAt != 1757757600 {
		t.Fatalf("fields: ipv6=%q device=%q issued=%d", id.IPv6, id.DeviceID, id.IssuedAt)
	}
}

func TestParseIdentityUsqueShape(t *testing.T) {
	priv, peer := testKeys(t)
	raw, _ := json.Marshal(map[string]any{
		"private_key":      priv,
		"endpoint_v4":      "162.159.198.1",
		"endpoint_v6":      "2606:4700:103::1",
		"endpoint_pub_key": peer,
		"license":          "lic",
		"id":               "usque-device",
		"access_token":     "tok",
		"ipv4":             "172.16.0.2",
		"ipv6":             "2606:4700:110:8a36::2",
	})
	id, err := ParseIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if id.DeviceID != "usque-device" {
		t.Fatalf("id not mapped to device_id: %q", id.DeviceID)
	}
	if !reflect.DeepEqual(id.Ports, DefaultPorts) {
		t.Fatalf("usque file without ports must get the PC defaults, got %v", id.Ports)
	}
	if !reflect.DeepEqual(id.EndpointV4Candidates, []string{"162.159.198.1", "162.159.198.2"}) {
		t.Fatalf("siblings missing: %v", id.EndpointV4Candidates)
	}
	// An explicit device_id wins over usque's id.
	raw2 := strings.Replace(string(raw), `"id":"usque-device"`, `"id":"usque-device","device_id":"android-device"`, 1)
	id2, err := ParseIdentity([]byte(raw2))
	if err != nil {
		t.Fatal(err)
	}
	if id2.DeviceID != "android-device" {
		t.Fatalf("device_id should win over id, got %q", id2.DeviceID)
	}
}

func TestParseIdentityRejectsInvalidProfiles(t *testing.T) {
	priv, peer := testKeys(t)
	base := map[string]any{"private_key": priv, "endpoint_pub_key": peer, "endpoint_v4": "162.159.198.2", "ipv4": "172.16.0.2"}
	cases := map[string]func(m map[string]any){
		"no private key":  func(m map[string]any) { delete(m, "private_key") },
		"no endpoint key": func(m map[string]any) { m["endpoint_pub_key"] = "  " },
		"no endpoint":     func(m map[string]any) { delete(m, "endpoint_v4") },
		"hostname only":   func(m map[string]any) { m["endpoint_v4"] = "engage.cloudflareclient.com:2408" },
		"no tunnel addr":  func(m map[string]any) { delete(m, "ipv4") },
		"ipv4 not v4":     func(m map[string]any) { m["ipv4"] = "2606:4700::1" },
	}
	for name, mutate := range cases {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mutate(m)
		raw, _ := json.Marshal(m)
		if _, err := ParseIdentity(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseIdentity([]byte("  ")); err == nil {
		t.Error("empty profile accepted")
	}
	if _, err := ParseIdentity([]byte("{not json")); err == nil {
		t.Error("broken JSON accepted")
	}
	raw, _ := json.Marshal(base)
	if _, err := ParseIdentity(raw); err != nil {
		t.Fatalf("minimal valid profile rejected: %v", err)
	}
}

// GM-3: Nova's profile listing reads a UTF-8 BOM or UTF-16 ("Unicode" in Notepad) file, so the
// helper must read the same bytes instead of failing with exit 3.
func TestParseIdentityAcceptsBOMAndUTF16(t *testing.T) {
	priv, peer := testKeys(t)
	plain, _ := json.Marshal(map[string]any{"private_key": priv, "endpoint_pub_key": peer, "endpoint_v4": "162.159.198.2",
		"ipv4": "172.16.0.2", "nova": map[string]any{"name": "Мой профиль"}, "future_key": 1})
	utf16Bytes := func(order binary.AppendByteOrder, bom []byte) []byte {
		units := utf16.Encode([]rune(string(plain)))
		out := append([]byte(nil), bom...)
		for _, u := range units {
			out = order.AppendUint16(out, u)
		}
		return out
	}
	cases := map[string][]byte{
		"utf-8 bom": append([]byte{0xEF, 0xBB, 0xBF}, plain...),
		"utf-16le":  utf16Bytes(binary.LittleEndian, []byte{0xFF, 0xFE}),
		"utf-16be":  utf16Bytes(binary.BigEndian, []byte{0xFE, 0xFF}),
	}
	for name, raw := range cases {
		id, err := ParseIdentity(raw)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if id.PrivateKey != priv || id.EndpointV4 != "162.159.198.2" || !strings.Contains(string(id.Nova), "Мой профиль") {
			t.Errorf("%s: fields lost: %+v", name, id)
		}
		// A rewrite (enroll) keeps the unknown keys of such a file and writes plain UTF-8.
		doc, err := MarshalDocument(id, raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(doc), `"future_key"`) || doc[0] != '{' {
			t.Errorf("%s: rewrite lost unknown keys or kept a BOM: %s", name, doc)
		}
	}
	if _, err := ParseIdentity([]byte{0xEF, 0xBB, 0xBF, ' '}); err == nil {
		t.Error("a BOM-only profile accepted")
	}
}

func TestNormalizeEndpointHost(t *testing.T) {
	cases := map[string]string{
		"162.159.198.2:0":                  "162.159.198.2",
		" 162.159.198.2 ":                  "162.159.198.2",
		"[2606:4700:103::2]:0":             "2606:4700:103::2",
		"[2606:4700:103::2]":               "2606:4700:103::2",
		"2606:4700:103::2":                 "2606:4700:103::2",
		"engage.cloudflareclient.com:2408": "engage.cloudflareclient.com",
		"":                                 "",
	}
	for in, want := range cases {
		if got := NormalizeEndpointHost(in); got != want {
			t.Errorf("NormalizeEndpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildIdentityFromDeviceRecord(t *testing.T) {
	_, peer := testKeys(t)
	priv, _, _ := GenerateKeyPair()
	var account usquemodels.AccountData
	account.ID = "device-123456789"
	account.Account.License = "lic"
	account.Config.Interface.Addresses.V4 = "172.16.0.2"
	account.Config.Interface.Addresses.V6 = "2606:4700:110:8a36::2"
	var p usquemodels.Peer
	p.PublicKey = peer
	p.Endpoint.V4 = "162.159.198.2:0"
	p.Endpoint.V6 = "[2606:4700:103::2]:0"
	p.Endpoint.Host = "engage.cloudflareclient.com:2408"
	p.Endpoint.Ports = []int{2408, 443, 500}
	account.Config.Peers = []usquemodels.Peer{p}

	issued := time.Unix(1789273257, 0)
	id, err := BuildIdentity(account, priv, "token", issued)
	if err != nil {
		t.Fatal(err)
	}
	if id.EndpointV4 != "162.159.198.2" || id.EndpointV6 != "2606:4700:103::2" || id.IssuedAt != issued.Unix() {
		t.Fatalf("identity: %+v", id)
	}
	// Registered profiles get the PC order first, extra server ports after.
	wantPorts := append(append([]int(nil), DefaultPorts...), 2408)
	if !reflect.DeepEqual(id.Ports, wantPorts) {
		t.Fatalf("ports = %v, want %v", id.Ports, wantPorts)
	}
	account.Config.Peers = nil
	if _, err := BuildIdentity(account, priv, "token", issued); err == nil {
		t.Fatal("record without peers accepted")
	}
}

func TestMarshalDocumentPreservesUnknownKeysAndNova(t *testing.T) {
	priv, peer := testKeys(t)
	previous := []byte(`{"private_key":"old","future_android_key":{"a":1},"id":"x","nova":{"schema":1,"name":"Мой профиль"}}`)
	id := Identity{PrivateKey: priv, EndpointV4: "162.159.198.2", EndpointPubKey: peer, IPv4: "172.16.0.2",
		Ports: DefaultPorts, Nova: json.RawMessage(`{"schema":1,"name":"Мой профиль"}`)}
	doc, err := MarshalDocument(id, previous)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(doc, &back); err != nil {
		t.Fatalf("document is not JSON: %v\n%s", err, doc)
	}
	var future map[string]int
	if err := json.Unmarshal(back["future_android_key"], &future); err != nil || future["a"] != 1 {
		t.Fatalf("unknown key lost: %s", doc)
	}
	if _, ok := back["id"]; ok {
		t.Fatalf("usque id must not be written back: %s", doc)
	}
	if !strings.Contains(string(doc), "Мой профиль") {
		t.Fatalf("nova object lost: %s", doc)
	}
	if strings.Index(string(doc), `"private_key"`) > strings.Index(string(doc), `"ipv4"`) {
		t.Fatalf("known keys must keep the documented order: %s", doc)
	}
	parsed, err := ParseIdentity(doc)
	if err != nil {
		t.Fatalf("written document does not parse: %v", err)
	}
	if parsed.PrivateKey != priv {
		t.Fatal("private key changed in round trip")
	}
}
