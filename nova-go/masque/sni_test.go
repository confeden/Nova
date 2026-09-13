package masque

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIsCloudflareClientSNI(t *testing.T) {
	blocked := []string{
		"cloudflareclient.com", "zt-masque.cloudflareclient.com", "consumer-masque.cloudflareclient.com",
		"API.CloudflareClient.COM", "engage.cloudflareclient.com.", " x.cloudflareclient.com ",
	}
	for _, h := range blocked {
		if !IsCloudflareClientSNI(h) {
			t.Errorf("%q not recognised as a cloudflareclient.com name", h)
		}
	}
	allowed := []string{"www.google.com", "notcloudflareclient.com", "cloudflareclient.com.evil.net", "cloudflare.com", ""}
	for _, h := range allowed {
		if IsCloudflareClientSNI(h) {
			t.Errorf("%q wrongly blocked", h)
		}
	}
}

func TestBuildSNIOrderDefaultsGuardAndFile(t *testing.T) {
	got, err := BuildSNIOrder(nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www.google.com", "static.twitchcdn.net", "4pda.to", "vk.com", "cdn.jsdelivr.net", "www.microsoft.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default pool = %v", got)
	}

	if _, err := BuildSNIOrder([]string{"vk.com", "zt-masque.cloudflareclient.com"}, "", false); err == nil ||
		!strings.Contains(err.Error(), "cloudflareclient.com") {
		t.Fatalf("cloudflareclient SNI accepted: %v", err)
	}
	if got, err := BuildSNIOrder([]string{"consumer-masque.cloudflareclient.com"}, "", true); err != nil || got[0] != "consumer-masque.cloudflareclient.com" {
		t.Fatalf("override did not allow the name: %v %v", got, err)
	}
	for _, bad := range []string{"162.159.198.2", "[2606:4700::1]", "bad host", "a..b", "ex_ample.com/x"} {
		if _, err := BuildSNIOrder([]string{bad}, "", false); err == nil {
			t.Errorf("invalid SNI %q accepted", bad)
		}
	}

	path := filepath.Join(t.TempDir(), "sni.txt")
	content := "\ufeff# version: 1\nyastatic.net\n\n  VK.com  # duplicate after --sni\ncdn.jsdelivr.net\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = BuildSNIOrder([]string{"vk.com"}, path, false)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"vk.com", "yastatic.net", "cdn.jsdelivr.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged order = %v, want %v", got, want)
	}

	cfFile := filepath.Join(t.TempDir(), "cf.txt")
	if err := os.WriteFile(cfFile, []byte("www.google.com\nzt-masque.cloudflareclient.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSNIOrder(nil, cfFile, false); err == nil {
		t.Fatal("cloudflareclient SNI from a file accepted")
	}
}

func TestNewTLSConfigRefusesCloudflareSNI(t *testing.T) {
	c := testCrypto(t)
	if _, err := NewTLSConfig(c, "zt-masque.cloudflareclient.com", false); err == nil {
		t.Fatal("TLS config built with a cloudflareclient.com SNI")
	}
	cfg, err := NewTLSConfig(c, "WWW.Google.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "www.google.com" || !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate == nil {
		t.Fatalf("unexpected TLS config: server=%q insecure=%v verify=%v", cfg.ServerName, cfg.InsecureSkipVerify, cfg.VerifyPeerCertificate != nil)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h3" {
		t.Fatalf("ALPN = %v", cfg.NextProtos)
	}
}
