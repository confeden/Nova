package masque

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// NeutralSNIPool is Android's MASQUE_NEUTRAL_SNI_POOL (NovaVpnService.kt:1331-1338), the order used
// when the caller gives no --sni. Measured good on 162.159.198.2:443/:8443 (2026-08-15):
// 4pda.to, www.google.com, static.twitchcdn.net, vk.com.
var NeutralSNIPool = []string{
	"www.google.com",
	"static.twitchcdn.net",
	"4pda.to",
	"vk.com",
	"cdn.jsdelivr.net",
	"www.microsoft.com",
}

// cloudflareClientSuffix is the name DPI blocks: what actually fixed MASQUE on Android was never
// sending it in the ClientHello (and-masque.md §0.1, §4.6). QUIC does not hide the SNI.
const cloudflareClientSuffix = "cloudflareclient.com"

// IsCloudflareClientSNI reports whether host is cloudflareclient.com or any subdomain of it
// (case-insensitive, trailing dot ignored).
func IsCloudflareClientSNI(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return h == cloudflareClientSuffix || strings.HasSuffix(h, "."+cloudflareClientSuffix)
}

// NormalizeSNI lowercases and validates a TLS server name. IP literals are refused: TLS does not
// carry them in SNI, so the handshake would go out without a name at all.
func NormalizeSNI(host string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return "", errors.New("empty SNI")
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return "", fmt.Errorf("SNI %q is an IP address", host)
	}
	if len(h) > 253 {
		return "", fmt.Errorf("SNI %q is too long", host)
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("SNI %q has an empty or oversized label", host)
		}
		for _, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				return "", fmt.Errorf("SNI %q has an invalid character %q", host, r)
			}
		}
	}
	return h, nil
}

// BuildSNIOrder merges --sni values and --sni-file lines (in that order, duplicates removed).
// Empty input yields NeutralSNIPool. A cloudflareclient.com name is an error unless allowCF.
func BuildSNIOrder(flagValues []string, sniFile string, allowCF bool) ([]string, error) {
	var raw []string
	raw = append(raw, flagValues...)
	if strings.TrimSpace(sniFile) != "" {
		lines, err := ReadSNIFile(sniFile)
		if err != nil {
			return nil, err
		}
		raw = append(raw, lines...)
	}
	if len(raw) == 0 {
		raw = append(raw, NeutralSNIPool...)
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool)
	for _, value := range raw {
		name, err := NormalizeSNI(value)
		if err != nil {
			return nil, err
		}
		if IsCloudflareClientSNI(name) && !allowCF {
			return nil, fmt.Errorf("SNI %q is a cloudflareclient.com name; DPI blocks it (pass --allow-cloudflare-sni to override)", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// ReadSNIFile reads one host per line; blank lines and `#` comments are skipped.
func ReadSNIFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SNI file: %w", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read SNI file: %w", err)
	}
	return out, nil
}
