package masque

// Port of Nova Android nova-core/engine/masque.go:79-107 (MasqueIdentity) and :719-947
// (parse, build, endpoint/port normalization). The on-disk key set is Android's
// `masque_config.json` verbatim, so an Android export imports as is and a PC file loads on
// Android; PC metadata lives under one "nova" object (and-masque.md §3.3).

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	usquemodels "github.com/Diniboy1123/usque/models"
)

// DefaultPorts is the PC port order (and-masque.md §4.1): 443 first because only 443 also gets
// the HTTP/2 attempt, 8095 last because of the rx=0 note. Android measured a different order on
// one phone; which ports answer shifts by the minute (N10), so the order is a recommendation.
var DefaultPorts = []int{443, 8443, 4443, 500, 1701, 4500, 8095}

// Known sibling addresses of the MASQUE service: an identity enrolled on one also works on the
// other (masque.go:934-947). Scanned addresses never work because the endpoint key is pinned (N16).
var (
	knownSiblingsV4 = []string{"162.159.198.1", "162.159.198.2"}
	knownSiblingsV6 = []string{"2606:4700:103::1", "2606:4700:103::2"}
)

// Identity is one MASQUE profile file.
type Identity struct {
	PrivateKey           string   `json:"private_key"`
	EndpointV4           string   `json:"endpoint_v4,omitempty"`
	EndpointV6           string   `json:"endpoint_v6,omitempty"`
	EndpointV4Candidates []string `json:"endpoint_v4_candidates,omitempty"`
	EndpointV6Candidates []string `json:"endpoint_v6_candidates,omitempty"`
	EndpointPubKey       string   `json:"endpoint_pub_key"`
	// EndpointHost is Cloudflare's name for the node (engage.cloudflareclient.com:2408). Audit only:
	// it must never be dialled, MASQUE dials IPs.
	EndpointHost string `json:"endpoint_host,omitempty"`
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
	Ports        []int  `json:"ports,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	License      string `json:"license,omitempty"`
	// IssuedAt is the unix time the current key was enrolled. Nova's fresh-window rule
	// (access_denied on a key younger than 5 min -> activate, older -> re-enroll) reads it.
	IssuedAt     int64  `json:"issued_at,omitempty"`
	LastEndpoint string `json:"last_endpoint,omitempty"`
	LastPort     int    `json:"last_port,omitempty"`
	// Nova is the PC metadata object, kept verbatim on rewrite.
	Nova json.RawMessage `json:"nova,omitempty"`
}

// NovaMeta is the content of the "nova" object written by `register`.
type NovaMeta struct {
	Schema      int    `json:"schema"`
	Name        string `json:"name,omitempty"`
	CreatedBy   string `json:"created_by,omitempty"`
	Source      string `json:"source,omitempty"`
	AccountType string `json:"account_type,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
}

// identityKeys are the top-level keys owned by Identity; anything else in a file is preserved.
var identityKeys = map[string]bool{
	"private_key": true, "endpoint_v4": true, "endpoint_v6": true, "endpoint_v4_candidates": true,
	"endpoint_v6_candidates": true, "endpoint_pub_key": true, "endpoint_host": true, "ipv4": true,
	"ipv6": true, "ports": true, "access_token": true, "device_id": true, "license": true,
	"issued_at": true, "last_endpoint": true, "last_port": true, "nova": true,
	// usque's name for device_id; folded into device_id on parse, never written back.
	"id": true,
}

// ParseIdentity decodes and normalizes a profile in Android or usque shape and validates it with
// Android's rules (parseMasqueIdentity): private key, endpoint public key, at least one endpoint and
// at least one tunnel address.
func ParseIdentity(raw []byte) (Identity, error) {
	raw = profileText(raw)
	if len(bytes.TrimSpace(raw)) == 0 {
		return Identity{}, errors.New("profile is empty")
	}
	var doc struct {
		Identity
		ID string `json:"id"` // usque config.json
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Identity{}, fmt.Errorf("profile is not valid JSON: %w", err)
	}
	id := doc.Identity
	if strings.TrimSpace(id.DeviceID) == "" {
		id.DeviceID = doc.ID
	}
	id.normalize()
	if err := id.Validate(); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// profileText strips a UTF-8 byte order mark and decodes UTF-16 with a byte order mark (Notepad's
// "Unicode"), as Nova's profile listing reads the same file (nova_profiles._decode_bytes): a
// profile the UI shows as valid must not fail here with exit 3. Other bytes pass through unchanged.
func profileText(raw []byte) []byte {
	switch {
	case bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}):
		return raw[3:]
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}):
		return decodeUTF16(raw[2:], binary.LittleEndian)
	case bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		return decodeUTF16(raw[2:], binary.BigEndian)
	}
	return raw
}

// decodeUTF16 converts UTF-16 code units to UTF-8; an odd trailing byte is dropped and a broken
// surrogate becomes U+FFFD, which JSON parsing then reports if it matters.
func decodeUTF16(b []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = order.Uint16(b[2*i:])
	}
	return []byte(string(utf16.Decode(units)))
}

// LoadIdentityFile reads and parses a profile file.
func LoadIdentityFile(path string) (Identity, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, nil, fmt.Errorf("read profile: %w", err)
	}
	id, err := ParseIdentity(raw)
	if err != nil {
		return Identity{}, raw, err
	}
	return id, raw, nil
}

func (id *Identity) normalize() {
	id.PrivateKey = strings.TrimSpace(id.PrivateKey)
	id.AccessToken = strings.TrimSpace(id.AccessToken)
	id.DeviceID = strings.TrimSpace(id.DeviceID)
	id.License = strings.TrimSpace(id.License)
	id.EndpointHost = strings.TrimSpace(id.EndpointHost)
	id.IPv4 = normalizeTunnelAddress(id.IPv4)
	id.IPv6 = normalizeTunnelAddress(id.IPv6)
	id.EndpointV4Candidates = normalizeEndpointCandidates(NormalizeEndpointHost(id.EndpointV4), id.EndpointV4Candidates, true)
	id.EndpointV6Candidates = normalizeEndpointCandidates(NormalizeEndpointHost(id.EndpointV6), id.EndpointV6Candidates, false)
	// The endpoint must be an IP of the right family (masque.go:982-985): a name here would never be
	// dialled, so it is dropped rather than carried as a "valid" endpoint Android would accept.
	id.EndpointV4, id.EndpointV6 = "", ""
	if len(id.EndpointV4Candidates) > 0 {
		id.EndpointV4 = id.EndpointV4Candidates[0]
	}
	if len(id.EndpointV6Candidates) > 0 {
		id.EndpointV6 = id.EndpointV6Candidates[0]
	}
	id.Ports = NormalizePorts(id.Ports)
}

// Validate applies Android's validity rules plus the checks the dial needs anyway.
func (id Identity) Validate() error {
	var problems []string
	if id.PrivateKey == "" {
		problems = append(problems, "private_key is missing")
	}
	if strings.TrimSpace(id.EndpointPubKey) == "" {
		problems = append(problems, "endpoint_pub_key is missing")
	}
	if id.EndpointV4 == "" && id.EndpointV6 == "" {
		problems = append(problems, "no IP endpoint (endpoint_v4/endpoint_v6)")
	}
	if id.IPv4 == "" && id.IPv6 == "" {
		problems = append(problems, "no tunnel address (ipv4/ipv6)")
	}
	if id.IPv4 != "" {
		if a, err := netip.ParseAddr(id.IPv4); err != nil || !a.Is4() {
			problems = append(problems, fmt.Sprintf("ipv4 %q is not an IPv4 address", id.IPv4))
		}
	}
	if id.IPv6 != "" {
		if a, err := netip.ParseAddr(id.IPv6); err != nil || !a.Is6() || a.Is4In6() {
			problems = append(problems, fmt.Sprintf("ipv6 %q is not an IPv6 address", id.IPv6))
		}
	}
	if len(problems) > 0 {
		return errors.New("invalid MASQUE profile: " + strings.Join(problems, "; "))
	}
	return nil
}

// NormalizeEndpointHost strips a port and brackets from an endpoint (masque.go:857-883):
// "162.159.198.2:0" -> "162.159.198.2", "[2606:4700:103::2]:0" -> "2606:4700:103::2".
func NormalizeEndpointHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "[") && strings.Contains(value, "]") {
		end := strings.Index(value, "]")
		return strings.TrimSpace(value[1:end])
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	if ip := net.ParseIP(value); ip != nil {
		return value
	}
	if idx := strings.LastIndex(value, ":"); idx > 0 && strings.Count(value, ":") == 1 {
		if _, err := strconv.Atoi(value[idx+1:]); err == nil {
			return strings.TrimSpace(value[:idx])
		}
	}
	return strings.Trim(value, "[]")
}

// normalizeTunnelAddress accepts "172.16.0.2" and tolerates "172.16.0.2/32".
func normalizeTunnelAddress(raw string) string {
	value := strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().String()
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.String()
	}
	return value
}

// NormalizePorts keeps valid file ports in order, then appends DefaultPorts (masque.go:885-896).
func NormalizePorts(ports []int) []int {
	out := make([]int, 0, len(ports)+len(DefaultPorts))
	seen := make(map[int]bool)
	add := func(p int) {
		if p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range ports {
		add(p)
	}
	for _, p := range DefaultPorts {
		add(p)
	}
	return out
}

// portsDefaultFirst is used for freshly registered profiles: the PC order first, then any extra
// port the server advertised.
func portsDefaultFirst(serverPorts []int) []int {
	return NormalizePorts(append(append([]int(nil), DefaultPorts...), serverPorts...))
}

func normalizeEndpointCandidates(primary string, candidates []string, ipv4 bool) []string {
	ordered := make([]string, 0, len(candidates)+3)
	seen := make(map[string]bool)
	add := func(value string) {
		normalized := NormalizeEndpointHost(value)
		if normalized == "" {
			return
		}
		addr, err := netip.ParseAddr(normalized)
		if err != nil {
			return
		}
		addr = addr.Unmap()
		if ipv4 != addr.Is4() {
			return
		}
		text := addr.String()
		if seen[text] {
			return
		}
		seen[text] = true
		ordered = append(ordered, text)
	}
	add(primary)
	for _, c := range candidates {
		add(c)
	}
	for _, sibling := range knownSiblings(ordered, ipv4) {
		add(sibling)
	}
	return ordered
}

func knownSiblings(candidates []string, ipv4 bool) []string {
	pool := knownSiblingsV6
	if ipv4 {
		pool = knownSiblingsV4
	}
	for _, c := range candidates {
		for _, known := range pool {
			if c == known {
				return pool
			}
		}
	}
	return nil
}

// BuildIdentity turns an enroll/GET device record into a profile (masque.go:754-782).
func BuildIdentity(account usquemodels.AccountData, privateKeyDER []byte, accessToken string, issuedAt time.Time) (Identity, error) {
	if len(account.Config.Peers) == 0 {
		return Identity{}, errors.New("device record has no peers")
	}
	peer := account.Config.Peers[0]
	id := Identity{
		PrivateKey:     base64.StdEncoding.EncodeToString(privateKeyDER),
		EndpointV4:     peer.Endpoint.V4,
		EndpointV6:     peer.Endpoint.V6,
		EndpointPubKey: peer.PublicKey,
		EndpointHost:   peer.Endpoint.Host,
		IPv4:           account.Config.Interface.Addresses.V4,
		IPv6:           account.Config.Interface.Addresses.V6,
		Ports:          portsDefaultFirst(peer.Endpoint.Ports),
		AccessToken:    accessToken,
		DeviceID:       account.ID,
		License:        account.Account.License,
		IssuedAt:       issuedAt.Unix(),
	}
	id.normalize()
	if err := id.Validate(); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// MarshalDocument renders a profile as indented JSON: the Identity keys in their documented order,
// then the unknown top-level keys of the previous file (sorted), so a rewrite never drops fields a
// newer Android or Nova version added.
func MarshalDocument(id Identity, previous []byte) ([]byte, error) {
	compact, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	var extras map[string]json.RawMessage
	previous = profileText(previous)
	if len(bytes.TrimSpace(previous)) > 0 {
		if err := json.Unmarshal(previous, &extras); err != nil {
			extras = nil // an unparseable previous file has nothing worth preserving
		}
	}
	keys := make([]string, 0, len(extras))
	for k := range extras {
		if !identityKeys[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		var b bytes.Buffer
		b.Write(compact[:len(compact)-1]) // drop the closing brace
		for _, k := range keys {
			name, _ := json.Marshal(k)
			b.WriteByte(',')
			b.Write(name)
			b.WriteByte(':')
			b.Write(extras[k])
		}
		b.WriteByte('}')
		compact = b.Bytes()
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// DeviceIDPrefix is the log-safe form of a device id.
func DeviceIDPrefix(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if len(deviceID) > 8 {
		return deviceID[:8]
	}
	return deviceID
}
