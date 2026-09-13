package warp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Registration is the subset of a POST /reg answer that a WireGuard profile needs. Field names follow
// WarpClient.kt parseRegistrationResponse; the Python side re-parses the raw JSON on its own.
type Registration struct {
	ID            string
	Token         string
	AccountType   string
	License       string
	WarpEnabled   bool
	PeerPublicKey string
	EndpointV4    string
	EndpointV6    string
	EndpointHost  string
	AddressV4     string
	AddressV6     string
	ClientID      string
	Reserved      []byte   // first 3 bytes of the decoded client_id, nil when it has fewer
	Peers         int      // number of peers in config.peers
	Keys          []string // top-level keys of the (unwrapped) object, sorted
	Wrapped       bool     // the object came inside {"result": ...}
}

type registrationWire struct {
	ID          string `json:"id"`
	Token       string `json:"token"`
	WarpEnabled any    `json:"warp_enabled"`
	Account     *struct {
		AccountType string `json:"account_type"`
		License     string `json:"license"`
	} `json:"account"`
	Config *struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  *struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface *struct {
			Addresses *struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// ParseRegistration accepts both the bare device object and the {"result": {...}} wrapper. It fails
// when the body is not a JSON object, or lacks what a tunnel cannot do without: a 32-byte peer public
// key and an IPv4 interface address.
func ParseRegistration(body []byte) (*Registration, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("registration response is not a JSON object: %w", err)
	}
	if top == nil {
		return nil, errors.New("registration response is null")
	}
	out := &Registration{}
	objectRaw := json.RawMessage(body)
	if inner, ok := top["result"]; ok && strings.HasPrefix(strings.TrimSpace(string(inner)), "{") {
		objectRaw = inner
		out.Wrapped = true
		top = nil
		if err := json.Unmarshal(inner, &top); err != nil {
			return nil, fmt.Errorf("registration result is not a JSON object: %w", err)
		}
	}
	for key := range top {
		out.Keys = append(out.Keys, key)
	}
	slices.Sort(out.Keys)

	var wire registrationWire
	if err := json.Unmarshal(objectRaw, &wire); err != nil {
		return nil, fmt.Errorf("registration response has unexpected field types: %w", err)
	}
	out.ID = strings.TrimSpace(wire.ID)
	out.Token = strings.TrimSpace(wire.Token)
	if enabled, ok := wire.WarpEnabled.(bool); ok {
		out.WarpEnabled = enabled
	}
	if wire.Account != nil {
		out.AccountType = strings.TrimSpace(wire.Account.AccountType)
		out.License = strings.TrimSpace(wire.Account.License)
	}
	if wire.Config == nil {
		return nil, errors.New("registration response has no config")
	}
	out.ClientID = strings.TrimSpace(wire.Config.ClientID)
	out.Peers = len(wire.Config.Peers)
	if out.Peers == 0 {
		return nil, errors.New("registration response has no peers")
	}
	peer := wire.Config.Peers[0]
	out.PeerPublicKey = strings.TrimSpace(peer.PublicKey)
	if peer.Endpoint != nil {
		out.EndpointV4 = strings.TrimSpace(peer.Endpoint.V4)
		out.EndpointV6 = strings.TrimSpace(peer.Endpoint.V6)
		out.EndpointHost = strings.TrimSpace(peer.Endpoint.Host)
	}
	if wire.Config.Interface != nil && wire.Config.Interface.Addresses != nil {
		out.AddressV4 = strings.TrimSpace(wire.Config.Interface.Addresses.V4)
		out.AddressV6 = strings.TrimSpace(wire.Config.Interface.Addresses.V6)
	}
	if _, err := DecodeKey(out.PeerPublicKey); err != nil {
		return nil, fmt.Errorf("registration peer public key: %w", err)
	}
	if out.AddressV4 == "" {
		return nil, errors.New("registration response has no IPv4 interface address")
	}
	out.Reserved = decodeReserved(out.ClientID)
	return out, nil
}

// decodeReserved turns client_id into the three WireGuard reserved bytes. Anything shorter yields
// nil: writing 0,0,0 blindly is wrong (negative knowledge N3).
func decodeReserved(clientID string) []byte {
	if clientID == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clientID, "="))
		if err != nil {
			return nil
		}
	}
	if len(raw) < 3 {
		return nil
	}
	return raw[:3]
}

// ReservedCSV is "a,b,c" or "" when client_id did not decode to three bytes.
func (r *Registration) ReservedCSV() string {
	if len(r.Reserved) < 3 {
		return ""
	}
	return fmt.Sprintf("%d,%d,%d", r.Reserved[0], r.Reserved[1], r.Reserved[2])
}

// Summary is a log-safe description: which fields are present, secrets as lengths only.
func (r *Registration) Summary() string {
	size := func(s string) string {
		if s == "" {
			return "absent"
		}
		return fmt.Sprintf("<%d chars>", len(s))
	}
	yes := func(s string) string {
		if s == "" {
			return "no"
		}
		return "yes"
	}
	accountType := r.AccountType
	if accountType == "" {
		accountType = "absent"
	}
	return fmt.Sprintf(
		"wrapped=%t keys=[%s] id=%s token=%s account_type=%s license=%s warp_enabled=%t peers=%d peer_public_key=%s endpoint_v4=%s endpoint_v6=%s endpoint_host=%s address_v4=%s address_v6=%s client_id=%s reserved=%s",
		r.Wrapped, strings.Join(r.Keys, ","), size(r.ID), size(r.Token), accountType, size(r.License),
		r.WarpEnabled, r.Peers, size(r.PeerPublicKey), yes(r.EndpointV4), yes(r.EndpointV6),
		yes(r.EndpointHost), yes(r.AddressV4), yes(r.AddressV6), size(r.ClientID), yes(r.ReservedCSV()),
	)
}
