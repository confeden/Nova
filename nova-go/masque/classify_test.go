package masque

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassifyErrorSignatures(t *testing.T) {
	cases := []struct {
		stage, transport, msg, want string
	}{
		{StageDial, transportH3, "CRYPTO_ERROR 0x131 (remote): tls: access denied", ClassAccessDenied},
		{StageSettings, transportH3, "connection closed before HTTP/3 SETTINGS: CRYPTO_ERROR 0x131 (remote)", ClassAccessDenied},
		{StageConnectIP, transportH2, "connect-ip: failed to send request: remote error: tls: access denied", ClassAccessDenied},
		{StageDial, transportH3, "CRYPTO_ERROR 0x12a (local): x509: remote endpoint has a different public key than what we trust in config.json", ClassPubkeyMismatch},
		{StageDial, transportH3, "CRYPTO_ERROR 0x128 (remote): tls: handshake failure", ClassPubkeyMismatch},
		{StageDial, transportH3, "PROTOCOL_VIOLATION (remote): connection ID length", ClassProtocolViolation},
		{StageDial, transportH3, "timeout: no recent network activity", ClassQUICTimeout},
		{StageDial, transportH2, "tcp dial: i/o timeout", ClassH2TLS},
		{StageTLS, transportH2, "tls handshake: EOF", ClassH2TLS},
		{StageSettings, transportH3, "server accepted QUIC but sent no HTTP/3 SETTINGS within 4.5s", ClassSettingsTimeout},
		{StageConnectIP, transportH3, "connect-ip: server responded with 403", ClassConnectIPStatus},
		{StageConnectIP, transportH3, errConnectIPNoAnswer.Error(), ClassConnectIPTimeout},
		{StageProbe, transportH3, "no packet came back", ClassZeroRx},
		{StageSession, transportH3, "use of closed network connection", ClassClosed},
	}
	for _, c := range cases {
		if got := classifyError(c.stage, c.transport, errors.New(c.msg)); got != c.want {
			t.Errorf("classify(%s,%s,%q) = %s, want %s", c.stage, c.transport, c.msg, got, c.want)
		}
	}
	if classifyError(StageDial, transportH3, nil) != "" {
		t.Error("nil error classified")
	}
	wrapped := fmt.Errorf("failed to dial: %w", errors.New("tls: access denied"))
	if classifyError(StageDial, transportH3, wrapped) != ClassAccessDenied {
		t.Error("wrapped signature missed")
	}
}

func TestTallyExitCodePriority(t *testing.T) {
	type expect struct {
		code  int
		class string
	}
	cases := []struct {
		name    string
		classes []string
		want    expect
	}{
		{"nothing reached CONNECT-IP", []string{ClassQUICTimeout, ClassSettingsTimeout, ClassH2TLS}, expect{ExitNoResponse, ClassH2TLS}},
		{"empty walk", nil, expect{ExitNoResponse, ClassQUICTimeout}},
		{"only pubkey mismatch", []string{ClassPubkeyMismatch, ClassPubkeyMismatch}, expect{ExitPubkeyMismatch, ClassPubkeyMismatch}},
		{"mismatch beats timeouts", []string{ClassQUICTimeout, ClassPubkeyMismatch, ClassQUICTimeout}, expect{ExitPubkeyMismatch, ClassPubkeyMismatch}},
		{"access denied beats mismatch", []string{ClassPubkeyMismatch, ClassAccessDenied, ClassQUICTimeout}, expect{ExitAccessDenied, ClassAccessDenied}},
		{"zero rx beats everything", []string{ClassAccessDenied, ClassPubkeyMismatch, ClassZeroRx, ClassQUICTimeout}, expect{ExitZeroRx, ClassZeroRx}},
		{"status without better evidence", []string{ClassConnectIPStatus, ClassQUICTimeout}, expect{ExitNoResponse, ClassQUICTimeout}},
	}
	for _, c := range cases {
		tl := newTally()
		for _, cl := range c.classes {
			tl.add(cl)
		}
		code, class := tl.exit()
		if code != c.want.code || class != c.want.class {
			t.Errorf("%s: exit = (%d, %s), want (%d, %s)", c.name, code, class, c.want.code, c.want.class)
		}
	}
	// The documented numbers are a contract with nova.pyw.
	if ExitNoResponse != 10 || ExitAccessDenied != 11 || ExitPubkeyMismatch != 12 || ExitZeroRx != 13 ||
		ExitAPIUnreachable != 20 || ExitAPIStatus != 21 || ExitNoPeers != 22 || ExitLocked != 23 ||
		ExitUsage != 2 || ExitConfig != 3 || ExitBind != 4 {
		t.Fatal("exit code constants drifted from and-masque.md §8.5")
	}
}
