package masque

import (
	"errors"
	"strings"
)

// Fail classes of the event protocol (and-masque.md §8.4).
const (
	ClassAccessDenied      = "access_denied"
	ClassPubkeyMismatch    = "pubkey_mismatch"
	ClassQUICTimeout       = "quic_timeout"
	ClassProtocolViolation = "protocol_violation"
	ClassSettingsTimeout   = "settings_timeout"
	ClassConnectIPTimeout  = "connectip_timeout"
	ClassConnectIPStatus   = "connectip_status"
	ClassH2TLS             = "h2_tls"
	ClassZeroRx            = "zero_rx"
	ClassStall             = "stall"
	ClassClosed            = "closed"
	ClassBind              = "bind"
	ClassConfig            = "config"
)

// Exit codes (and-masque.md §8.5).
const (
	ExitOK             = 0
	ExitInternal       = 1
	ExitUsage          = 2
	ExitConfig         = 3
	ExitBind           = 4
	ExitNoResponse     = 10
	ExitAccessDenied   = 11
	ExitPubkeyMismatch = 12
	ExitZeroRx         = 13
	ExitAPIUnreachable = 20
	ExitAPIStatus      = 21
	ExitNoPeers        = 22
	ExitLocked         = 23
)

// Dial stages used in fail events.
const (
	StageDial      = "dial"
	StageTLS       = "tls"
	StageSettings  = "settings"
	StageConnectIP = "connectip"
	StageProbe     = "probe"
	StageSession   = "session"
)

// errConnectIPNoAnswer marks a CONNECT-IP request the server accepted but never answered.
var errConnectIPNoAnswer = errors.New("server accepted the CONNECT-IP request but did not answer")

// classifyError maps an attempt error to a fail class using the signatures of and-masque.md §4.7.
// Signatures in the text win over the stage: an access denial can surface while waiting for
// SETTINGS (TLS 1.3 validates the client certificate after the client's handshake is done).
func classifyError(stage, transport string, err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "access denied") || strings.Contains(msg, "0x131"):
		return ClassAccessDenied
	case strings.Contains(msg, "different public key") || strings.Contains(msg, "0x128") ||
		strings.Contains(msg, "presented no certificate"):
		return ClassPubkeyMismatch
	case strings.Contains(msg, "protocol_violation"):
		return ClassProtocolViolation
	}
	switch stage {
	case StageSettings:
		return ClassSettingsTimeout
	case StageConnectIP:
		if strings.Contains(msg, "server responded with") {
			return ClassConnectIPStatus
		}
		return ClassConnectIPTimeout
	case StageProbe:
		return ClassZeroRx
	case StageSession:
		return ClassClosed
	}
	if transport == "h2" {
		return ClassH2TLS
	}
	return ClassQUICTimeout
}

// tally counts fail classes of one matrix walk and picks the exit code.
type tally struct {
	counts   map[string]int
	attempts int
	last     string
}

func newTally() *tally { return &tally{counts: make(map[string]int)} }

func (t *tally) add(class string) {
	if class == "" {
		return
	}
	t.counts[class]++
	t.last = class
}

// exit picks the most specific code. Priority 13 > 11 > 12 > 10: evidence of a working key (the
// server opened CONNECT-IP) outranks an authorization failure, which outranks a wrong endpoint,
// which outranks network silence.
func (t *tally) exit() (int, string) {
	switch {
	case t.counts[ClassZeroRx] > 0:
		return ExitZeroRx, ClassZeroRx
	case t.counts[ClassAccessDenied] > 0:
		return ExitAccessDenied, ClassAccessDenied
	case t.counts[ClassPubkeyMismatch] > 0:
		return ExitPubkeyMismatch, ClassPubkeyMismatch
	}
	class := t.last
	if class == "" {
		class = ClassQUICTimeout
	}
	return ExitNoResponse, class
}
