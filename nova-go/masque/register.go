package masque

// `nova-go masque register` and `nova-go masque enroll`.
//
// Lessons carried over from Android (and-masque.md §2.4), all real bugs there:
//   - the server keeps only the LAST key: two enrolls in one cycle kill the first saved key;
//   - a caller timeout does not cancel the PATCH, so a key can be rotated server-side and lost
//     client-side. Android kept an in-memory memo; here the private key is written to
//     `<profile>.pending` BEFORE the PATCH, which also survives a killed process;
//   - a cross-process LockFileEx on `<profile>.lock` makes the operation single-flight;
//   - a fresh registration answers warp_enabled:false and the service then refuses the client
//     certificate with "tls: access denied": activate with {"warp_enabled":true} and check the flag;
//   - an enroll answer without peers is not a failure (the key is already rotated): GET the record.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	usquemodels "github.com/Diniboy1123/usque/models"

	"nova-pc/nova-go/internal/events"
)

// pendingKey is the content of `<profile>.pending`.
type pendingKey struct {
	PrivateKey  string `json:"private_key"`
	DeviceID    string `json:"device_id"`
	AccessToken string `json:"access_token"`
	IssuedAt    int64  `json:"issued_at"`
	License     string `json:"license,omitempty"`
	// Source says which flow wrote it: "register" (device created by this helper) or "enroll".
	Source string `json:"source,omitempty"`
}

func readPending(path string) (*pendingKey, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pending key: %w", err)
	}
	var p pendingKey
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("pending key file is corrupt: %w", err)
	}
	if p.PrivateKey == "" || p.DeviceID == "" || p.AccessToken == "" {
		return nil, errors.New("pending key file misses private_key/device_id/access_token")
	}
	if _, err := PublicKeyB64FromPrivate(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("pending key file: %w", err)
	}
	return &p, nil
}

func writePending(path string, p pendingKey) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// setAsidePending renames a pending file that can no longer be used, instead of deleting a
// private key: `<profile>.pending.<unix>.bak` (ignored by Nova's profile listing).
func setAsidePending(path string, log *Logger) {
	target := fmt.Sprintf("%s.%d.bak", path, time.Now().Unix())
	if err := os.Rename(path, target); err != nil {
		log.Error("cannot set the stale pending key aside", "path", path, "err", err)
		return
	}
	log.Warn("stale pending key set aside", "path", target)
}

type apiOptions struct {
	mode    string
	proxy   string
	timeout time.Duration
}

// apiProxyEnv adds API proxies without putting them on the command line, where other local processes
// can read them: Nova passes relay URLs with credentials here (INTEGRATION.md §10), the same variable
// the WARP helper reads.
const apiProxyEnv = "NOVA_API_PROXY"

func (a *apiOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&a.mode, "api-mode", APIModeAuto, "auto|proxy|direct|plain")
	fs.StringVar(&a.proxy, "api-proxy", "", "HTTP proxy for the Cloudflare API, e.g. http://127.0.0.1:1371 (env "+apiProxyEnv+" adds more, tried after it)")
	fs.DurationVar(&a.timeout, "timeout", 90*time.Second, "whole operation")
}

// apiProxyList is --api-proxy first, then the URLs of NOVA_API_PROXY separated by whitespace, commas
// or semicolons (Nova percent-encodes relay credentials, so none of those occur inside a URL).
func apiProxyList(flagValue, envValue string) []string {
	var out []string
	if v := strings.TrimSpace(flagValue); v != "" {
		out = append(out, v)
	}
	return append(out, strings.FieldsFunc(envValue, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';'
	})...)
}

// apiClientHook adjusts every API client right after creation; tests point it at a local server.
var apiClientHook func(*APIClient)

func (a *apiOptions) newClient(log *Logger) (*APIClient, error) {
	c, err := newAPIClient(a.mode, apiProxyList(a.proxy, os.Getenv(apiProxyEnv)), log)
	if err != nil {
		return nil, err
	}
	if len(c.proxies) > 0 {
		log.Info("API proxies", "count", len(c.proxies), "proxies", c.proxyLabel())
	}
	if apiClientHook != nil {
		apiClientHook(c)
	}
	return c, nil
}

// relayFields tell Nova that a relay refused this version, so it can say «обновите Nova».
func relayFields(c *APIClient) []events.Field {
	outdated, current := c.relayState()
	if !outdated {
		return nil
	}
	fields := []events.Field{events.F("relay_outdated", true)}
	if current != "" {
		fields = append(fields, events.F("relay_current", current))
	}
	return fields
}

// flowError carries the exit code of a failed register/enroll step.
type flowError struct {
	code  int
	class string
	err   error
}

func (e *flowError) Error() string { return e.err.Error() }
func (e *flowError) Unwrap() error { return e.err }

// apiFailure maps an API call error to its exit code: an HTTP answer is 21, no answer is 20.
func apiFailure(step string, err error) *flowError {
	var se *apiStatusError
	if errors.As(err, &se) {
		return &flowError{code: ExitAPIStatus, class: "api_status", err: fmt.Errorf("%s: %w", step, err)}
	}
	if errors.Is(err, ErrAPIUnreachable) || errors.Is(err, context.DeadlineExceeded) {
		return &flowError{code: ExitAPIUnreachable, class: "api_unreachable", err: fmt.Errorf("%s: %w", step, err)}
	}
	// A 200 with a body we cannot use is a server-side answer too.
	return &flowError{code: ExitAPIStatus, class: "api_status", err: fmt.Errorf("%s: %w", step, err)}
}

// enrollOutcome is the result of the key/activation/peers steps.
type enrollOutcome struct {
	account     usquemodels.AccountData
	warpEnabled bool
}

// completeEnrollment runs PATCH key (unless skipKey) -> activation -> GET when peers are missing.
func completeEnrollment(ctx context.Context, api *APIClient, log *Logger, deviceID, token string, publicDER []byte, name string, skipKey bool) (*enrollOutcome, *flowError) {
	var account usquemodels.AccountData
	if !skipKey {
		acc, resp, err := api.enrollKey(ctx, deviceID, token, publicDER, name)
		if err != nil {
			return nil, apiFailure("enroll key", err)
		}
		logDeviceShape(log, "enroll", resp.Body)
		account = acc
		log.Info("MASQUE key enrolled", "device", DeviceIDPrefix(deviceID), "tunnel", account.TunType,
			"key_type", account.KeyType, "warp_enabled", account.WarpEnabled, "account", account.Account.AccountType,
			"peers", len(account.Config.Peers))
	}
	if skipKey || !account.WarpEnabled {
		activated, resp, err := api.activateWarp(ctx, deviceID, token)
		switch {
		case err != nil:
			// Not fatal here: the GET below shows the real state, and Nova's access_denied handling
			// runs `enroll --activate-only` later.
			log.Warn("WARP activation failed", "device", DeviceIDPrefix(deviceID), "err", err)
		default:
			logDeviceShape(log, "activate", resp.Body)
			log.Info("WARP activation answered", "warp_enabled", activated.WarpEnabled, "enabled", activated.Enabled)
			if activated.WarpEnabled && (len(activated.Config.Peers) > 0 || len(account.Config.Peers) == 0) {
				account = activated
			} else if activated.WarpEnabled {
				account.WarpEnabled = true
			}
		}
	}
	if len(account.Config.Peers) == 0 || !account.WarpEnabled {
		fetched, resp, err := api.fetchDevice(ctx, deviceID, token)
		if err != nil {
			if len(account.Config.Peers) == 0 {
				return nil, apiFailure("read device record", err)
			}
			log.Warn("device record re-read failed", "err", err)
		} else {
			logDeviceShape(log, "device", resp.Body)
			if len(fetched.Config.Peers) > 0 {
				account = fetched
			}
			if fetched.WarpEnabled {
				account.WarpEnabled = true
			}
		}
	}
	if len(account.Config.Peers) == 0 {
		return nil, &flowError{code: ExitNoPeers, class: "no_peers", err: errors.New("device record has no peers even after GET")}
	}
	if !account.WarpEnabled {
		log.Warn("device still reports warp_enabled=false; the MASQUE service may answer access denied")
	}
	return &enrollOutcome{account: account, warpEnabled: account.WarpEnabled}, nil
}

func runRegister(args []string, env *cliEnv) int {
	var (
		common    commonOptions
		api       apiOptions
		out       string
		acceptTOS bool
		force     bool
		name      string
		model     string
		locale    string
		license   string
		jwt       string
	)
	fs := flag.NewFlagSet("masque register", flag.ContinueOnError)
	common.register(fs)
	api.register(fs)
	fs.StringVar(&out, "out", "", "profile path to create, e.g. profiles\\MASQUE\\Cloudflare MASQUE 1.json")
	fs.BoolVar(&acceptTOS, "accept-tos", false, "accept the Cloudflare terms of service (required)")
	fs.BoolVar(&force, "force", false, "overwrite an existing profile")
	fs.StringVar(&name, "name", "Nova PC", "device name")
	fs.StringVar(&model, "model", "PC", "registration model")
	fs.StringVar(&locale, "locale", "en-US", "registration locale")
	fs.StringVar(&license, "license", "", "optional WARP+ license key")
	fs.StringVar(&jwt, "jwt", "", "Zero Trust team token (CF-Access-Jwt-Assertion)")
	if ok, code := env.parseFlags(fs, args); !ok {
		return code
	}
	log, em, cleanup, code := env.setup(common, "register")
	if code != 0 {
		return code
	}
	defer cleanup()

	var client *APIClient
	exit := func(fe *flowError) int {
		log.Error("register failed", "code", fe.code, "class", fe.class, "err", fe.err)
		return emitExit(em, fe.code, fe.class, 0, fe.err, relayFields(client)...)
	}
	usage := func(err error) int { return exit(&flowError{code: ExitUsage, class: "usage", err: err}) }
	if strings.TrimSpace(out) == "" {
		return usage(errors.New("--out is required"))
	}
	if !acceptTOS {
		return usage(errors.New("--accept-tos is required: registration accepts https://www.cloudflare.com/application/terms/"))
	}
	if api.timeout < 10*time.Second {
		return usage(errors.New("--timeout must be >= 10s"))
	}
	client, err := api.newClient(log)
	if err != nil {
		return usage(err)
	}
	if dir := filepath.Dir(out); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return exit(&flowError{code: ExitConfig, class: ClassConfig, err: fmt.Errorf("create profile directory: %w", err)})
		}
	}

	lock, err := lockProfile(out)
	if err != nil {
		if errors.Is(err, errLocked) {
			return exit(&flowError{code: ExitLocked, class: "locked", err: err})
		}
		return exit(&flowError{code: ExitConfig, class: ClassConfig, err: err})
	}
	defer lock.Unlock()

	if _, err := os.Stat(out); err == nil && !force {
		return usage(fmt.Errorf("%s exists (pass --force to replace it)", out))
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if code, stop := env.startStopWatch(ctx, cancel, common.parentPID, log); stop {
		return emitExit(em, code, stopClass(code), 0, nil)
	}
	tctx, tcancel := context.WithTimeout(ctx, api.timeout)
	defer tcancel()

	pendingPath := out + ".pending"
	pending, perr := readPending(pendingPath)
	if perr != nil {
		log.Error("pending key unusable", "err", perr)
		setAsidePending(pendingPath, log)
		pending = nil
	}

	var (
		privDER   []byte
		pubDER    []byte
		deviceID  string
		token     string
		issuedAt  time.Time
		source    = "register"
		skipPatch bool
	)
	if pending != nil {
		// Recovery: a previous run wrote the key and may or may not have sent the PATCH.
		log.Info("recovering a pending registration", "device", DeviceIDPrefix(pending.DeviceID))
		record, _, err := client.fetchDevice(tctx, pending.DeviceID, pending.AccessToken)
		var se *apiStatusError
		switch {
		case err == nil:
			pubB64, _ := PublicKeyB64FromPrivate(pending.PrivateKey)
			privDER, _ = decodeB64(pending.PrivateKey)
			pubDER, _ = decodeB64(pubB64)
			deviceID, token = pending.DeviceID, pending.AccessToken
			issuedAt = time.Unix(pending.IssuedAt, 0)
			if strings.TrimSpace(record.Key) == pubB64 {
				log.Info("the server already holds the pending key; promoting it")
				skipPatch = true
			} else {
				log.Info("the pending key never reached the server; enrolling it now")
				issuedAt = time.Now()
			}
		case errors.As(err, &se) && (se.Code == 401 || se.Code == 403 || se.Code == 404):
			log.Warn("the pending device is gone or its token is refused; starting over", "status", se.Status)
			setAsidePending(pendingPath, log)
		default:
			return exit(apiFailure("read pending device", err))
		}
	}
	if deviceID == "" {
		account, resp, err := client.registerDevice(tctx, model, locale, jwt)
		if err != nil {
			return exit(apiFailure("register device", err))
		}
		logDeviceShape(log, "register", resp.Body)
		deviceID, token = strings.TrimSpace(account.ID), strings.TrimSpace(account.Token)
		log.Info("device registered", "device", DeviceIDPrefix(deviceID), "account", account.Account.AccountType, "via", resp.Via)
		if privDER, pubDER, err = GenerateKeyPair(); err != nil {
			return exit(&flowError{code: ExitInternal, class: "keygen", err: err})
		}
		issuedAt = time.Now()
		if err := writePending(pendingPath, pendingKey{PrivateKey: encodeB64(privDER), DeviceID: deviceID,
			AccessToken: token, IssuedAt: issuedAt.Unix(), Source: source}); err != nil {
			// Without the pending file a killed process would lose a server-side key: do not PATCH.
			return exit(&flowError{code: ExitConfig, class: ClassConfig, err: fmt.Errorf("write pending key: %w", err)})
		}
	}

	outcome, fe := enrollWithRetry(tctx, client, log, deviceID, token, &privDER, &pubDER, name, skipPatch, pendingPath, issuedAt, source)
	if fe != nil {
		return exit(fe)
	}
	if skipPatch {
		source = "register-recovered"
	}
	return finishProfile(tctx, env, em, log, client, profileWrite{
		path: out, previous: nil, account: outcome.account, privDER: privDER, token: token, issuedAt: issuedAt,
		name: strings.TrimSuffix(filepath.Base(out), filepath.Ext(out)), deviceName: name, source: source,
		license: license, pendingPath: pendingPath, event: "registered",
	})
}

// enrollWithRetry enrolls; on "Invalid public key" it generates a new key once (usque enroll.go).
func enrollWithRetry(ctx context.Context, client *APIClient, log *Logger, deviceID, token string, privDER, pubDER *[]byte,
	name string, skipPatch bool, pendingPath string, issuedAt time.Time, source string) (*enrollOutcome, *flowError) {
	outcome, fe := completeEnrollment(ctx, client, log, deviceID, token, *pubDER, name, skipPatch)
	if fe == nil || skipPatch {
		return outcome, fe
	}
	var se *apiStatusError
	if !errors.As(fe.err, &se) || se.API == nil || !se.API.HasErrorMessage(usquemodels.InvalidPublicKey) {
		return nil, fe
	}
	log.Warn("the server rejected the public key; generating a new one")
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, &flowError{code: ExitInternal, class: "keygen", err: err}
	}
	if err := writePending(pendingPath, pendingKey{PrivateKey: encodeB64(priv), DeviceID: deviceID, AccessToken: token,
		IssuedAt: issuedAt.Unix(), Source: source}); err != nil {
		return nil, &flowError{code: ExitConfig, class: ClassConfig, err: fmt.Errorf("write pending key: %w", err)}
	}
	*privDER, *pubDER = priv, pub
	return completeEnrollment(ctx, client, log, deviceID, token, pub, name, false)
}

type profileWrite struct {
	path        string
	previous    []byte
	prevNova    json.RawMessage
	account     usquemodels.AccountData
	privDER     []byte
	token       string
	issuedAt    time.Time
	name        string
	deviceName  string
	source      string
	license     string
	pendingPath string
	event       string
	mode        string
}

// finishProfile applies the optional license, writes the profile atomically, drops the pending
// file and emits the result event.
func finishProfile(ctx context.Context, env *cliEnv, em *events.Emitter, log *Logger, client *APIClient, w profileWrite) int {
	accountType := strings.TrimSpace(w.account.Account.AccountType)
	if strings.TrimSpace(w.license) != "" {
		if at, err := client.setLicense(ctx, w.account.ID, w.token, w.license); err != nil {
			log.Warn("license was not applied; the profile works without it (MASQUE needs no WARP+)", "err", err)
		} else if at != "" {
			accountType = at
			log.Info("license applied", "account_type", at)
		}
	}
	id, err := BuildIdentity(w.account, w.privDER, w.token, w.issuedAt)
	if err != nil {
		log.Error("device record does not form a profile", "err", err)
		return emitExit(em, ExitNoPeers, "no_peers", 0, err)
	}
	if strings.TrimSpace(w.account.ID) == "" {
		id.DeviceID = deviceIDFromPending(w.pendingPath)
	}
	if w.prevNova != nil {
		id.Nova = w.prevNova
	} else {
		meta, _ := json.Marshal(NovaMeta{Schema: 1, Name: w.name, CreatedBy: "nova-pc/" + env.version, Source: w.source,
			AccountType: accountType, DeviceName: w.deviceName})
		id.Nova = meta
	}
	doc, err := MarshalDocument(id, w.previous)
	if err != nil {
		return emitExit(em, ExitInternal, "encode", 0, err)
	}
	if err := writeFileAtomic(w.path, doc); err != nil {
		log.Error("cannot write the profile; the key stays in the pending file", "path", w.path, "err", err)
		return emitExit(em, ExitConfig, ClassConfig, 0, err)
	}
	if err := os.Remove(w.pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Error("profile written but the pending key file could not be removed", "path", w.pendingPath, "err", err)
	}
	fields := []events.Field{
		events.F("path", w.path), events.F("device_id_prefix", DeviceIDPrefix(id.DeviceID)),
		events.F("account_type", accountType), events.F("warp_enabled", w.account.WarpEnabled),
		events.F("peers", len(w.account.Config.Peers)), events.F("endpoint_v4", id.EndpointV4),
		events.F("api_via", client.winnerLabel()),
	}
	if w.mode != "" {
		fields = append(fields, events.F("mode", w.mode))
	}
	fields = append(fields, relayFields(client)...)
	em.Emit(w.event, fields...)
	log.Info("profile written", "path", w.path, "device", DeviceIDPrefix(id.DeviceID), "endpoint_v4", id.EndpointV4,
		"ipv4", id.IPv4, "warp_enabled", w.account.WarpEnabled)
	return ExitOK
}

// classKeySuperseded: `enroll --activate-only` found another key on the server; a full enroll is needed.
const classKeySuperseded = "key_superseded"

// confirmServerHoldsKey checks that the device record carries the profile's public key. A record
// without a comparable key leaves the key unverified (logged) rather than failing a working profile.
func confirmServerHoldsKey(ctx context.Context, client *APIClient, log *Logger, id Identity, account usquemodels.AccountData) *flowError {
	serverKey, keyType := strings.TrimSpace(account.Key), strings.TrimSpace(account.KeyType)
	if serverKey == "" {
		record, _, err := client.fetchDevice(ctx, id.DeviceID, id.AccessToken)
		if err != nil {
			log.Warn("cannot read the device key back; the profile key stays unverified", "err", err)
			return nil
		}
		serverKey, keyType = strings.TrimSpace(record.Key), strings.TrimSpace(record.KeyType)
	}
	same, known := sameMasqueKey(serverKey, keyType, id.PrivateKey)
	switch {
	case !known:
		log.Warn("the device record carries no comparable key; the profile key stays unverified", "key_type", keyType)
		return nil
	case same:
		log.Info("the server holds the profile key", "device", DeviceIDPrefix(id.DeviceID))
		return nil
	}
	return &flowError{code: ExitAccessDenied, class: classKeySuperseded, err: errors.New(
		"the server holds another key for this device (a later enroll replaced it); the profile is left as is, run a full enroll")}
}

// sameMasqueKey compares the key of a device record with the public half of privateB64. known is
// false when the record key cannot be compared (absent or in an unknown form).
func sameMasqueKey(serverKey, keyType, privateB64 string) (same, known bool) {
	if serverKey == "" {
		return false, false
	}
	own, err := PublicKeyB64FromPrivate(privateB64)
	if err != nil {
		return false, false
	}
	if serverKey == own {
		return true, true
	}
	der, _ := decodeB64(privateB64)
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return false, false
	}
	var raw []byte
	if block, _ := pem.Decode([]byte(serverKey)); block != nil {
		raw = block.Bytes
	} else if raw, err = decodeB64(serverKey); err != nil {
		return false, false
	}
	if pub, err := x509.ParsePKIXPublicKey(raw); err == nil {
		ec, ok := pub.(*ecdsa.PublicKey)
		return ok && ec.Equal(&priv.PublicKey), true
	}
	if len(raw) == 65 && raw[0] == 4 { // an uncompressed P-256 point without the PKIX wrapper
		if point, err := priv.PublicKey.ECDH(); err == nil {
			return bytes.Equal(raw, point.Bytes()), true
		}
	}
	if keyType != "" && !strings.EqualFold(keyType, "secp256r1") {
		return false, true // e.g. a WireGuard curve25519 key: certainly not this MASQUE key
	}
	return false, false
}

func deviceIDFromPending(path string) string {
	p, err := readPending(path)
	if err != nil || p == nil {
		return ""
	}
	return p.DeviceID
}

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// ---- enroll -------------------------------------------------------------------------------------

func runEnroll(args []string, env *cliEnv) int {
	var (
		common       commonOptions
		api          apiOptions
		configPath   string
		sameKey      bool
		activateOnly bool
		name         string
	)
	fs := flag.NewFlagSet("masque enroll", flag.ContinueOnError)
	common.register(fs)
	api.register(fs)
	fs.StringVar(&configPath, "config", "", "profile to update in place")
	fs.BoolVar(&sameKey, "same-key", false, "re-send the current public key instead of generating one")
	fs.BoolVar(&activateOnly, "activate-only", false, "only PATCH warp_enabled + GET; the key is not rotated")
	fs.StringVar(&name, "name", "Nova PC", "device name")
	if ok, code := env.parseFlags(fs, args); !ok {
		return code
	}
	log, em, cleanup, code := env.setup(common, "enroll")
	if code != 0 {
		return code
	}
	defer cleanup()
	var client *APIClient
	exit := func(fe *flowError) int {
		log.Error("enroll failed", "code", fe.code, "class", fe.class, "err", fe.err)
		return emitExit(em, fe.code, fe.class, 0, fe.err, relayFields(client)...)
	}
	usage := func(err error) int { return exit(&flowError{code: ExitUsage, class: "usage", err: err}) }
	if strings.TrimSpace(configPath) == "" {
		return usage(errors.New("--config is required"))
	}
	if sameKey && activateOnly {
		return usage(errors.New("--same-key and --activate-only exclude each other"))
	}
	if api.timeout < 10*time.Second {
		return usage(errors.New("--timeout must be >= 10s"))
	}
	client, err := api.newClient(log)
	if err != nil {
		return usage(err)
	}
	lock, err := lockProfile(configPath)
	if err != nil {
		if errors.Is(err, errLocked) {
			return exit(&flowError{code: ExitLocked, class: "locked", err: err})
		}
		return exit(&flowError{code: ExitConfig, class: ClassConfig, err: err})
	}
	defer lock.Unlock()

	id, raw, err := LoadIdentityFile(configPath)
	if err != nil {
		return exit(&flowError{code: ExitConfig, class: ClassConfig, err: err})
	}
	if id.DeviceID == "" || id.AccessToken == "" {
		return exit(&flowError{code: ExitConfig, class: ClassConfig, err: errors.New("profile has no device_id/access_token; register a new one")})
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if code, stop := env.startStopWatch(ctx, cancel, common.parentPID, log); stop {
		return emitExit(em, code, stopClass(code), 0, nil)
	}
	tctx, tcancel := context.WithTimeout(ctx, api.timeout)
	defer tcancel()

	pendingPath := configPath + ".pending"
	pending, perr := readPending(pendingPath)
	if perr != nil {
		log.Error("pending key unusable", "err", perr)
		setAsidePending(pendingPath, log)
		pending = nil
	}
	if pending != nil && pending.DeviceID != id.DeviceID {
		log.Warn("pending key belongs to another device; setting it aside", "pending_device", DeviceIDPrefix(pending.DeviceID))
		setAsidePending(pendingPath, log)
		pending = nil
	}

	w := profileWrite{path: configPath, previous: raw, prevNova: id.Nova, token: id.AccessToken, pendingPath: pendingPath,
		event: "enrolled", license: ""}
	var (
		privDER, pubDER []byte
		skipPatch       bool
		issuedAt        = time.Unix(id.IssuedAt, 0)
		mode            string
	)
	switch {
	case pending != nil:
		record, _, err := client.fetchDevice(tctx, id.DeviceID, id.AccessToken)
		if err != nil {
			return exit(apiFailure("read device", err))
		}
		pubB64, _ := PublicKeyB64FromPrivate(pending.PrivateKey)
		privDER, _ = decodeB64(pending.PrivateKey)
		pubDER, _ = decodeB64(pubB64)
		if strings.TrimSpace(record.Key) == pubB64 {
			log.Info("the server holds the pending key; promoting it")
			skipPatch, issuedAt, mode = true, time.Unix(pending.IssuedAt, 0), "recovered"
		} else {
			log.Info("the pending key never reached the server; enrolling it now")
			issuedAt, mode = time.Now(), "rotate"
		}
	case activateOnly:
		privDER, _ = decodeB64(id.PrivateKey)
		skipPatch, mode = true, "activate-only"
	case sameKey:
		pubB64, err := PublicKeyB64FromPrivate(id.PrivateKey)
		if err != nil {
			return exit(&flowError{code: ExitConfig, class: ClassConfig, err: err})
		}
		privDER, _ = decodeB64(id.PrivateKey)
		pubDER, _ = decodeB64(pubB64)
		issuedAt, mode = time.Now(), "same-key"
	default:
		if privDER, pubDER, err = GenerateKeyPair(); err != nil {
			return exit(&flowError{code: ExitInternal, class: "keygen", err: err})
		}
		issuedAt, mode = time.Now(), "rotate"
		if err := writePending(pendingPath, pendingKey{PrivateKey: encodeB64(privDER), DeviceID: id.DeviceID,
			AccessToken: id.AccessToken, IssuedAt: issuedAt.Unix(), Source: "enroll"}); err != nil {
			return exit(&flowError{code: ExitConfig, class: ClassConfig, err: fmt.Errorf("write pending key: %w", err)})
		}
	}
	outcome, fe := enrollWithRetry(tctx, client, log, id.DeviceID, id.AccessToken, &privDER, &pubDER, name, skipPatch,
		pendingPath, issuedAt, "enroll")
	if fe != nil {
		return exit(fe)
	}
	if mode == "activate-only" {
		// Activation and GET succeed for a device whose key a later enroll replaced (another Nova job,
		// an Android client sharing the identity). Rewriting the profile with its stale key and exiting
		// 0 would spend Nova's one enroll of this start on nothing.
		if fe := confirmServerHoldsKey(tctx, client, log, id, outcome.account); fe != nil {
			return exit(fe)
		}
	}
	if outcome.account.ID == "" {
		outcome.account.ID = id.DeviceID
	}
	w.account, w.privDER, w.issuedAt, w.mode = outcome.account, privDER, issuedAt, mode
	return finishProfile(tctx, env, em, log, client, w)
}
