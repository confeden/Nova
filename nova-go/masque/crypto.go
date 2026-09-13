package masque

// Port of nova-core/engine/masque.go:784-855 (key pair, crypto preparation, client certificate)
// plus the PC hardening of and-masque.md §4.2: the TLS config comes from usque's
// PrepareTlsConfig, and its VerifyPeerCertificate is replaced by a strict copy that also fails on
// an empty certificate chain.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	usqueapi "github.com/Diniboy1123/usque/api"
)

// GenerateKeyPair returns a P-256 key as SEC1 DER and its public half as PKIX DER.
func GenerateKeyPair() (privateDER, publicDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	publicDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateDER, publicDER, nil
}

// PublicKeyB64FromPrivate derives base64(PKIX DER public key) from base64(SEC1 DER private key),
// the form Cloudflare stores in the device record's "key".
func PublicKeyB64FromPrivate(privateB64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// Crypto is the parsed key material of an identity.
type Crypto struct {
	PrivateKey *ecdsa.PrivateKey
	PeerKey    *ecdsa.PublicKey
	Cert       [][]byte
}

// PrepareCrypto parses the identity keys and creates the client certificate.
func PrepareCrypto(id Identity) (*Crypto, error) {
	der, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode MASQUE private key: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE private key: %w", err)
	}
	block, _ := pem.Decode([]byte(id.EndpointPubKey))
	if block == nil {
		return nil, errors.New("decode MASQUE endpoint public key: no PEM block")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE endpoint public key: %w", err)
	}
	peer, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("MASQUE endpoint public key is not ECDSA")
	}
	cert, err := generateClientCert(priv)
	if err != nil {
		return nil, fmt.Errorf("generate MASQUE client certificate: %w", err)
	}
	return &Crypto{PrivateKey: priv, PeerKey: peer, Cert: cert}, nil
}

// generateClientCert matches usque field for field (serial 0, NotBefore now, 24 h), on purpose:
// a client identical to the reference leaves only server-side variables (masque.go:837-855).
func generateClientCert(priv *ecdsa.PrivateKey) ([][]byte, error) {
	now := time.Now()
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
	}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return [][]byte{cert}, nil
}

// errPubkeyMismatch keeps usque's wording: the classifier and the Android KB grep for it.
const pubkeyMismatchDetail = "remote endpoint has a different public key than what we trust in config.json"

// NewTLSConfig builds the MASQUE TLS config for one SNI. The SNI guard runs here too, as the last
// line of defence: a *cloudflareclient.com name is refused unless allowCloudflareSNI.
func NewTLSConfig(c *Crypto, sni string, allowCloudflareSNI bool) (*tls.Config, error) {
	if c == nil || c.PrivateKey == nil || c.PeerKey == nil || len(c.Cert) == 0 {
		return nil, errors.New("MASQUE crypto is not prepared")
	}
	name, err := NormalizeSNI(sni)
	if err != nil {
		return nil, err
	}
	if IsCloudflareClientSNI(name) && !allowCloudflareSNI {
		return nil, fmt.Errorf("SNI %q is a cloudflareclient.com name, refused (DPI blocks it)", name)
	}
	cfg, err := usqueapi.PrepareTlsConfig(c.PrivateKey, c.PeerKey, c.Cert, name)
	if err != nil {
		return nil, fmt.Errorf("prepare MASQUE TLS config: %w", err)
	}
	if !cfg.InsecureSkipVerify {
		// usque's config relies on the pin; if that ever changes the strict pin still applies.
		cfg.InsecureSkipVerify = true
	}
	cfg.VerifyPeerCertificate = strictPinVerifier(c.PeerKey)
	return cfg, nil
}

// strictPinVerifier accepts exactly one thing: a leaf certificate whose ECDSA key equals the
// endpoint key from enrollment. Unlike usque it fails on an empty chain, because with
// InsecureSkipVerify this callback is the whole authentication of the server.
func strictPinVerifier(peer *ecdsa.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if peer == nil {
			return errors.New("no pinned endpoint key")
		}
		if len(rawCerts) == 0 {
			return errors.New("remote endpoint presented no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse endpoint certificate: %w", err)
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return x509.ErrUnsupportedAlgorithm
		}
		if !key.Equal(peer) {
			return x509.CertificateInvalidError{Cert: cert, Reason: x509.NoValidChains, Detail: pubkeyMismatchDetail}
		}
		return nil
	}
}
