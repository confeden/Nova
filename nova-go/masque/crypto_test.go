package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCrypto builds Crypto with a fresh client key and a separate endpoint key; it also returns
// nothing else, the endpoint private key lives in testServerCert when a test needs a server.
func testCrypto(t *testing.T) *Crypto {
	t.Helper()
	c, _ := testCryptoWithServerKey(t)
	return c
}

func testCryptoWithServerKey(t *testing.T) (*Crypto, *ecdsa.PrivateKey) {
	t.Helper()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerDER, err := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{
		PrivateKey:     base64.StdEncoding.EncodeToString(clientDER),
		EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: peerDER})),
	}
	c, err := PrepareCrypto(id)
	if err != nil {
		t.Fatal(err)
	}
	return c, serverKey
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"cloudflareaccess.com"},
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestStrictPinVerifier(t *testing.T) {
	c, serverKey := testCryptoWithServerKey(t)
	verify := strictPinVerifier(c.PeerKey)

	if err := verify(nil, nil); err == nil {
		t.Fatal("empty certificate chain accepted (usque returns nil here; the PC helper must not)")
	}
	if err := verify([][]byte{selfSigned(t, serverKey)}, nil); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verify([][]byte{selfSigned(t, otherKey)}, nil)
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || !strings.Contains(err.Error(), "different public key") {
		t.Fatalf("foreign key: want CertificateInvalidError with the usque detail, got %v", err)
	}
	if classifyError(StageTLS, transportH2, err) != ClassPubkeyMismatch {
		t.Fatalf("mismatch not classified as pubkey_mismatch: %v", err)
	}
	if err := verify([][]byte{[]byte("garbage")}, nil); err == nil {
		t.Fatal("garbage certificate accepted")
	}
	if err := strictPinVerifier(nil)([][]byte{selfSigned(t, serverKey)}, nil); err == nil {
		t.Fatal("verifier without a pin accepted a certificate")
	}
}

func TestClientCertificateMatchesUsqueFields(t *testing.T) {
	c := testCrypto(t)
	cert, err := x509.ParseCertificate(c.Cert[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.Sign() != 0 {
		t.Fatalf("serial = %v, want 0", cert.SerialNumber)
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("validity = %v, want 24h", d)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&c.PrivateKey.PublicKey) {
		t.Fatal("certificate key is not the profile key")
	}
}

func TestPublicKeyB64FromPrivate(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKeyB64FromPrivate(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(pub) {
		t.Fatal("derived public key differs from the generated one")
	}
	if _, err := PublicKeyB64FromPrivate("!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
}

func TestPrepareCryptoRejectsBrokenKeys(t *testing.T) {
	c := testCrypto(t)
	_ = c
	if _, err := PrepareCrypto(Identity{PrivateKey: "AAAA", EndpointPubKey: "x"}); err == nil {
		t.Fatal("broken private key accepted")
	}
	priv, _, _ := GenerateKeyPair()
	if _, err := PrepareCrypto(Identity{PrivateKey: base64.StdEncoding.EncodeToString(priv), EndpointPubKey: "not pem"}); err == nil {
		t.Fatal("non-PEM endpoint key accepted")
	}
}
