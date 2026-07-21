package protocol

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

func testSigningKey(t *testing.T) (path string, pub ssh.PublicKey) {
	t.Helper()
	signer, _, err := sshkey.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, err = ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	path = t.TempDir() + "/id"
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

func baseRelayRegisterRequest(pubLine string) RelayRegisterRequest {
	return RelayRegisterRequest{
		Version: Version, PublicKey: pubLine, Name: "home",
		Timestamp: "2026-01-01T00:00:00Z", Nonce: "abc123",
	}
}

func TestRelayRegisterPayload_RoundTrip(t *testing.T) {
	path, pub := testSigningKey(t)
	pubLine := string(ssh.MarshalAuthorizedKey(pub))
	r := baseRelayRegisterRequest(pubLine)

	p, err := RelayRegisterPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshkey.SignFile(path, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = sshkey.Verify(pub, p, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestRelayRegisterPayload_Tamper(t *testing.T) {
	path, pub := testSigningKey(t)
	pubLine := string(ssh.MarshalAuthorizedKey(pub))
	base := baseRelayRegisterRequest(pubLine)

	p, err := RelayRegisterPayload(base)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshkey.SignFile(path, p)
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(r RelayRegisterRequest) RelayRegisterRequest { return r }
	cases := []struct {
		name string
		fn   func(RelayRegisterRequest) RelayRegisterRequest
	}{
		{"public_key", func(r RelayRegisterRequest) RelayRegisterRequest { r.PublicKey = r.PublicKey + "x"; return r }},
		{"name", func(r RelayRegisterRequest) RelayRegisterRequest { r.Name = "lab"; return r }},
		{"timestamp", func(r RelayRegisterRequest) RelayRegisterRequest { r.Timestamp = "2026-01-01T00:00:01Z"; return r }},
		{"nonce", func(r RelayRegisterRequest) RelayRegisterRequest { r.Nonce = "different"; return r }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.fn(mutate(base))
			p2, err := RelayRegisterPayload(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if err = sshkey.Verify(pub, p2, sig); err == nil {
				t.Fatalf("signature verified after tampering field %q", tc.name)
			}
		})
	}
}

// TestRelayRegisterPayload_DistinctFromAuthSigning proves the domain
// separator does real work: a valid /v1/auth signature (SigningPayload) must
// not verify as a relay registration, and vice versa, even when the
// underlying field values overlap.
func TestRelayRegisterPayload_DistinctFromAuthSigning(t *testing.T) {
	path, pub := testSigningKey(t)
	pubLine := string(ssh.MarshalAuthorizedKey(pub))

	authReq := AuthRequest{
		Version: Version, PublicKey: pubLine, WireGuardPublicKey: "wg",
		Timestamp: "2026-01-01T00:00:00Z", Nonce: "abc123",
	}
	authPayload, err := SigningPayload(authReq)
	if err != nil {
		t.Fatal(err)
	}
	authSig, err := sshkey.SignFile(path, authPayload)
	if err != nil {
		t.Fatal(err)
	}

	relayReq := baseRelayRegisterRequest(pubLine)
	relayPayload, err := RelayRegisterPayload(relayReq)
	if err != nil {
		t.Fatal(err)
	}

	if err = sshkey.Verify(pub, relayPayload, authSig); err == nil {
		t.Fatal("an ntwire-auth-v1 signature verified as a relay registration signature")
	}

	relaySig, err := sshkey.SignFile(path, relayPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err = sshkey.Verify(pub, authPayload, relaySig); err == nil {
		t.Fatal("a relay registration signature verified as an ntwire-auth-v1 signature")
	}
}

func TestRelayRegisterPayload_RejectsWrongVersion(t *testing.T) {
	_, pub := testSigningKey(t)
	r := baseRelayRegisterRequest(string(ssh.MarshalAuthorizedKey(pub)))
	r.Version = Version + 1
	if _, err := RelayRegisterPayload(r); err == nil {
		t.Fatal("expected an error for an unsupported protocol version")
	}
}
