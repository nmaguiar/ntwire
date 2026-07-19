package sshkey

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGeneratedKeySignsAndParses(t *testing.T) {
	signer, _, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := ParsePublic(append(ssh.MarshalAuthorizedKey(pub), []byte(" test\\n")...))
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(parsed) != Fingerprint(pub) {
		t.Fatal("fingerprint mismatch")
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/id"
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	sig, err := SignFile(path, []byte("nwire"))
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(parsed, []byte("nwire"), sig); err != nil {
		t.Fatal(err)
	}
}
