package sshkey

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
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
	sig, err := SignFile(path, []byte("ntwire"))
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(parsed, []byte("ntwire"), sig); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedKeyRequiresPassphrase(t *testing.T) {
	signer, _, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(signer, "", []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/id"
	if err = os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}

	if needs, err := NeedsPassphrase(path); err != nil || !needs {
		t.Fatalf("NeedsPassphrase() = %v, %v, want true, nil", needs, err)
	}
	if _, err := SignFile(path, []byte("ntwire")); err == nil {
		t.Fatal("SignFile without a passphrase on an encrypted key should fail")
	}
	if _, err := SignFileWithPassphrase(path, []byte("ntwire"), []byte("wrong")); err == nil {
		t.Fatal("SignFileWithPassphrase with the wrong passphrase should fail")
	}
	sig, err := SignFileWithPassphrase(path, []byte("ntwire"), []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicFromPrivateWithPassphrase(path, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := ParsePublicString(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(parsed, []byte("ntwire"), sig); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateIdentityFileRoundTripsThroughPublicFromPrivateAndSignFile(t *testing.T) {
	path := t.TempDir() + "/relay_id_ed25519"
	fingerprint, err := GenerateIdentityFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pubLine, err := PublicFromPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := ParsePublicString(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(parsed) != fingerprint {
		t.Fatalf("Fingerprint(parsed) = %q, want %q", Fingerprint(parsed), fingerprint)
	}
	onDisk, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(onDisk)) != pubLine {
		t.Fatalf(".pub file %q does not match PublicFromPrivate %q", onDisk, pubLine)
	}
	sig, err := SignFile(path, []byte("ntwire-relay-register-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(parsed, []byte("ntwire-relay-register-v1"), sig); err != nil {
		t.Fatal(err)
	}
	if _, err = GenerateIdentityFile(path); err == nil {
		t.Fatal("GenerateIdentityFile should refuse to overwrite an existing key")
	}
}

func TestNeedsPassphraseUnencryptedKey(t *testing.T) {
	signer, _, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/id"
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if needs, err := NeedsPassphrase(path); err != nil || needs {
		t.Fatalf("NeedsPassphrase() = %v, %v, want false, nil", needs, err)
	}
}
