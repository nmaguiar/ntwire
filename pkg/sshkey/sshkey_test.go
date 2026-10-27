package sshkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/youmark/pkcs8"
	"os"
	"path/filepath"
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

func TestEncryptedPKCS8KeyTypes(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{"ed25519": ed, "ecdsa": ec, "rsa": rsaKey} {
		t.Run(name, func(t *testing.T) {
			der, err := pkcs8.MarshalPrivateKey(key, []byte("secret"), nil)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "identity")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if needs, err := NeedsPassphrase(path); err != nil || !needs {
				t.Fatalf("needs = %v, %v", needs, err)
			}
			if _, err := PublicFromPrivateWithPassphrase(path, []byte("wrong")); err == nil {
				t.Fatal("wrong passphrase accepted")
			}
			got, err := PublicFromPrivateWithPassphrase(path, []byte("secret"))
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if got != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) {
				t.Fatal("public key mismatch")
			}
		})
	}
}

func TestEncryptedPKCS8Scrypt(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkcs8.MarshalPrivateKey(key, []byte("secret"), &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.ScryptOpts{
			SaltSize:                 16,
			CostParameter:            1 << 14,
			BlockSize:                8,
			ParallelizationParameter: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicFromPrivateWithPassphrase(path, []byte("secret")); err != nil {
		t.Fatalf("valid bounded scrypt key rejected: %v", err)
	}
}

func TestMalformedEncryptedPKCS8Rejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	data := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NeedsPassphrase(path); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestEncryptedPKCS8KDFLimits(t *testing.T) {
	tests := []struct {
		name    string
		kdf     asn1.ObjectIdentifier
		params  any
		wantErr bool
	}{
		{name: "pbkdf2 boundary", kdf: oidPBKDF2, params: struct {
			Salt       []byte
			Iterations int
		}{[]byte("12345678"), maxPBKDF2Iterations}},
		{name: "pbkdf2 excessive", kdf: oidPBKDF2, params: struct {
			Salt       []byte
			Iterations int
		}{[]byte("12345678"), maxPBKDF2Iterations + 1}, wantErr: true},
		{name: "scrypt boundary", kdf: oidScrypt, params: struct {
			Salt        []byte
			Cost        int
			BlockSize   int
			Parallelism int
		}{[]byte("12345678"), 1 << 18, 8, 2}},
		{name: "scrypt excessive memory", kdf: oidScrypt, params: struct {
			Salt        []byte
			Cost        int
			BlockSize   int
			Parallelism int
		}{[]byte("12345678"), 1 << 19, 8, 1}, wantErr: true},
		{name: "scrypt excessive work", kdf: oidScrypt, params: struct {
			Salt        []byte
			Cost        int
			BlockSize   int
			Parallelism int
		}{[]byte("12345678"), 1 << 18, 8, 3}, wantErr: true},
		{name: "scrypt non power of two", kdf: oidScrypt, params: struct {
			Salt        []byte
			Cost        int
			BlockSize   int
			Parallelism int
		}{[]byte("12345678"), 3, 8, 1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kdfParams, err := asn1.Marshal(tt.params)
			if err != nil {
				t.Fatal(err)
			}
			pbes2Params, err := asn1.Marshal(struct {
				KDF        pkix.AlgorithmIdentifier
				Encryption pkix.AlgorithmIdentifier
			}{
				KDF: pkix.AlgorithmIdentifier{
					Algorithm:  tt.kdf,
					Parameters: asn1.RawValue{FullBytes: kdfParams},
				},
				Encryption: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = validateEncryptedPKCS8Parameters(pkix.AlgorithmIdentifier{
				Algorithm:  oidPBES2,
				Parameters: asn1.RawValue{FullBytes: pbes2Params},
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateEncryptedPKCS8Parameters() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptedPKCS8ExcessiveKDFRejectedBeforeDecryption(t *testing.T) {
	kdfParams, err := asn1.Marshal(struct {
		Salt       []byte
		Iterations int
	}{[]byte("12345678"), maxPBKDF2Iterations + 1})
	if err != nil {
		t.Fatal(err)
	}
	pbes2Params, err := asn1.Marshal(struct {
		KDF        pkix.AlgorithmIdentifier
		Encryption pkix.AlgorithmIdentifier
	}{
		KDF: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParams},
		},
		Encryption: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}},
	})
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: pbes2Params},
		},
		Data: []byte("not reached"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = parsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "unsafe PBKDF2") {
		t.Fatalf("parsePrivateKey() error = %v, want unsafe PBKDF2 rejection", err)
	}
}
