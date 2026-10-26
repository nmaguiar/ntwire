package sshkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/nmaguiar/ntwire/internal/testutil"
	"golang.org/x/crypto/ssh"
	"os"
	"strings"
	"testing"
)

func TestPPK(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{rsaKey, ecKey, edKey} {
		for _, version := range []int{2, 3} {
			for _, encrypted := range []bool{false, true} {
				pub, _ := ssh.NewPublicKey(key.Public())
				t.Run(fmt.Sprintf("%s/v%d/encrypted=%v", pub.Type(), version, encrypted), func(t *testing.T) {
					b := testutil.PPK(t, key, version, encrypted)
					for _, crlf := range []bool{false, true} {
						content := b
						if crlf {
							content = []byte(strings.ReplaceAll(string(b), "\n", "\r\n"))
						}
						path := t.TempDir() + "/identity-without-extension"
						if err := os.WriteFile(path, content, 0600); err != nil {
							t.Fatal(err)
						}
						needs, err := NeedsPassphrase(path)
						if err != nil || needs != encrypted {
							t.Fatalf("NeedsPassphrase = %v, %v", needs, err)
						}
						pass := []byte(nil)
						if encrypted {
							_, err := parsePrivateKey(content, nil)
							var missing *ssh.PassphraseMissingError
							if !errors.As(err, &missing) {
								t.Fatalf("missing passphrase: %v", err)
							}
							if _, err := parsePrivateKey(content, []byte("wrong")); err == nil {
								t.Fatal("accepted wrong passphrase")
							}
							pass = []byte("s3cret")
						}
						line, err := PublicFromPrivateWithPassphrase(path, pass)
						if err != nil {
							t.Fatal(err)
						}
						parsed, _, err := ParsePublicString(line)
						if err != nil {
							t.Fatal(err)
						}
						if Fingerprint(parsed) != Fingerprint(pub) || string(parsed.Marshal()) != string(pub.Marshal()) {
							t.Fatal("public key mismatch")
						}
						sig, err := SignFileWithPassphrase(path, []byte("challenge"), pass)
						if err != nil {
							t.Fatal(err)
						}
						if err := Verify(pub, []byte("challenge"), sig); err != nil {
							t.Fatal(err)
						}
						corrupt := append([]byte(nil), content...)
						idx := strings.Index(string(corrupt), "Private-MAC: ") + len("Private-MAC: ")
						corrupt[idx] = '0'
						if content[idx] == '0' {
							corrupt[idx] = '1'
						}
						if _, err := parsePrivateKey(corrupt, pass); err == nil {
							t.Fatal("accepted corrupted MAC")
						}
					}
				})
			}
		}
	}
}

func TestPPKMalformed(t *testing.T) {
	for _, b := range []string{"PuTTY-User-Key-File-1: ssh-rsa\n", "PuTTY-User-Key-File-4: ssh-rsa\n", "PuTTY-User-Key-File-3", "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\n", "PuTTY-User-Key-File-3: SECRET\n"} {
		t.Run(b, func(t *testing.T) {
			if _, err := parsePrivateKey([]byte(b), nil); err == nil {
				t.Fatal("accepted malformed key")
			} else if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error leaked content")
			}
		})
	}
}

func TestPPKTruncated(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{2, 3} {
		b := testutil.PPK(t, key, version, true)
		for cut := 1; cut < len(b)-2; cut++ {
			if _, err := parsePrivateKey(b[:cut], []byte("s3cret")); err == nil {
				t.Fatalf("v%d accepted truncated file at %d", version, cut)
			}
		}
	}
}

func TestPPKMalformedArgonParameters(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := string(testutil.PPK(t, key, 3, true))
	for _, replacement := range []struct{ old, new string }{
		{"Argon2-Memory: 32", "Argon2-Memory: 0"},
		{"Argon2-Passes: 1", "Argon2-Passes: -1"},
		{"Argon2-Passes: 1", "Argon2-Passes: 4294967296"},
		{"Argon2-Parallelism: 1", "Argon2-Parallelism: 256"},
	} {
		t.Run(replacement.new, func(t *testing.T) {
			if _, err := parsePrivateKey([]byte(strings.Replace(b, replacement.old, replacement.new, 1)), []byte("s3cret")); err == nil {
				t.Fatal("accepted invalid Argon2 parameter")
			}
		})
	}
}
