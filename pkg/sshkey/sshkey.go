// Package sshkey parses authorized_keys material and signs ntwire challenges.
package sshkey

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kayrus/putty"
	"golang.org/x/crypto/ssh"
)

func ParsePublic(b []byte) (ssh.PublicKey, string, error) {
	k, c, _, _, err := ssh.ParseAuthorizedKey(b)
	return k, c, err
}
func ParsePublicString(s string) (ssh.PublicKey, string, error) { return ParsePublic([]byte(s)) }
func Fingerprint(k ssh.PublicKey) string                        { return ssh.FingerprintSHA256(k) }

// parsePrivateKey parses key material, decrypting it with passphrase when
// non-empty. An encrypted key with an empty passphrase yields
// *ssh.PassphraseMissingError, which NeedsPassphrase checks for.
func parsePrivateKey(b, passphrase []byte) (ssh.Signer, error) {
	if bytes.HasPrefix(b, []byte("PuTTY-User-Key-File-")) {
		return parsePPK(b, passphrase)
	}
	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(b, passphrase)
	}
	return ssh.ParsePrivateKey(b)
}

// NeedsPassphrase reports whether the key at path is encrypted. It returns
// any other read/parse error unchanged so callers can surface it normally.
func NeedsPassphrase(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	_, err = parsePrivateKey(b, nil)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return true, nil
	}
	return false, err
}

func SignFile(path string, message []byte) (string, error) {
	return SignFileWithPassphrase(path, message, nil)
}
func SignFileWithPassphrase(path string, message, passphrase []byte) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	k, err := parsePrivateKey(b, passphrase)
	if err != nil {
		return "", err
	}
	sig, err := k.Sign(rand.Reader, message)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ssh.Marshal(sig)), nil
}
func Verify(k ssh.PublicKey, message []byte, encoded string) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	sig := &ssh.Signature{}
	if err = ssh.Unmarshal(raw, sig); err != nil {
		return err
	}
	return k.Verify(message, sig)
}
func PublicFromPrivate(path string) (string, error) {
	return PublicFromPrivateWithPassphrase(path, nil)
}
func PublicFromPrivateWithPassphrase(path string, passphrase []byte) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	k, err := parsePrivateKey(b, passphrase)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey()))), nil
}

// GenerateIdentityFile writes an Ed25519 private key (PKCS8 PEM) and its
// paired OpenSSH-format public key at path and path+".pub". It never
// overwrites an existing key pair. The returned fingerprint, and the
// generated files, use the same format as an authorized_keys entry --
// PublicFromPrivate and SignFile read the private key back directly.
func GenerateIdentityFile(path string) (fingerprint string, err error) {
	if path == "" {
		return "", fmt.Errorf("identity path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("refusing to overwrite existing key %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	signer, pub, err := GenerateEd25519()
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return "", err
	}
	k, err := ssh.NewPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(k), 0644); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return Fingerprint(k), nil
}

func GenerateEd25519() (crypto.Signer, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return base64.RawStdEncoding.EncodeToString(h[:])
}

// parsePPK keeps parser diagnostics (which may contain file contents) private.
// ParseRawPrivateKey verifies the MAC before decoding private key material.
func parsePPK(b, passphrase []byte) (ssh.Signer, error) {
	header, _, _ := bytes.Cut(b, []byte(": "))
	if string(header) != "PuTTY-User-Key-File-2" && string(header) != "PuTTY-User-Key-File-3" {
		return nil, fmt.Errorf("unsupported PuTTY private key version (expected PPK v2 or v3)")
	}
	// Reject numeric overflow before the parser narrows Argon2 parameters.
	for _, line := range strings.Split(string(b), "\n") {
		name, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ": ")
		if !ok {
			continue
		}
		bits := 32
		switch name {
		case "Argon2-Parallelism":
			bits = 8
		case "Argon2-Memory", "Argon2-Passes":
		default:
			continue
		}
		n, err := strconv.ParseUint(value, 10, bits)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid PuTTY Argon2 parameters")
		}
	}
	key, err := putty.New(b)
	if err != nil {
		return nil, fmt.Errorf("malformed PuTTY private key")
	}
	if key.KeyDerivation != "" && key.Encryption == "none" {
		return nil, fmt.Errorf("unexpected PuTTY key derivation for unencrypted key")
	}
	macLen := 20
	if key.Version == 3 {
		macLen = 32
	}
	if len(key.PublicKey) == 0 || len(key.PrivateKey) == 0 || len(key.PrivateMac) != macLen || key.Encryption == "" {
		return nil, fmt.Errorf("incomplete PuTTY private key")
	}
	if key.Encryption != "none" {
		if len(key.PrivateKey)%16 != 0 {
			return nil, fmt.Errorf("malformed encrypted PuTTY private key")
		}
		if len(passphrase) == 0 {
			return nil, &ssh.PassphraseMissingError{}
		}
	} else {
		// Unencrypted PPK MACs always use an empty passphrase.
		passphrase = nil
	}
	public, err := ssh.ParsePublicKey(key.PublicKey)
	if err != nil || public.Type() != key.Algo {
		return nil, fmt.Errorf("malformed PuTTY public key")
	}
	raw, err := key.ParseRawPrivateKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid PuTTY private key or incorrect passphrase (integrity check or key parsing failed)")
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("unsupported PuTTY private key type")
	}
	return signer, nil
}
