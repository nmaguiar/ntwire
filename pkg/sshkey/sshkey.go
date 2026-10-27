// Package sshkey parses authorized_keys material and signs ntwire challenges.
package sshkey

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kayrus/putty"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
)

var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

const (
	maxPBKDF2Iterations = 1_000_000
	maxScryptMemory     = 256 << 20
	maxScryptWork       = 4_194_304
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
	if block, _ := pem.Decode(b); block != nil && block.Type == "ENCRYPTED PRIVATE KEY" {
		var info struct {
			Algorithm pkix.AlgorithmIdentifier
			Data      []byte
		}
		rest, err := asn1.Unmarshal(block.Bytes, &info)
		if err != nil || len(rest) != 0 || len(info.Data) == 0 || len(info.Algorithm.Algorithm) == 0 {
			return nil, errors.New("malformed encrypted PKCS#8 private key")
		}
		if err := validateEncryptedPKCS8Parameters(info.Algorithm); err != nil {
			return nil, err
		}
		if len(passphrase) == 0 {
			return nil, &ssh.PassphraseMissingError{}
		}
		key, err := decryptPKCS8(block.Bytes, passphrase)
		if err != nil {
			return nil, errors.New("invalid or unsupported encrypted PKCS#8 private key, or incorrect passphrase")
		}
		return ssh.NewSignerFromKey(key)
	}
	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(b, passphrase)
	}
	return ssh.ParsePrivateKey(b)
}

// validateEncryptedPKCS8Parameters rejects password KDF settings that could
// consume excessive client CPU or memory before the dependency derives a key.
func validateEncryptedPKCS8Parameters(algorithm pkix.AlgorithmIdentifier) error {
	if !algorithm.Algorithm.Equal(oidPBES2) {
		return nil
	}
	var params struct {
		KDF        pkix.AlgorithmIdentifier
		Encryption pkix.AlgorithmIdentifier
	}
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		return errors.New("malformed encrypted PKCS#8 private key")
	}
	switch {
	case params.KDF.Algorithm.Equal(oidPBKDF2):
		var p struct {
			Salt       []byte
			Iterations int
		}
		rest, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &p)
		if err != nil || len(rest) != 0 || p.Iterations <= 0 || p.Iterations > maxPBKDF2Iterations {
			return errors.New("encrypted PKCS#8 private key uses unsafe PBKDF2 parameters")
		}
	case params.KDF.Algorithm.Equal(oidScrypt):
		var p struct {
			Salt        []byte
			Cost        int
			BlockSize   int
			Parallelism int
		}
		rest, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &p)
		if err != nil || len(rest) != 0 || !safeScryptParameters(p.Cost, p.BlockSize, p.Parallelism) {
			return errors.New("encrypted PKCS#8 private key uses unsafe scrypt parameters")
		}
	}
	return nil
}

func safeScryptParameters(cost, blockSize, parallelism int) bool {
	if cost <= 1 || cost&(cost-1) != 0 || blockSize <= 0 || parallelism <= 0 {
		return false
	}
	// scrypt uses about 128*N*r bytes and work proportional to N*r*p.
	if cost > maxScryptMemory/128/blockSize {
		return false
	}
	return cost <= maxScryptWork/blockSize/parallelism
}

// The dependency may panic on malformed cipher parameters; reject such input.
func decryptPKCS8(der, passphrase []byte) (key any, err error) {
	defer func() {
		if recover() != nil {
			key = nil
			err = errors.New("malformed encrypted key")
		}
	}()
	return pkcs8.ParsePKCS8PrivateKey(der, passphrase)
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

// IdentityError describes an unreadable or invalid identity without exposing its contents.
func IdentityError(path string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("cannot read SSH private key %q: %w", path, err)
	}
	return fmt.Errorf("invalid or unsupported SSH private key %q; see docs/CLIENT.md#private-key-formats-and-conversion for supported formats and conversion guidance", path)
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
