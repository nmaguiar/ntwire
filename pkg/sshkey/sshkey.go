// Package sshkey parses authorized_keys material and signs nwire challenges.
package sshkey

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func ParsePublic(b []byte) (ssh.PublicKey, string, error) {
	k, c, _, _, err := ssh.ParseAuthorizedKey(b)
	return k, c, err
}
func ParsePublicString(s string) (ssh.PublicKey, string, error) { return ParsePublic([]byte(s)) }
func Fingerprint(k ssh.PublicKey) string                        { return ssh.FingerprintSHA256(k) }
func SignFile(path string, message []byte) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	k, err := ssh.ParsePrivateKey(b)
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
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	k, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey()))), nil
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
