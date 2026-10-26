package testutil

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

// PPK is an independent test-only encoder: keys come from crypto/rand, not the PPK
// parser. No private key fixtures are stored in the repository.
func PPK(t *testing.T, key crypto.Signer, version int, encrypted bool) []byte {
	t.Helper()
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	var private []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		private = ssh.Marshal(struct{ D, P, Q, Qinv *big.Int }{k.D, k.Primes[0], k.Primes[1], new(big.Int).ModInverse(k.Primes[1], k.Primes[0])})
	case *ecdsa.PrivateKey:
		private = ssh.Marshal(struct{ D *big.Int }{k.D})
	case ed25519.PrivateKey:
		private = ssh.Marshal(struct{ Seed []byte }{k.Seed()})
	}
	encryption, extra := "none", ""
	var cipherKey, iv, macKey []byte
	password := []byte(nil)
	if encrypted {
		encryption = "aes256-cbc"
		password = []byte("s3cret")
		private = append(private, make([]byte, 16-len(private)%16)...)
	}
	var hf func() hash.Hash
	if version == 2 {
		hf = sha1.New
		sum := sha1.Sum(append([]byte("putty-private-key-file-mac-key"), password...))
		macKey = sum[:]
		for i := uint32(0); i < 2; i++ {
			prefix := binary.BigEndian.AppendUint32(nil, i)
			sum := sha1.Sum(append(prefix, password...))
			cipherKey = append(cipherKey, sum[:]...)
		}
		cipherKey = cipherKey[:32]
		iv = make([]byte, 16)
	} else {
		hf = sha256.New
		if encrypted {
			salt := []byte("0123456789abcdef")
			derived := argon2.IDKey(password, salt, 1, 32, 1, 80)
			cipherKey = derived[:32]
			iv = derived[32:48]
			macKey = derived[48:]
			extra = fmt.Sprintf("Key-Derivation: Argon2id\nArgon2-Memory: 32\nArgon2-Passes: 1\nArgon2-Parallelism: 1\nArgon2-Salt: %x\n", salt)
		}
	}
	mac := hmac.New(hf, macKey)
	mac.Write(ssh.Marshal(struct {
		Algo, Encryption, Comment string
		Public, Private           []byte
	}{pub.Type(), encryption, "test", pub.Marshal(), private}))
	if encrypted {
		block, err := aes.NewCipher(cipherKey)
		if err != nil {
			t.Fatal(err)
		}
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(private, private)
	}
	blob := func(b []byte) string {
		s := base64.StdEncoding.EncodeToString(b)
		var lines []string
		for len(s) > 64 {
			lines = append(lines, s[:64])
			s = s[64:]
		}
		lines = append(lines, s)
		return fmt.Sprintf("%d\n%s\n", len(lines), strings.Join(lines, "\n"))
	}
	return []byte(fmt.Sprintf("PuTTY-User-Key-File-%d: %s\nEncryption: %s\nComment: test\nPublic-Lines: %s%sPrivate-Lines: %sPrivate-MAC: %x\n", version, pub.Type(), encryption, blob(pub.Marshal()), extra, blob(private), mac.Sum(nil)))
}
