// Command update-manifest signs the complete set of client release archives.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/updater"
	"io"
	"os"
	"path/filepath"
)

func main() {
	version := flag.String("version", "", "stable release version")
	dir := flag.String("dir", "dist", "directory containing all published client archives")
	generate := flag.String("generate-key", "", "create a private signing key at this path and print only its public key")
	flag.Parse()
	if *generate != "" {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e == nil {
			var f *os.File
			f, e = os.OpenFile(*generate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e == nil {
				_, e = f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
				ce := f.Close()
				if e == nil {
					e = ce
				}
			}
		}
		if e != nil {
			fail(e)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return
	}
	if e := sign(*version, *dir, os.Getenv("NTWIRE_UPDATE_SIGNING_KEY"), os.Getenv("NTWIRE_UPDATE_PUBLIC_KEY")); e != nil {
		fail(e)
	}
}
func fail(e error) { fmt.Fprintln(os.Stderr, "update manifest:", e); os.Exit(1) }
func sign(version, dir, encoded, public string) error {
	key, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("NTWIRE_UPDATE_SIGNING_KEY must contain a base64 Ed25519 private key")
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != public {
		return errors.New("signing key does not match NTWIRE_UPDATE_PUBLIC_KEY")
	}
	m := updater.Manifest{Version: version}
	for _, p := range []string{"ntwire", "ntwire-gui"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, arch := range []string{"amd64", "arm64"} {
				name, e := updater.AssetName(p, version, goos, arch)
				if e != nil {
					continue
				}
				f, e := os.Open(filepath.Join(dir, name))
				if e != nil {
					return e
				}
				h := sha256.New()
				n, e := io.Copy(h, f)
				f.Close()
				if e != nil {
					return e
				}
				m.Assets = append(m.Assets, updater.Asset{Product: p, OS: goos, Arch: arch, Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
			}
		}
	}
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return e
	}
	signature := ed25519.Sign(ed25519.PrivateKey(key), b)
	if _, e = updater.Verify(b, signature, pub); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "update-manifest.json"), b, 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "update-manifest.sig"), []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0644)
}
