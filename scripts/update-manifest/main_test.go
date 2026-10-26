package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/updater"
)

func TestSignRequiresCompleteArchivesAndMatchingKey(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	private := base64.StdEncoding.EncodeToString(key)
	public := base64.StdEncoding.EncodeToString(pub)
	dir := t.TempDir()
	if e := sign("1.2.3", dir, private, public); e == nil {
		t.Fatal("signed incomplete release")
	}
	for _, p := range []string{"ntwire", "ntwire-gui"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, arch := range []string{"amd64", "arm64"} {
				name, e := updater.AssetName(p, "1.2.3", goos, arch)
				if e == nil {
					os.WriteFile(filepath.Join(dir, name), []byte("fixture archive"), 0600)
				}
			}
		}
	}
	if e := sign("1.2.3", dir, private, "wrong key"); e == nil {
		t.Fatal("signed with mismatched public key")
	}
	if e := sign("1.2.3", dir, private, public); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "update-manifest.json"))
	encoded, _ := os.ReadFile(filepath.Join(dir, "update-manifest.sig"))
	sig, e := base64.StdEncoding.DecodeString(string(encoded))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = updater.Verify(b, sig, pub); e != nil {
		t.Fatal(e)
	}
}
