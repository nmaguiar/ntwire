//go:build !gui

package window

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserFallbackUsesPrivateFileInsteadOfCredentialArgv(t *testing.T) {
	original := launchBootstrapFile
	defer func() { launchBootstrapFile = original }()
	sentinel := errors.New("test launcher")
	var path string
	launchBootstrapFile = func(arg string) error {
		path = arg
		if strings.Contains(arg, "token=") {
			t.Fatal("credential in launcher argument")
		}
		file, _ := os.Stat(arg)
		dir, _ := os.Stat(filepath.Dir(arg))
		if file.Mode().Perm() != 0600 || dir.Mode().Perm() != 0700 {
			t.Fatal("bootstrap is not private")
		}
		b, err := os.ReadFile(arg)
		if err != nil || !strings.Contains(string(b), "token=secret") {
			t.Fatal("missing private bootstrap")
		}
		return sentinel
	}
	if err := Run("http://127.0.0.1:1234/?token=secret"); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("bootstrap not cleaned")
	}
}
