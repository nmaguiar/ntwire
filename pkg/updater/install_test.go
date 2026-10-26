package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func archiveBytes(t *testing.T, a Asset, names []string, symlink bool) []byte {
	t.Helper()
	var b bytes.Buffer
	if strings.HasSuffix(a.Name, ".zip") {
		z := zip.NewWriter(&b)
		for _, name := range names {
			h := &zip.FileHeader{Name: name, Method: zip.Deflate}
			h.SetMode(0755)
			if symlink {
				h.SetMode(os.ModeSymlink | 0755)
			}
			w, e := z.CreateHeader(h)
			if e != nil {
				t.Fatal(e)
			}
			w.Write([]byte("new app"))
		}
		if e := z.Close(); e != nil {
			t.Fatal(e)
		}
	} else {
		gz := gzip.NewWriter(&b)
		tr := tar.NewWriter(gz)
		for _, name := range names {
			h := &tar.Header{Name: name, Mode: 0755, Size: 7, Typeflag: tar.TypeReg}
			if symlink {
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "/etc/passwd"
				h.Size = 0
			}
			if e := tr.WriteHeader(h); e != nil {
				t.Fatal(e)
			}
			if !symlink {
				tr.Write([]byte("new app"))
			}
		}
		tr.Close()
		gz.Close()
	}
	return b.Bytes()
}
func TestExtractUnsafeArchives(t *testing.T) {
	for _, ext := range []string{".zip", ".tar.gz"} {
		a := Asset{Product: "ntwire", OS: "linux", Arch: "amd64", Name: "test" + ext}
		for _, tt := range []struct {
			names []string
			link  bool
		}{{[]string{"../ntwire"}, false}, {[]string{"/ntwire"}, false}, {[]string{"dir/../../ntwire"}, false}, {[]string{`dir\ntwire`}, false}, {[]string{"ntwire", "ntwire"}, false}, {[]string{"ntwire", "NTWIRE"}, false}, {[]string{"ntwire-server"}, false}, {[]string{"ntwire"}, true}, {[]string{"LICENSE"}, false}} {
			t.Run(ext+strings.Join(tt.names, "_"), func(t *testing.T) {
				dir := t.TempDir()
				archive := filepath.Join(dir, "archive")
				os.WriteFile(archive, archiveBytes(t, a, tt.names, tt.link), 0600)
				out := filepath.Join(dir, "stage")
				os.Mkdir(out, 0700)
				if _, e := extract(archive, out, a); e == nil {
					t.Fatal("accepted unsafe/missing executable archive")
				}
			})
		}
	}
}
func TestInstallAndRetainPrevious(t *testing.T) {
	a := Asset{Product: "ntwire", OS: runtime.GOOS, Arch: runtime.GOARCH}
	a.Name, _ = AssetName(a.Product, "1.2.3", a.OS, a.Arch)
	body := archiveBytes(t, a, []string{expectedTarget(a), "LICENSE", "README.md"}, false)
	c, r := signedRelease(t, body)
	dir := t.TempDir()
	target := filepath.Join(dir, expectedTarget(a))
	archive := filepath.Join(dir, r.Asset.Name)
	os.WriteFile(target, []byte("old app"), 0755)
	os.WriteFile(archive, body, 0600)
	j := Job{Release: *r, Target: target, Archive: archive, Current: "1.0.0"}
	if e := c.Install(j); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(target)
	old, _ := os.ReadFile(target + ".previous-1.0.0")
	if string(got) != "new app" || string(old) != "old app" {
		t.Fatalf("new %q old %q", got, old)
	}
	if e := c.Install(j); e == nil {
		t.Fatal("overwrote previous installation")
	}
	os.Mkdir(target+".update-lock", 0700)
	if e := c.Install(j); e == nil || !strings.Contains(e.Error(), "locked") {
		t.Fatalf("lock result %v", e)
	}
}
func TestExtractCompleteMacBundle(t *testing.T) {
	a := Asset{Product: "ntwire-gui", OS: "darwin", Arch: "arm64", Name: "bundle.zip"}
	dir := t.TempDir()
	archive := filepath.Join(dir, "bundle.zip")
	os.WriteFile(archive, archiveBytes(t, a, []string{"ntwire-gui.app/Contents/MacOS/ntwire-gui", "ntwire-gui.app/Contents/Info.plist", "ntwire-gui.app/Contents/Resources/icon.icns", "__MACOSX/._ntwire-gui.app"}, false), 0600)
	stage := filepath.Join(dir, "stage")
	os.Mkdir(stage, 0700)
	got, e := extract(archive, stage, a)
	if e != nil {
		t.Fatal(e)
	}
	if filepath.Base(got) != "ntwire-gui.app" {
		t.Fatal(got)
	}
	if _, e = os.Stat(filepath.Join(got, "Contents", "Resources", "icon.icns")); e != nil {
		t.Fatal(e)
	}
}
func TestReplacementRollback(t *testing.T) {
	for _, failRollback := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(dir, "ntwire")
		staged := filepath.Join(dir, "staged")
		previous := filepath.Join(dir, "previous")
		os.WriteFile(target, []byte("old"), 0700)
		os.WriteFile(staged, []byte("new"), 0700)
		rename := func(from, to string) error {
			if from == staged || (failRollback && from == previous) {
				return errors.New("injected replacement failure")
			}
			return os.Rename(from, to)
		}
		e := replace(target, staged, previous, rename)
		if e == nil {
			t.Fatal("failure not reported")
		}
		if failRollback {
			if !strings.Contains(e.Error(), "restore") {
				t.Fatal(e)
			}
			b, _ := os.ReadFile(previous)
			if string(b) != "old" {
				t.Fatal("lost recovery copy")
			}
		} else {
			b, _ := os.ReadFile(target)
			if string(b) != "old" {
				t.Fatal("rollback failed")
			}
		}
	}
}
func TestTargetRejectsManagedInstall(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ntwire")
	os.WriteFile(p, []byte("app"), 0755)
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if e := os.Symlink(p, link); e != nil {
			t.Fatal(e)
		}
		p, _ = filepath.EvalSymlinks(p)
		got, e := Target(link, "ntwire")
		if e != nil || got != p {
			t.Fatal(got, e)
		}
	}
	if e := Writable(filepath.Join(dir, "missing", "ntwire")); e == nil {
		t.Fatal("accepted unwritable/missing parent")
	}
}

func TestHelperResultDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0600)
	result := filepath.Join(dir, "result.json")
	if runtime.GOOS != "windows" {
		if e := os.Symlink(victim, result); e != nil {
			t.Fatal(e)
		}
		if e := writeHelperResult(result, []byte("error")); e == nil {
			t.Fatal("followed result symlink")
		}
		b, _ := os.ReadFile(victim)
		if string(b) != "keep" {
			t.Fatal("modified symlink target")
		}
		os.Remove(result)
	}
	os.WriteFile(result, []byte(`{}`), 0600)
	if e := writeHelperResult(result, []byte(`{"installed":"1.2.3"}`)); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(result)
	if string(b) != `{"installed":"1.2.3"}` {
		t.Fatal(string(b))
	}
}
