package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nmaguiar/ntwire/pkg/buildinfo"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Target resolves the complete bundle on macOS and refuses managed installations.
func Target(executable, product string) (string, error) {
	p, e := filepath.Abs(executable)
	if e != nil {
		return "", e
	}
	p, e = filepath.EvalSymlinks(p)
	if e != nil {
		return "", e
	}
	slash := filepath.ToSlash(p)
	for _, prefix := range []string{"/nix/", "/snap/", "/var/lib/flatpak/", "/app/", "/opt/homebrew/Cellar/", "/usr/local/Cellar/", "/opt/homebrew/Caskroom/", "/usr/local/Caskroom/"} {
		if strings.HasPrefix(slash, prefix) {
			return "", errors.New("package-managed installation: upgrade with the package manager (brew upgrade, snap refresh, flatpak update, or nix profile upgrade)")
		}
	}
	if strings.Contains(strings.ToLower(slash), "/scoop/") || strings.Contains(strings.ToLower(slash), "/chocolatey/") {
		return "", errors.New("package-managed installation: use scoop update or choco upgrade")
	}
	if runtime.GOOS == "linux" {
		for _, cmd := range [][]string{{"dpkg-query", "-S", p}, {"rpm", "-qf", p}, {"pacman", "-Qo", p}} {
			if exec.Command(cmd[0], cmd[1:]...).Run() == nil {
				return "", errors.New("package-managed installation: use apt, dnf, or pacman to upgrade ntwire")
			}
		}
	}
	if product == "ntwire-gui" && runtime.GOOS == "darwin" {
		suffix := "/ntwire-gui.app/Contents/MacOS/ntwire-gui"
		if !strings.HasSuffix(slash, suffix) {
			return "", errors.New("macOS GUI updates require a standalone ntwire-gui.app bundle")
		}
		p = strings.TrimSuffix(p, filepath.FromSlash("/Contents/MacOS/ntwire-gui"))
	}
	if strings.Contains(slash, "/AppTranslocation/") {
		return "", errors.New("move the app to Applications before updating")
	}
	if filepath.Base(p) != expectedTarget(Asset{Product: product, OS: runtime.GOOS}) {
		return "", errors.New("standalone updates require the original distributed application name")
	}
	return p, nil
}
func Writable(target string) error {
	f, e := os.CreateTemp(filepath.Dir(target), ".ntwire-write-*")
	if e != nil {
		return fmt.Errorf("installation needs administrator access or a writable location: %w", e)
	}
	f.Close()
	return os.Remove(f.Name())
}
func hashFile(file string) (string, int64, error) {
	f, e := os.Open(file)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, e
}

// extract accepts only regular files/directories. Links, special files, duplicate
// paths, traversal and unexpected executables are rejected before replacement.
func extract(archive, dir string, a Asset) (string, error) {
	bundle := a.Product == "ntwire-gui" && a.OS == "darwin"
	binary := a.Product
	if a.OS == "windows" {
		binary += ".exe"
	}
	root := binary
	if bundle {
		root = "ntwire-gui.app"
	}
	seen := map[string]bool{}
	var total int64
	files := 0
	entry := func(name string, size int64, mode os.FileMode, reader io.Reader) error {
		if strings.Contains(name, "\\") || strings.Contains(name, ":") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") || name == "." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		name = strings.TrimSuffix(name, "/")
		key := strings.ToLower(name)
		if seen[key] {
			return errors.New("duplicate archive path")
		}
		seen[key] = true
		files++
		total += size
		if files > 10000 || size < 0 || total > maxArchive {
			return errors.New("expanded archive too large")
		}
		if mode&os.ModeSymlink != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return errors.New("archive contains a link or special file")
		}
		// GoReleaser includes repository documentation. ditto includes resource forks.
		if !bundle && name != binary {
			if !strings.Contains(name, "/") && (name == "LICENSE" || name == "LICENSE.md" || strings.HasPrefix(name, "README")) {
				return nil
			}
			return fmt.Errorf("unexpected archive content %q", name)
		}
		if bundle && name != root && !strings.HasPrefix(name, root+"/") {
			if name == "__MACOSX" || strings.HasPrefix(name, "__MACOSX/") {
				return nil
			}
			return fmt.Errorf("unexpected bundle content %q", name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if mode.IsDir() {
			return os.MkdirAll(dst, 0755)
		}
		if e := os.MkdirAll(filepath.Dir(dst), 0755); e != nil {
			return e
		}
		perm := os.FileMode(0644)
		if name == binary || strings.Contains(name, "/Contents/MacOS/") || mode&0111 != 0 {
			perm = 0755
		}
		f, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if e != nil {
			return e
		}
		n, e := io.Copy(f, io.LimitReader(reader, size+1))
		if e == nil && n != size {
			e = errors.New("archive entry size mismatch")
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		return e
	}
	if strings.HasSuffix(a.Name, ".zip") {
		z, e := zip.OpenReader(archive)
		if e != nil {
			return "", e
		}
		defer z.Close()
		for _, f := range z.File {
			if f.UncompressedSize64 > maxArchive {
				return "", errors.New("archive entry too large")
			}
			r, e := f.Open()
			if e != nil {
				return "", e
			}
			e = entry(f.Name, int64(f.UncompressedSize64), f.Mode(), r)
			r.Close()
			if e != nil {
				return "", e
			}
		}
	} else {
		f, e := os.Open(archive)
		if e != nil {
			return "", e
		}
		defer f.Close()
		gz, e := gzip.NewReader(f)
		if e != nil {
			return "", e
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return "", e
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
				return "", errors.New("archive contains non-regular entry")
			}
			if e = entry(h.Name, h.Size, h.FileInfo().Mode(), tr); e != nil {
				return "", e
			}
		}
	}
	required := filepath.Join(dir, root)
	bin := required
	if bundle {
		bin = filepath.Join(required, "Contents", "MacOS", "ntwire-gui")
		if _, e := os.Stat(filepath.Join(required, "Contents", "Info.plist")); e != nil {
			return "", errors.New("bundle missing Info.plist")
		}
	}
	info, e := os.Stat(bin)
	if e != nil || !info.Mode().IsRegular() {
		return "", errors.New("archive missing application executable")
	}
	return required, nil
}

type Job struct {
	Release Release `json:"release"`
	Archive string  `json:"archive"`
	Target  string  `json:"target"`
	Current string  `json:"current"`
	Parent  int     `json:"parent"`
	Result  string  `json:"result"`
}

// VerifyArchive checks cached/staged evidence without trusting persisted fields.
func (c *Client) VerifyArchive(r *Release, file string) error {
	m, e := Verify(r.Raw, r.Signature, c.Key)
	if e != nil {
		return e
	}
	found := false
	for _, a := range m.Assets {
		if a == r.Asset {
			found = true
		}
	}
	if !found {
		return errors.New("asset is not in signed manifest")
	}
	h, n, e := hashFile(file)
	if e != nil {
		return e
	}
	if h != r.Asset.SHA256 || n != r.Asset.Size {
		return errors.New("staged archive hash or size mismatch")
	}
	return nil
}

// Install re-verifies the signed archive, extracts on the target filesystem,
// serializes replacement, and retains a previous installation for recovery.
func (c *Client) Install(j Job) error {
	if e := CanInstall(j.Current); e != nil {
		return e
	}
	m, e := Verify(j.Release.Raw, j.Release.Signature, c.Key)
	if e != nil {
		return e
	}
	newer, e := Newer(m.Version, j.Current)
	if e != nil || !newer {
		return errors.New("refusing downgrade or equal version")
	}
	a := j.Release.Asset
	ok := false
	for _, x := range m.Assets {
		if x == a {
			ok = true
		}
	}
	if !ok || a.OS != runtime.GOOS || a.Arch != runtime.GOARCH {
		return errors.New("incorrect install asset")
	}
	if !filepath.IsAbs(j.Target) || filepath.Base(j.Target) != expectedTarget(a) {
		return errors.New("invalid installation target")
	}
	info, e := os.Lstat(j.Target)
	if e != nil {
		return e
	}
	if info.Mode()&os.ModeSymlink != 0 || (info.IsDir() != (a.Product == "ntwire-gui" && a.OS == "darwin")) {
		return errors.New("target type changed")
	}
	lock := j.Target + ".update-lock"
	if e = os.Mkdir(lock, 0700); e != nil {
		return fmt.Errorf("installation locked (%s); if no updater is running, remove this directory: %w", lock, e)
	}
	defer os.Remove(lock)
	h, n, e := hashFile(j.Archive)
	if e != nil {
		return e
	}
	if h != a.SHA256 || n != a.Size {
		return errors.New("staged archive hash or size mismatch")
	}
	// Copy verified bytes into the destination filesystem and re-hash that private
	// snapshot before extraction, including when invoked with elevated privileges.
	dir, e := os.MkdirTemp(filepath.Dir(j.Target), ".ntwire-update-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	snapshot := filepath.Join(dir, "archive")
	src, e := os.Open(j.Archive)
	if e != nil {
		return e
	}
	dst, e := os.OpenFile(snapshot, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		src.Close()
		return e
	}
	_, e = io.Copy(dst, io.LimitReader(src, a.Size+1))
	src.Close()
	ce := dst.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	h, n, e = hashFile(snapshot)
	if e != nil || h != a.SHA256 || n != a.Size {
		return errors.New("staged archive changed")
	}
	staged, e := extract(snapshot, dir, a)
	if e != nil {
		return e
	}
	previous := j.Target + ".previous-" + strings.TrimPrefix(j.Current, "v")
	if _, e = os.Lstat(previous); e == nil {
		return fmt.Errorf("previous installation already exists at %s; move or remove it before updating", previous)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return replace(j.Target, staged, previous, os.Rename)
}
func expectedTarget(a Asset) string {
	if a.Product == "ntwire-gui" && a.OS == "darwin" {
		return "ntwire-gui.app"
	}
	n := a.Product
	if a.OS == "windows" {
		n += ".exe"
	}
	return n
}
func replace(target, staged, previous string, rename func(string, string) error) error {
	if e := rename(target, previous); e != nil {
		return e
	}
	if e := rename(staged, target); e != nil {
		if rollback := rename(previous, target); rollback != nil {
			return fmt.Errorf("replacement failed: %v; restore %s manually: %w", e, previous, rollback)
		}
		return fmt.Errorf("replacement failed; previous installation restored: %w", e)
	}
	return nil
}

// StartHelper copies the running binary so Windows can release its executable
// lock. The helper waits for the parent to exit and never relaunches the app.
func StartHelper(j Job, dir string, elevate bool) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	runDir, e := os.MkdirTemp(dir, "helper-*")
	if e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	name := "update-helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	helper := filepath.Join(runDir, name)
	in, e := os.Open(self)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(helper, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if e != nil {
		return e
	}
	helperHash := sha256.New()
	_, e = io.Copy(io.MultiWriter(out, helperHash), in)
	ce := out.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	// Pre-create the result as the invoking user, preserving readability after elevation.
	if j.Result != "" {
		if e = os.WriteFile(j.Result, []byte(`{}`), 0600); e != nil {
			return e
		}
	}
	j.Parent = os.Getpid()
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	job := filepath.Join(runDir, "job.json")
	if e = os.WriteFile(job, b, 0600); e != nil {
		return e
	}
	if elevate {
		if runtime.GOOS != "windows" {
			helper = self
		} // Execute the protected installed image on Unix.
		return startElevated(helper, job, hex.EncodeToString(helperHash.Sum(nil)))
	}
	cmd := exec.Command(helper, "--internal-update", job)
	if e = cmd.Start(); e != nil {
		return e
	}
	go cmd.Wait()
	return nil
}

// writeHelperResult never follows a substituted result-file symlink. Preserve
// the pre-created user's ownership when an elevated helper reports its result.
func writeHelperResult(file string, data []byte) error {
	info, e := os.Lstat(file)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("unsafe helper result file")
	}
	f, e := os.CreateTemp(filepath.Dir(file), ".result-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = resultOwner(f, info); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), file)
}

// RunHelper is invoked before ordinary CLI/GUI parsing. Its only input is a
// private job file; release evidence is always checked again before replacement.
func RunHelper(job string) error {
	b, e := os.ReadFile(job)
	if e != nil {
		return e
	}
	var j Job
	if e = json.Unmarshal(b, &j); e != nil {
		return e
	}
	if j.Current != buildinfo.String() {
		return errors.New("helper version does not match installation request")
	}
	if _, e = Verify(j.Release.Raw, j.Release.Signature, NewClient().Key); e != nil {
		return e
	}
	if e = os.WriteFile(job+".ready", []byte("ready"), 0600); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e = waitForExit(ctx, j.Parent)
	if e == nil {
		e = NewClient().Install(j)
	}
	if j.Result != "" {
		result := struct {
			Error     string `json:"error"`
			Installed string `json:"installed"`
		}{Installed: j.Release.Manifest.Version}
		if e != nil {
			result.Error = e.Error()
			result.Installed = ""
		}
		data, _ := json.Marshal(result)
		_ = writeHelperResult(j.Result, data)
	}
	return e
}
