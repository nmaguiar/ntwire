package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nmaguiar/ntwire/pkg/buildinfo"
)

// Re-executed copies exercise native executable locking and parent exit without
// touching a real installation or requesting administrator access.
func TestNativeUpdateProcess(t *testing.T) {
	switch os.Getenv("NTWIRE_UPDATE_TEST_MODE") {
	case "parent":
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "helper":
		PublicKey = os.Getenv("NTWIRE_UPDATE_TEST_KEY")
		buildinfo.Version = "1.0.0"
		if e := RunHelper(os.Getenv("NTWIRE_UPDATE_TEST_JOB")); e != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}
func TestNativeHelperWaitsBeforeReplacingExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := "ntwire"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	target := filepath.Join(dir, exe)
	src, e := os.Open(os.Args[0])
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if e != nil {
		t.Fatal(e)
	}
	_, e = io.Copy(f, src)
	src.Close()
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	parent := exec.Command(target, "-test.run=^TestNativeUpdateProcess$")
	parent.Env = append(os.Environ(), "NTWIRE_UPDATE_TEST_MODE=parent")
	stdin, e := parent.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = parent.Start(); e != nil {
		t.Fatal(e)
	}
	defer parent.Process.Kill()
	a := Asset{Product: "ntwire", OS: runtime.GOOS, Arch: runtime.GOARCH}
	a.Name, _ = AssetName(a.Product, "1.2.3", a.OS, a.Arch)
	body := archiveBytes(t, a, []string{exe}, false)
	c, r := signedRelease(t, body)
	// Re-sign using a known ephemeral key shared only with the test helper.
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c.Key = pub
	r.Signature = ed25519.Sign(key, r.Raw)
	archive := filepath.Join(dir, r.Asset.Name)
	os.WriteFile(archive, body, 0600)
	result := filepath.Join(dir, "result.json")
	os.WriteFile(result, []byte(`{}`), 0600)
	jobPath := filepath.Join(dir, "job.json")
	j := Job{Release: *r, Archive: archive, Target: target, Current: "1.0.0", Parent: parent.Process.Pid, Result: result}
	b, _ := json.Marshal(j)
	os.WriteFile(jobPath, b, 0600)
	helper := exec.Command(os.Args[0], "-test.run=^TestNativeUpdateProcess$")
	helper.Env = append(os.Environ(), "NTWIRE_UPDATE_TEST_MODE=helper", "NTWIRE_UPDATE_TEST_KEY="+base64.StdEncoding.EncodeToString(pub), "NTWIRE_UPDATE_TEST_JOB="+jobPath)
	if e = helper.Start(); e != nil {
		t.Fatal(e)
	}
	defer helper.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, e = os.Stat(jobPath + ".ready"); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	originalHash, _, e := hashFile(target)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(body)
	if originalHash == hex.EncodeToString(sum[:]) {
		t.Fatal("replaced a running executable")
	}
	if data, _ := os.ReadFile(result); string(data) != "{}" {
		t.Fatal("helper did not wait for parent")
	}
	stdin.Close()
	if e = parent.Wait(); e != nil {
		t.Fatal(e)
	}
	if e = helper.Wait(); e != nil {
		t.Fatal(e)
	}
	installed, e := os.ReadFile(target)
	if e != nil || string(installed) != "new app" {
		t.Fatalf("replacement: %q %v", installed, e)
	}
	if _, e = os.Stat(target + ".previous-1.0.0"); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(result)
	if e != nil {
		t.Fatal(e)
	}
	var status struct {
		Error     string `json:"error"`
		Installed string `json:"installed"`
	}
	if e = json.Unmarshal(b, &status); e != nil || status.Error != "" || status.Installed != "1.2.3" {
		t.Fatalf("result %s %v", b, e)
	}
}
