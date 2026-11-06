package web_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var windowsInstallers = map[string]string{
	"get.bat":        "ntwire",
	"get-server.bat": "ntwire-server",
	"get-relay.bat":  "ntwire-relay",
	"get-gui.bat":    "ntwire-gui",
}

func TestWindowsInstallers_QuotedPipelines(t *testing.T) {
	for name := range windowsInstallers {
		t.Run(name, func(t *testing.T) {
			script, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			// cmd.exe preserves carets inside the quoted -Command argument.
			if bytes.Contains(script, []byte("^|")) {
				t.Fatal("caret-escaped pipeline reaches PowerShell as an invalid token")
			}
		})
	}
}

func TestWindowsInstallers_InstallAndChecksumFailures(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("requires cmd.exe and Windows PowerShell")
	}
	// Exercise the real batch/PowerShell parsing boundary while replacing only
	// HTTP calls. Downloads, hashing, extraction and error exits use real files.
	const mockHTTP = `function Invoke-RestMethod { param([switch]$UseBasicParsing, [string]$Uri) Get-Content -Raw -LiteralPath (Join-Path $env:NTWIRE_INSTALLER_FIXTURE 'release.json') | ConvertFrom-Json }; function Invoke-WebRequest { param([switch]$UseBasicParsing, [string]$Uri, [string]$OutFile) if($Uri -eq 'https://example.invalid/archive'){Copy-Item -LiteralPath (Join-Path $env:NTWIRE_INSTALLER_FIXTURE 'fixture.zip') -Destination $OutFile} elseif($Uri -eq 'https://example.invalid/sums'){@{Content=(Get-Content -Raw -LiteralPath (Join-Path $env:NTWIRE_INSTALLER_FIXTURE 'checksums.txt'))}} else {throw 'Unexpected URL'} }; `
	for scriptName, bin := range windowsInstallers {
		for _, arch := range []string{"amd64", "arm64"} {
			for _, scenario := range []string{"success", "incompatible-modules", "mismatch", "missing-manifest", "missing-entry"} {
				t.Run(scriptName+"/"+arch+"/"+scenario, func(t *testing.T) {
					dir := filepath.Join(t.TempDir(), "fixture with spaces")
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
					write := func(name string, data []byte) {
						t.Helper()
						if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					var archive bytes.Buffer
					zw := zip.NewWriter(&archive)
					entry, err := zw.Create(bin + ".exe")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := entry.Write([]byte("installer fixture")); err != nil {
						t.Fatal(err)
					}
					if err := zw.Close(); err != nil {
						t.Fatal(err)
					}
					write("fixture.zip", archive.Bytes())
					assetName := bin + "_v1.2.3_windows_" + arch + ".zip"
					assets := []map[string]string{{"name": assetName, "browser_download_url": "https://example.invalid/archive"}}
					if scenario != "missing-manifest" {
						assets = append(assets, map[string]string{"name": "checksums.txt", "browser_download_url": "https://example.invalid/sums"})
					}
					release, err := json.Marshal(map[string]any{"assets": assets})
					if err != nil {
						t.Fatal(err)
					}
					write("release.json", release)
					hash := fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))
					if scenario == "mismatch" {
						hash = strings.Repeat("0", 64)
					}
					if scenario == "missing-entry" {
						assetName = "another.zip"
					}
					write("checksums.txt", []byte("unrelated  other.zip\r\n"+hash+"  "+assetName+"\r\n"))
					script, err := os.ReadFile(scriptName)
					if err != nil {
						t.Fatal(err)
					}
					const command = "-Command \""
					if strings.Count(string(script), command) != 1 {
						t.Fatal("expected one quoted PowerShell command")
					}
					write("install.bat", []byte(strings.Replace(string(script), command, command+mockHTTP, 1)))
					t.Setenv("NTWIRE_INSTALLER_FIXTURE", dir)
					t.Setenv("LOCALAPPDATA", filepath.Join(dir, "app data"))
					t.Setenv("TEMP", dir)
					t.Setenv("PROCESSOR_ARCHITECTURE", strings.ToUpper(arch))
					if scenario == "incompatible-modules" {
						// Model a newer PowerShell module shadowing the Windows
						// PowerShell built-in, even when the test starts outside pwsh.
						module := filepath.Join("modules", "Microsoft.PowerShell.Utility")
						if err := os.MkdirAll(filepath.Join(dir, module), 0700); err != nil {
							t.Fatal(err)
						}
						write(filepath.Join(module, "Microsoft.PowerShell.Utility.psd1"), []byte("@{ RootModule='Microsoft.PowerShell.Utility.psm1'; ModuleVersion='1.0'; PowerShellVersion='99.0'; FunctionsToExport=@('Get-FileHash') }"))
						write(filepath.Join(module, "Microsoft.PowerShell.Utility.psm1"), []byte("function Get-FileHash { throw 'Incompatible module loaded' }"))
						t.Setenv("PSModulePath", filepath.Join(dir, "modules"))
						// Confirm that the fixture actually breaks command discovery
						// before checking that the batch installer repairs it.
						probe := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-Command Get-FileHash -ErrorAction Stop")
						output, err := probe.CombinedOutput()
						if err == nil || !strings.Contains(string(output), "Get-FileHash") {
							t.Fatalf("expected incompatible module discovery to fail, got %v\n%s", err, output)
						}
					}
					cmd := exec.Command("cmd.exe", "/d", "/c", "install.bat")
					cmd.Dir = dir
					output, runErr := cmd.CombinedOutput()
					installed := filepath.Join(dir, "app data", "ntwire", "bin", bin+".exe")
					if scenario == "success" || scenario == "incompatible-modules" {
						if runErr != nil {
							t.Fatalf("install failed: %v\n%s", runErr, output)
						}
						data, err := os.ReadFile(installed)
						if err != nil || string(data) != "installer fixture" {
							t.Fatalf("installed content = %q, error = %v", data, err)
						}
					} else {
						message := map[string]string{"mismatch": "Checksum mismatch", "missing-manifest": "no checksums.txt", "missing-entry": "does not list"}[scenario]
						if runErr == nil || !strings.Contains(string(output), message) {
							t.Fatalf("expected %q failure, got %v\n%s", message, runErr, output)
						}
						if _, err := os.Stat(installed); !os.IsNotExist(err) {
							t.Fatalf("unverified binary installed: %v", err)
						}
					}
					if _, err := os.Stat(filepath.Join(dir, bin+".zip")); !os.IsNotExist(err) {
						t.Fatalf("download not cleaned up: %v", err)
					}
				})
			}
		}
	}
}
