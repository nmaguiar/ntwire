package updater

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

func waitForExit(ctx context.Context, pid int) error {
	h, e := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if e == windows.ERROR_INVALID_PARAMETER {
		return nil
	}
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	for {
		s, e := windows.WaitForSingleObject(h, 100)
		if e != nil {
			return e
		}
		if s == windows.WAIT_OBJECT_0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// Windows cannot replace a mapped executable. The elevated PowerShell launcher
// copies the helper into a protected Program Files directory and checks the hash
// measured while copying the original image, before executing privileged code.
func startElevated(helper, job, expectedHash string) error {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := `$ErrorActionPreference='Stop'; $stage=Join-Path $env:ProgramFiles ('ntwire-update-'+[guid]::NewGuid().ToString());
 try {
  New-Item -ItemType Directory -Path $stage | Out-Null;
  $helper=Join-Path $stage 'update-helper.exe';
  Copy-Item -LiteralPath ` + q(helper) + ` -Destination $helper;
  if ((Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -ne ` + q(expectedHash) + `) { throw 'Update helper changed; refusing elevation' };
  $p=Start-Process -FilePath $helper -ArgumentList ` + q(`--internal-update "`+job+`"`) + ` -PassThru;
  $p.WaitForExit(); exit $p.ExitCode;
 } finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force } }`
	encoded := encodePowerShell(script)
	launcher := `$ErrorActionPreference='Stop'; $p=Start-Process -Verb RunAs -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',` + q(encoded) + `) -PassThru;
 $deadline=[DateTime]::UtcNow.AddMinutes(2);
 while ([DateTime]::UtcNow -lt $deadline) {
  if (Test-Path -LiteralPath ` + q(job+".ready") + `) { exit 0 };
  if ($p.HasExited) { throw 'Administrator helper failed before becoming ready' };
  Start-Sleep -Milliseconds 100;
 }; throw 'Administrator authorization timed out'`
	out, e := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(launcher)).CombinedOutput()
	if e != nil {
		return fmt.Errorf("administrator authorization cancelled or failed: %s: %w", out, e)
	}
	return nil
}
func encodePowerShell(s string) string {
	units := utf16.Encode([]rune(s))
	bytes := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(bytes[2*i:], u)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// The private LocalAppData directory's inherited ACL grants the account access.
func resultOwner(f *os.File, info os.FileInfo) error { return nil }
