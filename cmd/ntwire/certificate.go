package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nmaguiar/ntwire/pkg/client"
)

func certCmd(args []string) {
	code := runCertInspect(args, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

// Exit codes: 0 matching pin without identity/validity warnings; 1 connection
// or argument error; 2 unpinned, changed, or diagnostic warnings. Never trusts.
func runCertInspect(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(errOut, "Usage: ntwire cert inspect [options] https://server.example.com")
		return 1
	}
	fs := flag.NewFlagSet("cert inspect", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOutput := fs.Bool("json", false, "emit JSON")
	known := fs.String("known-servers", "", "known_servers file (read only)")
	proxy := fs.String("https-proxy", "", "HTTP, HTTPS, SOCKS5 or SOCKS5H proxy, as for connect")
	noSystem := fs.Bool("no-system-proxy", false, "ignore system proxy environment")
	ip := fs.String("ip-version", "", "prefer only IP version 4 or 6")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 1
	}
	result, err := client.InspectCertificate(context.Background(), fs.Arg(0), client.Options{KnownServersFile: *known, HTTPSProxy: *proxy, NoSystemProxy: *noSystem, IPVersion: *ip})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
	} else {
		client.WriteCertificateSummary(out, result.Host, result.Fingerprint, result.Previous, result.Certificate, &result.Assessment)
		fmt.Fprintf(out, "Previously pinned: %t\nFingerprint match: %t\n", result.PreviouslyPinned, result.FingerprintMatch)
	}
	if !result.FingerprintMatch {
		return 2
	}
	for _, indicator := range result.Assessment.Indicators {
		if indicator != "self_signed" {
			return 2
		}
	}
	return 0
}
