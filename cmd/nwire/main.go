package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/nmaguiar/nwire/pkg/client"
	"github.com/nmaguiar/nwire/pkg/protocol"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "keygen":
		keygen(os.Args[2:])
	case "list":
		list(os.Args[2:])
	case "connect":
		connect(os.Args[2:])
	default:
		usage()
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: nwire <keygen|list|connect|version>")
}
func connect(args []string) {
	settings, configPath := settingsFor(args)
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	fs.String("config", configPath, "persistent client configuration")
	key := fs.String("i", settings.IdentityFile, "SSH private key")
	ca := fs.String("ca", settings.CAFile, "PEM CA certificate")
	insecure := fs.Bool("insecure", settings.Insecure, "skip TLS certificate verification")
	known := fs.String("known-servers", "", "known servers file")
	noBrowser := fs.Bool("no-browser", settings.NoBrowser, "do not open the local status UI in a browser")
	collect := fs.String("collect-exec", settings.CollectExec, "command that emits JSON client-info fields")
	mappings := multiFlag{}
	fs.Var(&mappings, "port", "name=local-port (repeatable)")
	fs.Parse(args)
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	if *key == "" || server == "" || fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: nwire connect -i key [--port name=15432] https://server:8443")
		os.Exit(2)
	}
	ports := map[string]int{}
	for n, p := range settings.Ports {
		ports[n] = p
	}
	for _, m := range mappings {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "invalid --port")
			os.Exit(2)
		}
		var p int
		if _, e := fmt.Sscanf(parts[1], "%d", &p); e != nil || p < 1 || p > 65535 {
			fmt.Fprintln(os.Stderr, "invalid --port")
			os.Exit(2)
		}
		ports[parts[0]] = p
	}
	info, e := collectedInfo(*collect)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	o := client.Options{Ports: ports, CAFile: *ca, Insecure: *insecure, KnownServersFile: *known, NoWebUI: *noBrowser}
	c, e := client.ConnectWithOptions(server, *key, info, o)
	var unknown *client.UnknownCertificateError
	if errors.As(e, &unknown) {
		if !trustPrompt(unknown, *known) {
			fmt.Fprintln(os.Stderr, "server certificate was not trusted")
			os.Exit(1)
		}
		c, e = client.ConnectWithOptions(server, *key, info, o)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer c.Close()
	for i, t := range c.Response.Tunnels {
		fmt.Printf("%s  %s\n", t.Name, c.LocalAddresses[i])
	}
	fmt.Println("connected; press Ctrl-C to disconnect")
	if c.UIURL != "" {
		fmt.Println("status:", c.UIURL)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
func list(args []string) {
	settings, configPath := settingsFor(args)
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.String("config", configPath, "persistent client configuration")
	key := fs.String("i", settings.IdentityFile, "SSH private key")
	ca := fs.String("ca", settings.CAFile, "PEM CA certificate")
	insecure := fs.Bool("insecure", settings.Insecure, "skip TLS certificate verification")
	known := fs.String("known-servers", "", "known servers file")
	collect := fs.String("collect-exec", settings.CollectExec, "command that emits JSON client-info fields")
	fs.Parse(args)
	server := settings.Server
	if fs.NArg() == 1 {
		server = fs.Arg(0)
	}
	if *key == "" || server == "" || fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: nwire list -i key https://server:8443")
		os.Exit(2)
	}
	info, err := collectedInfo(*collect)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o := client.Options{CAFile: *ca, Insecure: *insecure, KnownServersFile: *known}
	r, err := client.AuthenticateWithOptions(server, *key, info, o)
	var unknown *client.UnknownCertificateError
	if errors.As(err, &unknown) {
		if !trustPrompt(unknown, *known) {
			fmt.Fprintln(os.Stderr, "server certificate was not trusted")
			os.Exit(1)
		}
		r, err = client.AuthenticateWithOptions(server, *key, info, o)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, t := range r.Tunnels {
		fmt.Printf("%-20s %5d  %s\n", t.Name, t.VirtualPort, t.Description)
	}
}

func settingsFor(args []string) (client.Settings, string) {
	path := client.DefaultConfigFile()
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			path = args[i+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			path = strings.TrimPrefix(arg, "--config=")
		}
	}
	s, err := client.LoadSettings(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client configuration:", err)
		os.Exit(2)
	}
	return s, path
}

func collectedInfo(command string) (protocol.ClientInfo, error) {
	info := client.BuiltinInfo()
	if command == "" {
		return info, nil
	}
	v, err := (client.ExecCollector{Command: command}).Collect()
	if err != nil {
		return info, fmt.Errorf("collect-exec: %w", err)
	}
	for k, x := range v {
		info.Extra[k] = x
	}
	return info, nil
}

func trustPrompt(e *client.UnknownCertificateError, path string) bool {
	fmt.Fprintf(os.Stderr, "Trust server %s certificate %s? [y/N] ", e.Host, e.Fingerprint)
	var answer string
	if _, err := fmt.Fscan(os.Stdin, &answer); err != nil || strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes" {
		return false
	}
	if err := client.TrustServer(path, e.Host, e.Fingerprint); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	return true
}
func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", "nwire_ed25519", "private key output")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		panic(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(*out+".pub", ssh.MarshalAuthorizedKey(k), 0644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s (%s)\n", *out, sshkey.Fingerprint(k))
}
