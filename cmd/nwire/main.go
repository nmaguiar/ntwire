package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/nmaguiar/nwire/pkg/client"
	"github.com/nmaguiar/nwire/pkg/sshkey"
	"golang.org/x/crypto/ssh"
	"os"
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
	case "list", "connect":
		list(os.Args[2:])
	default:
		usage()
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: nwire <keygen|list|connect|version>")
}
func list(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	key := fs.String("i", "", "SSH private key")
	fs.Parse(args)
	if *key == "" || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: nwire list -i key https://server:8443")
		os.Exit(2)
	}
	r, err := client.Authenticate(fs.Arg(0), *key, client.BuiltinInfo())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, t := range r.Tunnels {
		fmt.Printf("%-20s %5d  %s\n", t.Name, t.VirtualPort, t.Description)
	}
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
