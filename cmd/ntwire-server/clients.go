package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/ui"
)

func runClients(args []string, u *ui.UI) int {
	fs := flag.NewFlagSet("clients", flag.ContinueOnError)
	fs.SetOutput(u.Err)
	config := fs.String("config", "ntwire.yaml", "server configuration file")
	asJSON := fs.Bool("json", false, "output in JSON format")
	fs.Usage = func() {
		ui.Spec{
			Tool:     "ntwire-server clients",
			Tagline:  "show live sessions and native WireGuard peers",
			Flags:    ui.FlagsOf(fs),
			Examples: []string{"ntwire-server clients", "ntwire-server clients -config /etc/ntwire/ntwire.yaml -json"},
		}.Fprint(u.Err, u)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		u.Errorf("clients takes no positional arguments")
		return 2
	}
	cfg, err := server.LoadConfig(*config)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			u.Errorf("cannot read server configuration %q: %v", *config, err)
		} else {
			// A YAML diagnostic may contain text from a secret-bearing scalar.
			u.Errorf("cannot load server configuration %q; check it with ntwire-server -check-config", *config)
		}
		return 1
	}
	snapshot, err := queryClients(cfg)
	if err != nil {
		u.Errorf("%v", err)
		return 1
	}
	if *asJSON {
		err = json.NewEncoder(u.Out).Encode(snapshot)
	} else {
		err = printClients(u.Out, snapshot)
	}
	if err != nil {
		u.Errorf("could not write client inventory: %v", err)
		return 1
	}
	return 0
}

func localMetricsAddress(bind string) (string, error) {
	if bind == "" {
		return "", errors.New("listen.metrics is disabled in the server configuration")
	}
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return "", errors.New("listen.metrics must have a host and port, for example 127.0.0.1:9090")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", errors.New("listen.metrics must use a numeric port between 1 and 65535")
	}
	if host == "" || host == "localhost" {
		host = "127.0.0.1"
	} else {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return "", errors.New("listen.metrics must be bound to loopback or a wildcard for local client listing")
		}
		switch {
		case ip.Unmap().IsLoopback():
			host = ip.Unmap().String()
		case ip.Unmap().IsUnspecified() && ip.Unmap().Is4():
			host = "127.0.0.1"
		case ip.IsUnspecified():
			host = "::1"
		default:
			return "", errors.New("listen.metrics must be bound to loopback or a wildcard for local client listing")
		}
	}
	return net.JoinHostPort(host, port), nil
}

func queryClients(cfg server.Config) (server.ClientsSnapshot, error) {
	var snapshot server.ClientsSnapshot
	address, err := localMetricsAddress(cfg.Listen.Metrics)
	if err != nil {
		return snapshot, err
	}
	if cfg.Admin.WebUIToken == "" {
		return snapshot, errors.New("admin.web_ui_token is missing from the server configuration")
	}

	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+address+server.AdminClientsPath, nil)
	if err != nil {
		return snapshot, errors.New("could not construct the local metrics request")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Admin.WebUIToken)
	res, err := client.Do(req)
	if err != nil {
		return snapshot, fmt.Errorf("could not query the local metrics listener at %s: %w", address, err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return snapshot, errors.New("client inventory unavailable; check the running server version, metrics address, and admin.web_ui_token")
	}
	if res.StatusCode != http.StatusOK {
		return snapshot, fmt.Errorf("client inventory request returned HTTP %d", res.StatusCode)
	}
	const maxSnapshotBytes = 32 << 20
	body := &io.LimitedReader{R: res.Body, N: maxSnapshotBytes + 1}
	dec := json.NewDecoder(body)
	if err := dec.Decode(&snapshot); err != nil || snapshot.Sessions == nil || snapshot.WireGuardPeers == nil {
		return snapshot, errors.New("invalid or incomplete client inventory response")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF || body.N == 0 {
		return snapshot, errors.New("invalid or oversized client inventory response")
	}
	return snapshot, nil
}

func printClients(out io.Writer, snapshot server.ClientsSnapshot) error {
	buffer := bufio.NewWriter(out)
	table := tabwriter.NewWriter(buffer, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "Authenticated sessions")
	if len(snapshot.Sessions) == 0 {
		fmt.Fprintln(table, "No unexpired sessions.")
	} else {
		fmt.Fprintln(table, "IDENTITY\tAUTH\tTUNNEL IP\tEXPIRES (UTC)\tTUNNELS\tSESSION ID")
		for _, session := range snapshot.Sessions {
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%d\t%s\n",
				clientTableValue(session.Identity), clientTableValue(session.Method), clientTableValue(session.TunnelIP),
				session.Expires.UTC().Format(time.RFC3339), session.GrantedTunnelCount, clientTableValue(session.SessionID))
		}
	}
	fmt.Fprintln(table, "\nNative WireGuard peers")
	if len(snapshot.WireGuardPeers) == 0 {
		fmt.Fprintln(table, "No enabled native WireGuard peers.")
	} else {
		fmt.Fprintln(table, "NAME\tTUNNEL IP\tLAST HANDSHAKE (UTC)\tSTATUS")
		for _, peer := range snapshot.WireGuardPeers {
			last := "-"
			if peer.LastHandshake != nil {
				last = peer.LastHandshake.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", clientTableValue(peer.Name), clientTableValue(peer.TunnelIP), last, clientTableValue(peer.Status))
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	return buffer.Flush()
}

func clientTableValue(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	return quoted[1 : len(quoted)-1]
}
