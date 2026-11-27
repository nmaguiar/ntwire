package benchmark

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/nmaguiar/ntwire/pkg/server"
	"github.com/nmaguiar/ntwire/pkg/wgnet"
	"golang.zx2c4.com/wireguard/conn"
)

// A native peer uses the upstream WireGuard UDP bind and no ntwire
// client control connection or local port forwarder.
const nativeServerIP, nativeClientIP = "100.70.0.1", "100.70.0.2"

func nativeTransport(transport string) bool {
	return transport == "native-wireguard-go" || transport == "native-wireguard-kernel"
}

func (f *fixture) startNativeServer(cfg server.Config, dir, endpoint string, port int, state *fixtureState) error {
	serverKey, err := wgnet.GenerateKey()
	if err != nil {
		return err
	}
	clientKey, err := wgnet.GenerateKey()
	if err != nil {
		return err
	}
	cfg.Network.WireGuardPrivateKeyFile = filepath.Join(dir, "wireguard.key")
	if err = os.WriteFile(cfg.Network.WireGuardPrivateKeyFile, []byte(serverKey.Private), 0600); err != nil {
		return err
	}
	cfg.NativeWireGuard.Enabled = true
	cfg.NativeWireGuard.Peers = []server.NativeWireGuardPeer{{
		Name: "benchmark", PublicKey: clientKey.Public, TunnelIP: nativeClientIP, Tunnels: []string{"benchmark"},
	}}
	f.server = server.New(cfg, slog.New(slog.DiscardHandler))
	if err = f.server.StartDataPlane(); err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, f.server.Close)
	state.WireEndpoint = endpoint
	state.WireServerKey = serverKey.Public
	state.WireClientKey = clientKey.Private
	state.WireTarget = net.JoinHostPort(nativeServerIP, fmt.Sprint(port))
	return nil
}

func (f *fixture) startNativeClient(o Options, state fixtureState) error {
	f.address = state.WireTarget
	f.nativePath = o.Transport
	if o.Transport == "native-wireguard-kernel" {
		return f.startKernelClient(state)
	}
	if f.topology == "loopback" {
		f.topology = "loopback-native-wireguard-go"
	}
	stack, err := wgnet.New(wgnet.Config{
		PrivateKey: state.WireClientKey,
		Addresses:  []netip.Addr{netip.MustParseAddr(nativeClientIP)},
		Bind:       conn.NewStdNetBind(),
	})
	if err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = stack.Close() })
	if err = stack.AddPeer(wgnet.Endpoint{PublicKey: state.WireServerKey, Address: nativeServerIP + "/32@" + state.WireEndpoint}); err != nil {
		return err
	}
	f.nativeDial = stack.DialContext
	return nil
}
