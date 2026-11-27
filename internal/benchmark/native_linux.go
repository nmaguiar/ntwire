package benchmark

import (
	"errors"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (f *fixture) startKernelClient(state fixtureState) error {
	// The namespace launcher creates this interface and its single host route.
	const name = "benchwg"
	peer := net.IPNet{IP: net.ParseIP(nativeServerIP).To4(), Mask: net.CIDRMask(32, 32)}
	private, err := wgtypes.ParseKey(state.WireClientKey)
	if err != nil {
		return err
	}
	server, err := wgtypes.ParseKey(state.WireServerKey)
	if err != nil {
		return err
	}
	endpoint, err := net.ResolveUDPAddr("udp4", state.WireEndpoint)
	if err != nil {
		return err
	}
	control, err := wgctrl.New()
	if err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = control.Close() })
	device, err := control.Device(name)
	if err != nil {
		return err
	}
	if device.Type != wgtypes.LinuxKernel || len(device.Peers) != 0 {
		return errors.New("expected a fresh Linux kernel WireGuard fixture device")
	}
	if err := control.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &private, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{PublicKey: server, Endpoint: endpoint, AllowedIPs: []net.IPNet{peer}}},
	}); err != nil {
		return err
	}
	f.nativeDial = (&net.Dialer{}).DialContext
	f.nativeProof = func() error {
		device, err := control.Device(name)
		if err != nil {
			return err
		}
		if len(device.Peers) != 1 || device.Peers[0].PublicKey != server ||
			device.Peers[0].LastHandshakeTime.IsZero() || device.Peers[0].ReceiveBytes == 0 || device.Peers[0].TransmitBytes == 0 {
			return errors.New("kernel WireGuard did not report a handshake and bidirectional traffic")
		}
		return nil
	}
	return nil
}
