package protocol

const (
	CapabilityMASQUECarrierV1 = "masque-carrier-v1"
	CarrierHTTP3              = "h3-connect-udp"
	CarrierHTTP3Path          = "/.well-known/masque/udp/wireguard.invalid/51820/"
	CarrierLaneHeader         = "Ntwire-Carrier-Lane"

	CapabilityHTTP2CarrierV1 = "http2-carrier-v1"
	CarrierHTTP2             = "http2-framed"
	CarrierHTTP2Media        = "application/vnd.ntwire.wg-datagrams"
)
