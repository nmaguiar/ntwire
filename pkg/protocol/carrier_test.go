package protocol

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCarrierProof() (CarrierProofScope, [32]byte, CarrierProof) {
	return CarrierProofScope{Parent: CarrierID{1}, Lane: CarrierID{2}, Candidate: CarrierID{3},
			AuthGeneration: 4, PathEpoch: 5}, [32]byte{6},
		CarrierProof{Kind: CarrierProbe, Direction: CarrierUpload, Nonce: CarrierID{7}, Size: 1452}
}

func TestCarrierProof_AuthenticatesCompleteProbeAndShortACK(t *testing.T) {
	scope, key, proof := testCarrierProof()
	frame := EncodeCarrierProof(scope, key, proof)
	if len(frame) != int(proof.Size) {
		t.Fatalf("probe size = %d", len(frame))
	}
	if want, ok := CarrierProofCandidate(frame); !ok || want != scope.Candidate {
		t.Fatal("candidate lookup hint was lost")
	}
	if got, ok := DecodeCarrierProof(scope, key, frame); !ok || got != proof {
		t.Fatal("valid proof was rejected")
	}
	proof.Kind = CarrierACK
	ack := EncodeCarrierProof(scope, key, proof)
	if len(ack) != CarrierProofACKSize || len(ack) >= CarrierProofMin {
		t.Fatalf("ACK has unexpected size %d", len(ack))
	}
	if got, ok := DecodeCarrierProof(scope, key, ack); !ok || got != proof {
		t.Fatal("valid short ACK lost the challenged size")
	}
}

func TestCarrierProof_RejectsWrongScopeAndTampering(t *testing.T) {
	scope, key, proof := testCarrierProof()
	frame := EncodeCarrierProof(scope, key, proof)
	for _, wrong := range []CarrierProofScope{
		{Parent: CarrierID{9}, Lane: scope.Lane, Candidate: scope.Candidate, AuthGeneration: 4, PathEpoch: 5},
		{Parent: scope.Parent, Lane: CarrierID{9}, Candidate: scope.Candidate, AuthGeneration: 4, PathEpoch: 5},
		{Parent: scope.Parent, Lane: scope.Lane, Candidate: CarrierID{9}, AuthGeneration: 4, PathEpoch: 5},
		{Parent: scope.Parent, Lane: scope.Lane, Candidate: scope.Candidate, AuthGeneration: 9, PathEpoch: 5},
		{Parent: scope.Parent, Lane: scope.Lane, Candidate: scope.Candidate, AuthGeneration: 4, PathEpoch: 9},
	} {
		if _, ok := DecodeCarrierProof(wrong, key, frame); ok {
			t.Fatal("proof accepted for a different scope")
		}
	}
	if _, ok := DecodeCarrierProof(scope, [32]byte{8}, frame); ok {
		t.Fatal("proof accepted under a different key")
	}
	for _, offset := range []int{0, 4, 5, 6, 22, 38, carrierProofHeader, len(frame) - 1} {
		mutated := bytes.Clone(frame)
		mutated[offset] ^= 1
		if _, ok := DecodeCarrierProof(scope, key, mutated); ok {
			t.Errorf("tampering at offset %d passed verification", offset)
		}
	}
	if _, ok := DecodeCarrierProof(scope, key, frame[:len(frame)-1]); ok {
		t.Fatal("truncated probe passed")
	}
	if _, ok := DecodeCarrierProof(scope, key, append(frame, 0)); ok {
		t.Fatal("oversized proof passed")
	}
}

func FuzzDecodeCarrierProof(f *testing.F) {
	scope, key, proof := testCarrierProof()
	f.Add(EncodeCarrierProof(scope, key, proof))
	proof.Kind = CarrierACK
	f.Add(EncodeCarrierProof(scope, key, proof))
	f.Add([]byte(carrierProofMagic))
	f.Fuzz(func(t *testing.T, frame []byte) {
		if proof, ok := DecodeCarrierProof(scope, key, frame); ok {
			if encoded := EncodeCarrierProof(scope, key, proof); !bytes.Equal(encoded, frame) {
				t.Fatal("accepted frame is not canonical")
			}
		}
	})
}

func TestCarrierChallenge_RequiresExactSourceDirectionAndNonce(t *testing.T) {
	scope, key, _ := testCarrierProof()
	path := CarrierUDPPath{LocalPort: 51820, Remote: netip.MustParseAddrPort("[2001:db8::1]:443")}
	now := time.Unix(100, 0)
	challenge, frame, err := BeginCarrierChallenge(scope, key, path, CarrierUpload, 1452, now)
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := DecodeCarrierProof(scope, key, frame)
	if !ok {
		t.Fatal("initial challenge did not decode")
	}
	proof.Kind = CarrierACK
	ack := EncodeCarrierProof(scope, key, proof)
	wrong := proof
	wrong.Direction = CarrierDownload
	wrongSize := proof
	wrongSize.Size = 1451
	wrongNonce := proof
	wrongNonce.Nonce[0] ^= 1
	for _, p := range []CarrierProof{wrong, wrongSize, wrongNonce} {
		if _, ok := challenge.AcceptACK(path, EncodeCarrierProof(scope, key, p), now.Add(time.Millisecond)); ok {
			t.Fatal("invalid response consumed the challenge")
		}
	}
	for _, offPath := range []CarrierUDPPath{
		{LocalPort: path.LocalPort, Remote: netip.AddrPortFrom(path.Remote.Addr(), 8443)},
		{LocalPort: 443, Remote: path.Remote},
	} {
		if _, ok := challenge.AcceptACK(offPath, ack, now.Add(time.Millisecond)); ok {
			t.Fatal("wrong socket was accepted")
		}
	}

	at := now.Add(27 * time.Millisecond)
	var accepted atomic.Int32
	var receivers sync.WaitGroup
	for range 16 {
		receivers.Go(func() {
			if rtt, ok := challenge.AcceptACK(path, ack, at); ok {
				accepted.Add(1)
				if rtt != 27*time.Millisecond {
					t.Errorf("measured RTT = %v", rtt)
				}
			}
		})
	}
	receivers.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted %d out of 16 repeated ACKs", got)
	}
}

func TestCarrierChallenge_ExpiryConsumesOutstandingNonce(t *testing.T) {
	scope, key, _ := testCarrierProof()
	path := CarrierUDPPath{LocalPort: 51820, Remote: netip.MustParseAddrPort("192.0.2.1:51820")}
	now := time.Unix(100, 0)
	challenge, frame, err := BeginCarrierChallenge(scope, key, path, CarrierDownload, 1452, now)
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := DecodeCarrierProof(scope, key, frame)
	if !ok {
		t.Fatal("initial challenge did not decode")
	}
	proof.Kind = CarrierACK
	ack := EncodeCarrierProof(scope, key, proof)
	if _, ok := challenge.AcceptACK(path, ack, now.Add(carrierChallengeLifetime)); ok {
		t.Fatal("expired acknowledgment was accepted")
	}
	if _, ok := challenge.AcceptACK(path, ack, now.Add(time.Millisecond)); ok {
		t.Fatal("expired challenge became live again")
	}
}

func TestCarrierChallenge_UDPProofAndSocketBinding(t *testing.T) {
	listen := func() *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	prober, responder, alternate := listen(), listen(), listen()
	origin := prober.LocalAddr().(*net.UDPAddr).AddrPort()
	remote := responder.LocalAddr().(*net.UDPAddr).AddrPort()
	path := CarrierUDPPath{LocalPort: origin.Port(), Remote: remote}
	scope, key, _ := testCarrierProof()
	challenge, request, err := BeginCarrierChallenge(scope, key, path, CarrierUpload, 1452, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prober.WriteToUDPAddrPort(request, remote); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, CarrierProofMax)
	n, observed, err := responder.ReadFromUDPAddrPort(buf)
	if err != nil || observed != origin || n != 1452 {
		t.Fatalf("probe read = %d from %v, %v", n, observed, err)
	}
	probe, ok := DecodeCarrierProof(scope, key, buf[:n])
	if !ok || probe.Kind != CarrierProbe {
		t.Fatal("real UDP probe did not verify")
	}
	probe.Kind = CarrierACK
	response := EncodeCarrierProof(scope, key, probe)
	if _, err := alternate.WriteToUDPAddrPort(response, origin); err != nil {
		t.Fatal(err)
	}
	n, observed, err = prober.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := challenge.AcceptACK(CarrierUDPPath{LocalPort: origin.Port(), Remote: observed}, buf[:n], time.Now()); ok {
		t.Fatal("authenticated response on a different remote port was accepted")
	}
	if _, err := responder.WriteToUDPAddrPort(response, origin); err != nil {
		t.Fatal(err)
	}
	n, observed, err = prober.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := challenge.AcceptACK(CarrierUDPPath{LocalPort: origin.Port(), Remote: observed}, buf[:n], time.Now()); !ok {
		t.Fatal("response from the qualified socket was rejected")
	}
}

func FuzzDecodeCarrierAttach(f *testing.F) {
	f.Add([]byte(`{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","auth_generation":1,"expected_path_epoch":0,"candidate_id":"wss"}`))
	f.Add([]byte(`{"request_id":"short","candidate_id":"wss"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 8192 {
			return
		}
		request, err := DecodeCarrierAttach(bytes.NewReader(payload))
		if err == nil && !ValidCarrierID(request.RequestID) {
			t.Fatal("accepted a noncanonical request ID")
		}
	})
}
