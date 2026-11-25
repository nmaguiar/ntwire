package manager

import (
	"testing"

	"github.com/nmaguiar/ntwire/pkg/egressrouter"
)

func TestSmartProxyHistorySample_RetainsAnEnrolledTunnelDuringReconnect(t *testing.T) {
	const profile = "office"
	const listen = "127.0.0.1:1080"
	enrollment := egressrouter.Enrollment{ProfileID: profile, EgressClass: "internet"}
	member := enrollment.Member("egress")
	m := &Manager{sessions: map[string]*session{profile: {state: StateConnected}}}
	cfg := egressrouter.Config{Egress: egressrouter.Membership{Enroll: []egressrouter.Enrollment{enrollment}}}
	healthy := egressrouter.Status{Listening: listen, Members: []egressrouter.MemberStatus{{Member: member, ConnectMillis: 42}}}
	sample := m.smartProxyHistorySample(0, cfg, healthy, SmartProxyHistorySample{})
	if len(sample.Members) != 1 || sample.Members[0].Outage != "" || sample.Members[0].ConnectMillis != 42 {
		t.Fatalf("connected sample = %+v", sample)
	}

	m.sessions[profile].state = StateReconnecting
	missing := egressrouter.Status{Listening: listen}
	for i := 1; i <= smartProxySampleLimit+1; i++ {
		sample = m.smartProxyHistorySample(int64(i)*smartProxySampleInterval.Milliseconds(), cfg, missing, sample)
		if len(sample.Members) != 1 || sample.Members[0].MemberID != member.ID() ||
			sample.Members[0].Outage != string(StateReconnecting) || sample.Members[0].ConnectMillis != 0 {
			t.Fatalf("reconnecting sample %d = %+v", i, sample)
		}
	}
	if removed := m.smartProxyHistorySample(sample.Time+2000, egressrouter.Config{}, missing, sample); len(removed.Members) != 0 {
		t.Fatalf("removed enrollment remains in sample: %+v", removed)
	}
	m.sessions[profile].state = StateConnected
	if recovered := m.smartProxyHistorySample(sample.Time+2000, cfg, healthy, sample); len(recovered.Members) != 1 ||
		recovered.Members[0].Outage != "" || recovered.Members[0].ConnectMillis != 42 {
		t.Fatalf("recovered sample = %+v", recovered)
	}
}
