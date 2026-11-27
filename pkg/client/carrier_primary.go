package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/protocol"
	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

// selectPrimary is the single client-initiated selection operation for
// qualified carriers. Its wire commit remains server-authoritative.
func (a *adaptiveCarrierClient) selectPrimary(ctx context.Context, candidate string) error {
	return a.selectPrimaryFrom(ctx, candidate, "")
}

func (a *adaptiveCarrierClient) selectPrimaryFrom(ctx context.Context, candidate, expected string) error {
	a.selectionMu.Lock()
	defer a.selectionMu.Unlock()
	info, bearer, _ := a.credentials()
	relay := info.RelaySelect && a.relay != nil && candidate != "" && a.relay.path(candidate).id == candidate
	udp := info.UDPSelect && a.nativeUDPUsable(candidate) && info.NativeUDPAddress(candidate) != ""
	if !info.PathSelect || (candidate != protocol.CarrierWSS && candidate != protocol.CarrierQUIC && !relay && !udp) {
		return errors.New("adaptive carrier selection was not negotiated")
	}
	source, epoch, ok := a.bind.LaneState(a.lane)
	if !ok || source == "" {
		return errors.New("no current adaptive carrier")
	}
	if expected != "" && source != expected {
		return wstransport.ErrStalePathEpoch
	}
	if candidate == protocol.CarrierWSS {
		if _, err := a.ws.CarrierEndpoint("remote"); err != nil {
			return err
		}
	}
	origin := a.base + "/v1/transport/lanes/" + info.LaneID
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	state, err := a.readSelection(ctx, origin, info, bearer)
	if err != nil {
		return err
	}
	if state.Selected == "" || (state.Selected != source && state.Selected != candidate && source != candidate) {
		return errors.New("adaptive carrier selection diverged")
	}
	if source == candidate && state.Selected == candidate {
		return nil
	}
	if source != candidate {
		release, err := a.bind.PreparePathReceive(a.lane, candidate, epoch)
		if err != nil {
			return err
		}
		defer release()
	}
	if state.Selected != candidate {
		id, err := newCarrierRequestID()
		if err != nil {
			return err
		}
		request := protocol.CarrierAttachRequest{
			RequestID: id, Generation: info.AuthGeneration,
			ExpectedEpoch: state.PathEpoch, Candidate: candidate,
		}
		if err := a.commitRemotePrimary(ctx, origin, info, bearer, request); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != bearer || a.info.AuthGeneration != info.AuthGeneration || !time.Now().Before(a.expires) {
		return errors.New("carrier authorization changed during selection")
	}
	if _, err := a.bind.CommitPath(a.lane, candidate, epoch); err != nil {
		return err
	}
	if udp {
		a.extendUDPPath(candidate, a.expires)
	}
	if source != candidate && a.nativeUDP(source) != nil {
		until := time.Now().Add(30 * time.Second)
		if a.expires.Before(until) {
			until = a.expires
		}
		a.extendUDPPath(source, until)
	}
	a.updateRelaySelection(source, candidate)
	return nil
}

func newCarrierRequestID() (string, error) {
	var id protocol.CarrierID
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(id[:]), nil
}

func (a *adaptiveCarrierClient) readSelection(ctx context.Context, origin string, info protocol.AdaptiveSession, bearer string) (protocol.CarrierCandidates, error) {
	var state protocol.CarrierCandidates
	if err := a.controlRequest(ctx, http.MethodGet, origin+"/candidates", bearer, nil, &state); err != nil {
		return state, err
	}
	if state.ParentID != info.ParentID || state.LaneID != info.LaneID || state.AuthGeneration != info.AuthGeneration ||
		!state.PathSelect || state.RelaySelect != info.RelaySelect || state.RelayPerformance != info.RelayPerformance || state.UDPSelect != info.UDPSelect ||
		state.DirectUDP != info.DirectUDP || state.AlternateUDP != info.AlternateUDP {
		return state, errors.New("unconfirmed adaptive carrier state")
	}
	return state, nil
}

func (a *adaptiveCarrierClient) commitRemotePrimary(ctx context.Context, origin string, info protocol.AdaptiveSession, bearer string, request protocol.CarrierAttachRequest) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	attempt, cancel := context.WithTimeout(ctx, time.Second)
	var result protocol.CarrierPrimary
	err = a.controlRequest(attempt, http.MethodPut, origin+"/primary", bearer, body, &result)
	cancel()
	if err == nil && result.Candidate == request.Candidate && result.PathEpoch == request.ExpectedEpoch+1 {
		return nil
	}
	if carrierControlDenied(err) {
		return err
	}
	// A lost response is ambiguous. The bounded receive overlap may
	// already have expired. Reconcile the authenticated epoch even then,
	// so the lane can resume without replaying the mutation.
	state, checkErr := a.readSelection(ctx, origin, info, bearer)
	if checkErr == nil && state.Selected == request.Candidate && state.PathEpoch == request.ExpectedEpoch+1 {
		return nil
	}
	return errors.Join(errors.New("primary selection was not confirmed"), err, checkErr)
}

func carrierControlDenied(err error) bool {
	var denied *carrierHTTPError
	return errors.As(err, &denied) && (denied.status == http.StatusUnauthorized || denied.status == http.StatusForbidden)
}
