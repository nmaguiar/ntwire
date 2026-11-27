package benchmark

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/nmaguiar/ntwire/pkg/wstransport"
)

type wssSnapshot struct {
	Performance wstransport.QueuePerformance `json:"performance"`
}

type serverMeasurement struct {
	WSS wssSnapshot `json:"wss"`
}

// The peer fixture creates the socket inside its private state directory.
// It supplies exactly two snapshots, one on either side of measurement.
func servePeerMeasurements(path string, snapshot func() serverMeasurement) (func(), error) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer listener.Close()
		for range 2 {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
				_ = json.NewEncoder(conn).Encode(snapshot())
			}
			_ = conn.Close()
		}
	}()
	return func() {
		_ = listener.Close()
		<-done
	}, nil
}

func readPeerMeasurement(ctx context.Context, path string) (serverMeasurement, error) {
	var snapshot serverMeasurement
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return snapshot, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return snapshot, err
	}
	err = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&snapshot)
	return snapshot, err
}
