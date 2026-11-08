package tcptune

import (
	"context"
	"net"
	"testing"
)

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{"zero", Options{}, false},
		{"bbr", Options{Congestion: "bbr", NotSentLowat: 16384}, false},
		{"negative lowat", Options{NotSentLowat: -1}, true},
		{"bad name", Options{Congestion: "bbr; rm"}, true},
		{"too long", Options{Congestion: "abcdefghijklmnop"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.opts.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOptions_ZeroIsNoOp(t *testing.T) {
	if (Options{}).control() != nil {
		t.Fatal("zero Options installed a Control hook")
	}
	if DialContext(Options{}) != nil {
		t.Fatal("zero Options returned a custom dialer")
	}
}

// An unsupported or rejected option must never prevent listening or dialing.
func TestListen_TuningFailureIsNonFatal(t *testing.T) {
	o := Options{Congestion: "definitely-not-real", NotSentLowat: 16384}
	ln, err := Listen(o, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := DialContext(o)(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial error = %v", err)
	}
	c.Close()
	var _ net.Listener = ln
}
