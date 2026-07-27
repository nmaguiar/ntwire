package main

import "testing"

func TestEndpointForSubnet(t *testing.T) {
	tests := []struct {
		name    string
		subnet  string
		want    string
		wantErr bool
	}{
		{name: "docker IPv4 subnet", subnet: "172.20.0.0/16", want: "172.20.0.2:51820"},
		{name: "invalid subnet", subnet: "not-a-subnet", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := endpointForSubnet(tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("endpointForSubnet(%q) error = %v, wantErr %t", tt.subnet, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("endpointForSubnet(%q) = %q, want %q", tt.subnet, got, tt.want)
			}
		})
	}
}
