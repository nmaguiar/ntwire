package protocol

import (
	"encoding/json"
	"testing"
)

// FuzzAuthRequestDecoding covers the public JSON authentication envelope.
// Signature verification and authorization remain separate; this boundary
// must safely reject arbitrary untrusted JSON without network access.
func FuzzAuthRequestDecoding(f *testing.F) {
	f.Add([]byte(`{"version":1,"public_key":"x","timestamp":"2020-01-01T00:00:00Z"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		var request AuthRequest
		if err := json.Unmarshal(input, &request); err != nil {
			return
		}
		_, _ = SigningPayload(request)
	})
}
