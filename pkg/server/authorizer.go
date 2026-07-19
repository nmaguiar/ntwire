package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"time"
)

type AuthorizationInput struct {
	SourceIP       string            `json:"source_ip"`
	KeyFingerprint string            `json:"key_fingerprint"`
	KeyComment     string            `json:"key_comment"`
	SessionID      string            `json:"session_id"`
	ClientInfo     map[string]string `json:"client_info"`
	GrantedTunnels []string          `json:"granted_tunnels_by_yaml"`
	RequestedAt    time.Time         `json:"requested_at"`
}
type AuthorizationResult struct {
	Allow          bool   `json:"allow"`
	AllowedTunnels any    `json:"allowed_tunnels"`
	TTLSeconds     int    `json:"ttl_seconds"`
	Reason         string `json:"reason"`
	RiskScore      int    `json:"risk_score"`
}

func Authorize(ctx context.Context, c AuthorizerConfig, in AuthorizationInput) (AuthorizationResult, error) {
	if c.WebhookURL == "" && c.Exec == "" {
		return AuthorizationResult{Allow: true, AllowedTunnels: "*"}, nil
	}
	b, _ := json.Marshal(in)
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var out []byte
	var err error
	if c.WebhookURL != "" {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.WebhookURL, bytes.NewReader(b))
		if e != nil {
			return AuthorizationResult{}, e
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			return AuthorizationResult{}, e
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return AuthorizationResult{}, fmt.Errorf("authorizer returned %s", resp.Status)
		}
		out, e = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		err = e
	} else {
		cmd := exec.CommandContext(ctx, c.Exec)
		cmd.Stdin = bytes.NewReader(b)
		out, err = cmd.Output()
	}
	if err != nil {
		return AuthorizationResult{}, err
	}
	var r AuthorizationResult
	if err = json.Unmarshal(out, &r); err != nil {
		return AuthorizationResult{}, fmt.Errorf("invalid authorizer response: %w", err)
	}
	return r, nil
}
