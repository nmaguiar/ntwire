package portal

import (
	"fmt"
	"net/url"
	"strings"
)

// Supported portal action types.
const (
	ActionOpen    = "open"
	ActionBrowser = "browser"
	ActionConnect = "connect"
)

// ParseActionURI parses an ntwire action URI into an action and target ID.
// Format: ntwire://open/{targetID} or ntwire://browser/{targetID}
// Rejects arbitrary URLs, query strings, and host:port injections.
func ParseActionURI(raw string) (action string, targetID string, err error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ntwire://") {
		return "", "", fmt.Errorf("invalid action URI scheme: expected ntwire://")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("malformed action URI: %w", err)
	}

	// Host is the action (e.g. "open" in ntwire://open/grafana)
	action = strings.ToLower(u.Host)
	if action == "" {
		return "", "", fmt.Errorf("missing action in URI %q", raw)
	}

	switch action {
	case ActionOpen, ActionBrowser, ActionConnect:
	default:
		return "", "", fmt.Errorf("unsupported portal action %q", action)
	}

	// Path is /{targetID}
	targetID = strings.TrimPrefix(u.Path, "/")
	targetID = strings.TrimSpace(targetID)

	if targetID == "" {
		return "", "", fmt.Errorf("missing target ID in action URI %q", raw)
	}

	if strings.ContainsAny(targetID, "/?#&=") {
		return "", "", fmt.Errorf("invalid characters in target ID %q", targetID)
	}

	return action, targetID, nil
}

// ActionRequest is the payload sent by a client to execute a portal action.
type ActionRequest struct {
	Action   string `json:"action"`
	TargetID string `json:"target_id"`
}

// ActionResolution is the result of resolving an action against the effective target set.
type ActionResolution struct {
	Target       PortalTarget `json:"target"`
	SocksAddress string       `json:"socks_address,omitempty"`
	URL          string       `json:"url,omitempty"`
	Authorized   bool         `json:"authorized"`
}

// ResolveAction revalidates authorization for a target ID against the effective
// target set.
//
// Authorization answers "which target", never "what URL". A resolved URL is
// handed to a browser launcher on the client, where an argument beginning with
// "-" is read as a command-line switch rather than a URL, so the scheme is
// checked here too and an unusable one is dropped rather than forwarded. The
// client re-validates independently; neither side relies on the other.
func ResolveAction(targetID string, effectiveTargets []PortalTarget) (*ActionResolution, error) {
	wanted := strings.ToLower(strings.TrimSpace(targetID))
	for _, t := range effectiveTargets {
		if strings.ToLower(t.ID) == wanted || strings.ToLower(t.Name) == wanted {
			url := t.URL
			if url != "" && !SafeExternalURL(url) {
				url = ""
			}
			return &ActionResolution{
				Target:     t,
				URL:        url,
				Authorized: true,
			}, nil
		}
	}
	return nil, fmt.Errorf("target %q is not authorized for this session", targetID)
}
