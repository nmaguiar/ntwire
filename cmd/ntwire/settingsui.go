package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

//go:embed static/index.html
var settingsUIFiles embed.FS

// settingsField maps a clientopts option name to the client.Settings field
// its value is read from and saved to -- the CLI's counterpart to
// internal/gui/api's profileField, but against the smaller set of options
// this settings page persists. "known-servers", "token-cache", and
// "websocket" are deliberately absent: those flags exist, but nothing in
// client.Settings persists them today, so a form field for them would have
// nowhere to save its value. "port" (Ports) is also absent -- editing that
// stays the job of `ntwire port` and the local status UI's per-tunnel
// "Replace" control; see settingsUIFields in pkg/client/config.go.
var settingsField = map[string]string{
	"i":               "IdentityFile",
	"ca":              "CAFile",
	"insecure":        "Insecure",
	"https-proxy":     "HTTPSProxy",
	"no-system-proxy": "NoSystemProxy",
	"no-browser":      "NoBrowser",
	"sso":             "SSO",
	"provider":        "Provider",
	"collect-exec":    "CollectExec",
	"bind":            "BindAddress",
	"ip-version":      "IPVersion",
}

// schemaField mirrors internal/gui/api's wire shape so the two settings
// forms stay renderable by the same kind of client-side code, even though
// each package defines it independently -- this one is not a GUI, and
// should not import the GUI's internal package to save a few lines.
type schemaField struct {
	Name     string `json:"name"`
	Field    string `json:"field"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Help     string `json:"help,omitempty"`
	Group    string `json:"group"`
	Widget   string `json:"widget"`
	Advanced bool   `json:"advanced"`
}

// settingsSchema is "server" (handled specially: it's a positional argument
// on `ntwire connect`, not a clientopts flag, so it has no registry entry)
// followed by every settingsField-mapped "connect" option.
func settingsSchema() []schemaField {
	out := []schemaField{
		{Name: "server", Field: "Server", Kind: "string", Label: "Server address", Group: "🌐 Connection", Widget: "text",
			Help: "e.g. https://ntwire.example:8443 -- required to connect."},
	}
	for _, f := range clientopts.Fields("connect", settingsField) {
		help := f.Help
		if f.Name == "sso" {
			// Only true for this page, not ntwire-gui's settings window
			// (a GUI profile's SSO field is never touched outside the
			// form itself): a successful `ntwire connect` overwrites
			// this in ~/.ntwire/config.yaml with however it actually
			// authenticated -- see main.go's post-connect UpdateSettings
			// call -- so the saved value here reflects the last
			// connection, not a standing preference.
			help = "A successful `ntwire connect` overwrites this with however it actually authenticated, so it reflects your last connection rather than a standing preference."
		}
		out = append(out, schemaField{
			Name: f.Name, Field: f.ConfigField, Kind: f.Kind,
			Label: f.Label, Help: help, Group: f.Group, Widget: f.Widget, Advanced: f.Advanced,
		})
	}
	return out
}

// startSettingsUI serves a settings page for `ntwire connect`'s persisted
// ~/.ntwire/config.yaml on a random loopback port, the CLI's counterpart to
// ntwire-gui's settings window: the local status UI's dashboard has no
// settings page of its own to link to (see client.Options.SettingsURL's
// doc comment), so `connect` runs one itself and passes its URL through
// SettingsURL. Editing here changes the file `ntwire connect` reads next
// time, not this running connection -- there is nothing to hot-reload.
//
// It returns the dashboard-linkable URL (with its own access token) and a
// close func; the caller is responsible for calling close when done, the
// same as Connection.Close manages the local status UI's own listener.
func startSettingsUI(configPath string) (string, func(), error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	access := base64.RawURLEncoding.EncodeToString(b)
	allowed := func(r *http.Request) bool { return r.URL.Query().Get("token") == access }

	mux := http.NewServeMux()
	mux.HandleFunc("/api/schema", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(settingsSchema())
	})
	mux.HandleFunc("/api/values", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s, err := client.LoadSettings(configPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(s)
		case http.MethodPut:
			var s client.Settings
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&s); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if _, err := client.SaveSettings(configPath, s); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r) {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(mustSub(settingsUIFiles, "static"))).ServeHTTP(w, r)
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	url := "http://" + l.Addr().String() + "/?token=" + access
	return url, func() { _ = srv.Close() }, nil
}

func mustSub(fsys embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err) // static/settings.html is compiled in; this cannot fail at runtime
	}
	return sub
}
