package api

import (
	"net/http"

	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

// profileField maps a clientopts option name -- as declared for the
// "connect" command, which is what a GUI profile mirrors -- to the
// config.Profile field the settings form reads it from and writes it back
// to. This table is what makes pkg/clientopts's no-drift promise (§1 of
// the implementation plan) real on the GUI side rather than aspirational:
// schema_test.go asserts every non-hidden, non-discarded "connect" option
// is covered here, so adding one to the registry without updating this
// table fails a test instead of silently producing a form field that
// writes nowhere.
//
// "no-browser" and "config" are deliberately absent: GUIHidden (see
// pkg/clientopts/options.go) marks options the GUI hardcodes itself
// rather than exposes as a per-profile choice -- config.Profile.
// ToClientOptions always sets NoWebUI:true, NoBrowser:false, and --config
// has no GUI equivalent at all (gui.yaml is not config.yaml).
var profileField = map[string]string{
	"i":             "IdentityFile",
	"ca":            "CAFile",
	"insecure":      "Insecure",
	"known-servers": "KnownServersFile",
	"sso":           "SSO",
	"provider":      "Provider",
	"token-cache":   "TokenCacheFile",
	"websocket":     "Websocket",
	"collect-exec":  "CollectExec",
	"port":          "Ports",
	"bind":          "BindAddress",
}

// schemaField is one generated form field, as served by GET /api/schema.
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

func kindName(k clientopts.Kind) string {
	switch k {
	case clientopts.KindBool:
		return "bool"
	case clientopts.KindKeyValue:
		return "keyvalue"
	default:
		return "string"
	}
}

// profileSchema is the settings form's field list, derived from
// pkg/clientopts's registry rather than hand-maintained -- adding an
// Option to the registry (with a profileField entry) makes it appear in
// the generated form with no other change needed here.
func profileSchema() []schemaField {
	var out []schemaField
	for _, o := range clientopts.For("connect") {
		if o.GUIHidden || o.Discarded {
			continue
		}
		field, ok := profileField[o.Name]
		if !ok {
			continue // covered by schema_test.go; see profileField's doc comment
		}
		out = append(out, schemaField{
			Name:     o.Name,
			Field:    field,
			Kind:     kindName(o.Kind),
			Label:    o.Label,
			Help:     o.Help,
			Group:    o.Group,
			Widget:   string(o.Widget),
			Advanced: o.Advanced,
		})
	}
	return out
}

func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, profileSchema())
}
