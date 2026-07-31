package api

import (
	"reflect"
	"testing"

	"github.com/nmaguiar/ntwire/internal/gui/config"
	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

// TestEveryNonHiddenConnectOptionHasAProfileFieldMapping is the actual
// enforcement of §1's no-drift promise on the GUI side: a clientopts
// option exposed on "connect" and not marked GUIHidden/Discarded must map
// to a config.Profile field, or the generated settings form would grow a
// field for it that silently writes nowhere.
func TestEveryNonHiddenConnectOptionHasAProfileFieldMapping(t *testing.T) {
	for _, o := range clientopts.For("connect") {
		if o.GUIHidden || o.Discarded {
			continue
		}
		if _, ok := profileField[o.Name]; !ok {
			t.Errorf("clientopts option %q (connect) has no profileField mapping -- the generated settings form would silently write it nowhere", o.Name)
		}
	}
}

// TestProfileFieldHasNoStaleMappings catches the opposite drift: an entry
// left behind after an option was removed, renamed, or newly hidden.
func TestProfileFieldHasNoStaleMappings(t *testing.T) {
	valid := map[string]bool{}
	for _, o := range clientopts.For("connect") {
		if !o.GUIHidden && !o.Discarded {
			valid[o.Name] = true
		}
	}
	for name := range profileField {
		if !valid[name] {
			t.Errorf("profileField has a mapping for %q, which is not a non-hidden \"connect\" option", name)
		}
	}
}

// TestProfileSchemaFieldNamesExistOnProfile guards the other half of the
// drift risk: a profileField entry whose value is not an actual
// config.Profile field name (a typo, or the field having been renamed).
func TestProfileSchemaFieldNamesExistOnProfile(t *testing.T) {
	profileFields := map[string]bool{}
	typ := reflect.TypeOf(config.Profile{})
	for i := 0; i < typ.NumField(); i++ {
		profileFields[typ.Field(i).Name] = true
	}
	for _, f := range profileSchema() {
		if !profileFields[f.Field] {
			t.Errorf("schema field %q maps to config.Profile.%s, which does not exist", f.Name, f.Field)
		}
	}
}

func TestProfileSchemaOmitsGUIHiddenOptions(t *testing.T) {
	for _, f := range profileSchema() {
		if f.Name == "no-browser" || f.Name == "config" || f.Name == "no-color" {
			t.Errorf("profileSchema() included %q, which should be GUIHidden or Discarded", f.Name)
		}
	}
}
