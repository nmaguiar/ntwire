package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nmaguiar/ntwire/pkg/client"
	"github.com/nmaguiar/ntwire/pkg/clientopts"
)

// TestSettingsFieldNamesExistOnSettings guards against a typo or rename in
// settingsField's client.Settings side: a value there that isn't an actual
// Settings field would silently decode/encode nothing.
func TestSettingsFieldNamesExistOnSettings(t *testing.T) {
	valid := map[string]bool{}
	typ := reflect.TypeOf(client.Settings{})
	for i := 0; i < typ.NumField(); i++ {
		valid[typ.Field(i).Name] = true
	}
	for option, field := range settingsField {
		if !valid[field] {
			t.Errorf("settingsField[%q] = %q, which is not a client.Settings field", option, field)
		}
	}
}

// TestSettingsFieldHasNoStaleMappings catches an entry left behind after a
// clientopts option was removed or renamed on "connect".
func TestSettingsFieldHasNoStaleMappings(t *testing.T) {
	valid := map[string]bool{}
	for _, o := range clientopts.For("connect") {
		valid[o.Name] = true
	}
	for name := range settingsField {
		if !valid[name] {
			t.Errorf("settingsField has a mapping for %q, which is not a \"connect\" option", name)
		}
	}
}

func TestSettingsSchemaIncludesServerAndOmitsPorts(t *testing.T) {
	fields := settingsSchema()
	if fields[0].Name != "server" || fields[0].Field != "Server" {
		t.Fatalf("first field = %+v, want the synthetic \"server\" field", fields[0])
	}
	for _, f := range fields {
		if f.Field == "Ports" || f.Field == "Hosts" {
			t.Errorf("settingsSchema() included %q, which has no single-value form field", f.Field)
		}
	}
}

func TestStartSettingsUIRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	url, closeUI, err := startSettingsUI(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeUI()

	resp, err := http.Get(strings.Replace(url, "/?token=", "/api/schema?token=", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/schema status = %d", resp.StatusCode)
	}
	var schema []schemaField
	if err := json.NewDecoder(resp.Body).Decode(&schema); err != nil {
		t.Fatal(err)
	}
	if len(schema) == 0 {
		t.Fatal("schema is empty")
	}

	valuesURL := strings.Replace(url, "/?token=", "/api/values?token=", 1)
	body, err := json.Marshal(client.Settings{Server: "https://ntwire.example:8443", SSO: true})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, valuesURL, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /api/values status = %d", putResp.StatusCode)
	}

	getResp, err := http.Get(valuesURL)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	var got client.Settings
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Server != "https://ntwire.example:8443" || !got.SSO {
		t.Fatalf("GET /api/values after save = %+v", got)
	}
}

func TestStartSettingsUIRejectsWrongToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	url, closeUI, err := startSettingsUI(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeUI()
	resp, err := http.Get(strings.Replace(url, "/?token=", "/api/values?token=wrong-", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a wrong token", resp.StatusCode)
	}
}
