package ui

import (
	"bytes"
	"testing"
)

func TestKVAlignsAndHighlightsKeys(t *testing.T) {
	var out bytes.Buffer
	u := New(&out, &out, true) // --no-color

	var kv KV
	kv.Add("pid", "123")
	kv.Add("server", "https://example.com")
	kv.Add("skipped", "")

	got := kv.Render(u)
	want := "pid:    123\nserver: https://example.com\n"
	if got != want {
		t.Errorf("Render() =\n%q\nwant\n%q", got, want)
	}
}
