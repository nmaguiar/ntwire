// Package webui embeds the settings window's HTML/CSS/JS, the same way
// pkg/client/webui embeds the CLI connection's local status page.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var files embed.FS

// Files returns the embedded static assets rooted at static/, ready to be
// served with http.FileServer.
func Files() (fs.FS, error) { return fs.Sub(files, "static") }
