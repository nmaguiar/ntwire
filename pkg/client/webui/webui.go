// Package webui embeds the local connection-status page.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var files embed.FS

func Files() (fs.FS, error) { return fs.Sub(files, "static") }
