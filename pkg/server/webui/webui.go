// Package webui embeds the server operator dashboard.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var files embed.FS

func Files() (fs.FS, error) { return fs.Sub(files, "static") }
