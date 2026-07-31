package autostart

import (
	"bytes"
	"encoding/xml"
	"path/filepath"
)

// launchAgentLabel is both the LaunchAgent's Label and its plist filename
// stem, matching the plan's io.ntwire.gui identifier.
const launchAgentLabel = "io.ntwire.gui"

func plistPath(dir string) string {
	return filepath.Join(dir, launchAgentLabel+".plist")
}

// plistContents builds a minimal LaunchAgent property list: Label,
// ProgramArguments (execPath followed by args), and RunAtLoad=true. It is
// hand-built rather than produced via encoding/xml.Marshal, since a
// plist's <dict><key>.../<key><string>.../<string></dict> alternation
// isn't naturally expressible with encoding/xml's struct-tag model, and
// the format here is small and fixed enough to template directly.
func plistContents(execPath string, args []string) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("\t<key>Label</key>\n\t<string>" + launchAgentLabel + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	b.WriteString("\t\t<string>" + xmlEscape(execPath) + "</string>\n")
	for _, a := range args {
		b.WriteString("\t\t<string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
