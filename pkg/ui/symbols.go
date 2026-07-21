package ui

// Symbols is the set of status glyphs used in CLI output, with a plain
// ASCII fallback for terminals/locales that don't support UTF-8.
type Symbols struct {
	OK          string
	Fail        string
	Bullet      string
	BulletEmpty string
	Arrow       string
	Warn        string
}

func SymbolsFor(caps Capabilities) Symbols {
	if caps.UTF8 {
		return Symbols{OK: "✓", Fail: "✗", Bullet: "●", BulletEmpty: "○", Arrow: "→", Warn: "⚠"}
	}
	return Symbols{OK: "OK", Fail: "FAIL", Bullet: "*", BulletEmpty: "o", Arrow: "->", Warn: "!"}
}
