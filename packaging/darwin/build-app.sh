#!/usr/bin/env bash
# Assembles ntwire-gui.app from an already-built ntwire-gui binary.
#
# Usage: build-app.sh <binary-path> <version> <output-dir>
#
# Produces <output-dir>/ntwire-gui.app: an unsigned macOS app bundle with
# LSUIElement=1 (menu-bar only, no Dock icon). Unsigned -- users hit
# Gatekeeper's "unidentified developer" warning (right-click -> Open gets
# past it) until this is code-signed and notarized with an Apple Developer
# ID, which needs an account this project doesn't have yet and is
# deliberately out of scope for now.
set -euo pipefail

BINARY="${1:?usage: build-app.sh <binary-path> <version> <output-dir>}"
VERSION="${2:?usage: build-app.sh <binary-path> <version> <output-dir>}"
OUT_DIR="${3:?usage: build-app.sh <binary-path> <version> <output-dir>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$OUT_DIR/ntwire-gui.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BINARY" "$APP/Contents/MacOS/ntwire-gui"
chmod +x "$APP/Contents/MacOS/ntwire-gui"

sed "s/__VERSION__/$VERSION/g" "$SCRIPT_DIR/Info.plist.tmpl" > "$APP/Contents/Info.plist"

echo "$APP"
