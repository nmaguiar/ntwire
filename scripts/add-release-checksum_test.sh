#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cd "$tmp"
name=ntwire-gui_v0.0.76_darwin_arm64.zip
printf 'archive fixture\n' > "$name"
printf 'other archive\n' > other.zip
shasum -a 256 other.zip > checksums.txt
cp checksums.txt original.txt
printf '%064d *%s\n' 0 "$name" >> checksums.txt
sh "$root/scripts/add-release-checksum.sh" checksums.txt "$name"
shasum -a 256 -c checksums.txt
test "$(wc -l < checksums.txt | tr -d ' ')" = 2
head -1 checksums.txt | cmp - original.txt
cp checksums.txt first.txt
sh "$root/scripts/add-release-checksum.sh" checksums.txt "$name"
cmp checksums.txt first.txt
# A missing manifest must fail rather than discard the existing release hashes.
if sh "$root/scripts/add-release-checksum.sh" missing.txt "$name" 2>/dev/null; then
  echo 'accepted a missing manifest' >&2
  exit 1
fi
test ! -e missing.txt
