#!/bin/sh
# Merge a separately built release archive into GoReleaser's SHA-256 manifest.
set -eu

manifest=$1
archive=$2
name=$(basename "$archive")
digest=$(shasum -a 256 "$archive" | awk '{print $1}')
tmp=$(mktemp "${manifest}.XXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM

# Compare filenames literally, accepting both text and binary checksum entries.
awk -v name="$name" '{ entry=$2; sub(/^\*/, "", entry); if (entry != name) print }' "$manifest" > "$tmp"
printf '%s  %s\n' "$digest" "$name" >> "$tmp"
mv "$tmp" "$manifest"
