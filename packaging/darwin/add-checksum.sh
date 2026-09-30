#!/bin/sh
# Add or replace one archive's SHA-256 entry without losing GoReleaser entries.
set -eu
archive=$1
manifest=$2
name=$(basename "$archive")
checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
temporary=$(mktemp "${manifest}.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
awk -v name="$name" '{ filename=$2; sub(/^\*/, "", filename); if (filename != name) print }' "$manifest" > "$temporary"
printf '%s  %s\n' "$checksum" "$name" >> "$temporary"
mv "$temporary" "$manifest"
