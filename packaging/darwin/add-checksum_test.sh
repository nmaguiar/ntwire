#!/bin/sh
set -eu
directory=$(mktemp -d)
trap 'rm -rf "$directory"' EXIT HUP INT TERM
script=$(dirname "$0")/add-checksum.sh
name=ntwire-gui_v0.0.74_darwin_arm64.zip
printf 'fixture archive\n' > "$directory/$name"
printf '%s\n' 'original  ntwire_0.0.74_linux_arm64.tar.gz' > "$directory/checksums.txt"
sh "$script" "$directory/$name" "$directory/checksums.txt"
grep -Fx 'original  ntwire_0.0.74_linux_arm64.tar.gz' "$directory/checksums.txt"
(cd "$directory" && tail -1 checksums.txt | shasum -a 256 -c -)
# Re-running replaces an existing entry, including the binary-mode spelling.
printf 'stale  *%s\n' "$name" >> "$directory/checksums.txt"
sh "$script" "$directory/$name" "$directory/checksums.txt"
test "$(wc -l < "$directory/checksums.txt" | tr -d ' ')" = 2
(cd "$directory" && tail -1 checksums.txt | shasum -a 256 -c -)
