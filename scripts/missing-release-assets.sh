#!/usr/bin/env bash
set -euo pipefail

tag=${1:?Usage: bash scripts/missing-release-assets.sh TAG < release.json}
version=${tag#v}
release=$(cat)

# Keep these names in sync with GoReleaser and the native GUI and Helm jobs.
expected=(checksums.txt "ntwire-$version.tgz" "ntwire-gui_${tag}_darwin_arm64.zip")
for product in ntwire ntwire-server ntwire-relay ntwire-gui; do
  for os in linux darwin windows; do
    if [[ "$product" == ntwire-gui && "$os" == darwin ]]; then
      continue
    fi
    extension=tar.gz
    if [[ "$os" == windows ]]; then
      extension=zip
    fi
    for arch in amd64 arm64; do
      expected+=("${product}_${version}_${os}_${arch}.$extension")
    done
  done
done
if [[ -n "${NTWIRE_UPDATE_PUBLIC_KEY:-}" ]] ||
   jq -e 'any(.assets[]; .name == "update-manifest.json" or .name == "update-manifest.sig")' <<< "$release" >/dev/null; then
  expected+=(update-manifest.json update-manifest.sig)
fi
printf '%s\n' "${expected[@]}" | jq -Rnr --argjson release "$release" '
  [$release.assets[] | select(.state == "uploaded" and .size > 0) | .name] as $uploaded
  | inputs | select(. as $name | $uploaded | index($name) == null)'
