#!/usr/bin/env bash
set -euo pipefail

tag=${1:?Usage: bash scripts/release-build-needed.sh TAG < release.json}
release=$(cat)

if jq -e '. == null or .draft == true' <<< "$release" >/dev/null; then
  echo true
elif jq -e '.prerelease == true' <<< "$release" >/dev/null; then
  missing=$(bash "$(dirname "$0")/missing-release-assets.sh" "$tag" <<< "$release")
  if [[ -z "$missing" ]]; then
    echo false
  elif jq -e '.immutable == true' <<< "$release" >/dev/null; then
    echo "Cannot upload missing assets to immutable prerelease $tag." >&2
    exit 1
  else
    echo true
  fi
else
  echo false
fi
