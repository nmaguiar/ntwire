#!/usr/bin/env bash
set -euo pipefail

tag=${1:?Usage: bash scripts/promote-release.sh vMAJOR.MINOR.PATCH}
repository=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}
if [[ ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Expected a release tag such as v1.2.3. Got $tag." >&2
  exit 1
fi
version=${tag#v}
release=$(gh api "repos/$repository/releases/tags/$tag")
if ! jq -e --arg tag "$tag" '.tag_name == $tag and .draft == false' <<< "$release" >/dev/null; then
  echo "Publish $tag as a prerelease before promoting it." >&2
  exit 1
fi
if jq -e '.prerelease == false' <<< "$release" >/dev/null; then
  latest=$(gh api "repos/$repository/releases/latest" --jq '.tag_name')
  if [[ "$latest" != "$tag" ]]; then
    echo "$tag is already stable and $latest is the current latest release." >&2
    exit 1
  fi
  echo "$tag is already the latest stable release. Continuing to Pages."
  exit 0
fi

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
missing=$(printf '%s\n' "${expected[@]}" | jq -Rnr --argjson release "$release" '
  [$release.assets[] | select(.state == "uploaded" and .size > 0) | .name] as $uploaded
  | inputs | select(. as $name | $uploaded | index($name) == null)')
if [[ -n "$missing" ]]; then
  printf 'Missing or incomplete release assets for %s\n%s\n' "$tag" "$missing" >&2
  exit 1
fi

# Resolve all versioned images before changing any latest tags. Copy each index
# from its digest so the new tag points at the same multi-platform image.
images=()
digests=()
owner=$(printf '%s' "${repository%%/*}" | LC_ALL=C tr '[:upper:]' '[:lower:]')
for registry in docker.io/nmaguiar "ghcr.io/$owner"; do
  for product in ntwire-server ntwire-client ntwire-relay; do
    image="$registry/$product"
    manifest=$(docker buildx imagetools inspect "$image:$version" --format '{{json .Manifest}}')
    if ! digest=$(jq -er '
      [.manifests[].platform | select(.os == "linux") | .architecture] as $arches
      | select(($arches | index("amd64")) != null and ($arches | index("arm64")) != null)
      | .digest | select(test("^sha256:[0-9a-f]{64}$"))' <<< "$manifest"); then
      echo "$image:$version is missing a valid linux/amd64 and linux/arm64 image index." >&2
      exit 1
    fi
    images+=("$image")
    digests+=("$digest")
  done
done
for i in "${!images[@]}"; do
  image=${images[i]}
  docker buildx imagetools create --tag "$image:latest" "$image@${digests[i]}"
done

gh release edit "$tag" --repo "$repository" --prerelease=false --latest --verify-tag
