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

missing=$(bash "$(dirname "$0")/missing-release-assets.sh" "$tag" <<< "$release")
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
