#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export PATH="$tmp:$PATH"
export GITHUB_REPOSITORY=example/ntwire
export NTWIRE_UPDATE_PUBLIC_KEY=configured
export CALL_LOG="$tmp/calls" RELEASE_FIXTURE="$tmp/release.json" LATEST=v1.2.3
export IMAGE_DIGEST="sha256:$(printf '%064d' 1)"

cat > "$tmp/gh" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "api repos/example/ntwire/releases/tags/v1.2.3") cat "$RELEASE_FIXTURE" ;;
  "api repos/example/ntwire/releases/latest --jq .tag_name") echo "$LATEST" ;;
  "release edit v1.2.3 --repo example/ntwire --prerelease=false --latest --verify-tag")
    echo "promote release" >> "$CALL_LOG" ;;
  *) echo "Unexpected gh call: $*" >&2; exit 1 ;;
esac
EOF
cat > "$tmp/docker" <<'EOF'
#!/usr/bin/env bash
case "$3" in
  inspect)
    echo "inspect $4" >> "$CALL_LOG"
    if [[ "$4" == "${MISSING_IMAGE:-}" ]]; then
      exit 1
    fi
    jq -n --arg digest "$IMAGE_DIGEST" '{
      $digest, manifests: [
        {platform: {os: "linux", architecture: "amd64"}},
        {platform: {os: "linux", architecture: "arm64"}}
      ]
    }' ;;
  create)
    [[ "$4" == --tag && "$5" == *:latest && "$6" == "${5%:latest}@$IMAGE_DIGEST" ]] || exit 1
    echo "retag $5" >> "$CALL_LOG" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$tmp/gh" "$tmp/docker"

jq -n '{
  tag_name: "v1.2.3", draft: false, prerelease: true,
  assets: ([
    ("ntwire", "ntwire-server", "ntwire-relay", "ntwire-gui") as $product
    | ("linux", "darwin", "windows") as $os
    | ("amd64", "arm64") as $arch
    | select($product != "ntwire-gui" or $os != "darwin")
    | "\($product)_1.2.3_\($os)_\($arch).\(if $os == "windows" then "zip" else "tar.gz" end)"
  ] + [
    "checksums.txt", "ntwire-1.2.3.tgz", "ntwire-gui_v1.2.3_darwin_arm64.zip",
    "update-manifest.json", "update-manifest.sig"
  ] | map({name: ., state: "uploaded", size: 100}))
}' > "$tmp/complete.json"

build_needed() {
  bash "$root/scripts/release-build-needed.sh" v1.2.3
}

# New tags, drafts and incomplete prereleases can build. Stable and complete
# prereleases are skipped, even when a duplicate release event arrives.
test "$(build_needed <<< 'null')" = true
test "$(jq '.draft = true' "$tmp/complete.json" | build_needed)" = true
test "$(jq '.assets = []' "$tmp/complete.json" | build_needed)" = true
test "$(jq '.assets[] |= if .name == "checksums.txt" then .size = 0 else . end' "$tmp/complete.json" | build_needed)" = true
test "$(build_needed < "$tmp/complete.json")" = false
test "$(jq '.prerelease = false | .assets = []' "$tmp/complete.json" | build_needed)" = false
if jq '.immutable = true | .assets = []' "$tmp/complete.json" | build_needed > "$tmp/output" 2>&1; then
  echo 'Expected immutable prerelease with missing assets to fail' >&2
  exit 1
fi
grep -Fq 'Cannot upload missing assets to immutable prerelease' "$tmp/output"

promote() {
  bash "$root/scripts/promote-release.sh" "${1:-v1.2.3}" > "$tmp/output" 2>&1
}

expect_failure() {
  if promote "${1:-v1.2.3}"; then
    echo 'Expected promotion to fail' >&2
    exit 1
  fi
  if grep -Eq '^(retag|promote release)' "$CALL_LOG"; then
    echo 'Failed preflight changed stable release state' >&2
    exit 1
  fi
}

# All six images are resolved before any stable tag changes.
cp "$tmp/complete.json" "$RELEASE_FIXTURE"
promote || { cat "$tmp/output" >&2; exit 1; }
test "$(head -n 6 "$CALL_LOG" | grep -c '^inspect ')" = 6
test "$(grep -c '^retag ' "$CALL_LOG")" = 6
test "$(tail -n 1 "$CALL_LOG")" = 'promote release'

# Reject RC tags, drafts, missing signing files and unavailable images.
: > "$CALL_LOG"
expect_failure v1.2.3-rc.1
jq '.draft = true' "$tmp/complete.json" > "$RELEASE_FIXTURE"
expect_failure
jq '.assets |= map(select(.name != "update-manifest.sig"))' "$tmp/complete.json" > "$RELEASE_FIXTURE"
NTWIRE_UPDATE_PUBLIC_KEY= expect_failure
grep -Fxq 'update-manifest.sig' "$tmp/output"
jq '.assets[] |= if .name == "ntwire-1.2.3.tgz" then .size = 0 else . end' "$tmp/complete.json" > "$RELEASE_FIXTURE"
expect_failure
grep -Fxq 'ntwire-1.2.3.tgz' "$tmp/output"
cp "$tmp/complete.json" "$RELEASE_FIXTURE"
MISSING_IMAGE=ghcr.io/example/ntwire-relay:1.2.3 expect_failure

# A release can be promoted without updater files when signing is unconfigured.
: > "$CALL_LOG"
jq '.assets |= map(select(.name | startswith("update-manifest.") | not))' "$tmp/complete.json" > "$RELEASE_FIXTURE"
expect_failure
NTWIRE_UPDATE_PUBLIC_KEY= promote
test "$(tail -n 1 "$CALL_LOG")" = 'promote release'

# A retry can refresh Pages for the current stable release without writes.
: > "$CALL_LOG"
jq '.prerelease = false' "$tmp/complete.json" > "$RELEASE_FIXTURE"
promote
test ! -s "$CALL_LOG"
LATEST=v1.2.4 expect_failure
