#!/bin/sh
set -eu

e2e_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
e2e_state=$(mktemp -d "${TMPDIR:-/tmp}/ntwire-e2e.XXXXXX")
e2e_project="ntwire-e2e-$$"
e2e_compose="docker compose --project-name $e2e_project --file $e2e_root/tests/e2e/docker-compose.yml"

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		$e2e_compose ps >&2 || true
		$e2e_compose logs --no-color >&2 || true
	fi
	$e2e_compose down --volumes --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$e2e_state"
	exit "$status"
}
trap cleanup EXIT INT TERM

export E2E_STATE_DIR="$e2e_state"
e2e_cache="${TMPDIR:-/tmp}/ntwire-e2e-gocache"
mkdir -p "$e2e_cache"
GOCACHE="$e2e_cache" go run ./tests/e2e/fixtures -out "$e2e_state"

$e2e_compose up --build --detach dummy direct-server relay relayed-server direct-client relay-client

e2e_deadline=$(( $(date +%s) + 150 ))
while :; do
	if $e2e_compose logs --no-color direct-client 2>/dev/null | grep -q 'connected to' &&
		$e2e_compose logs --no-color relay-client 2>/dev/null | grep -q 'connected to'; then
		break
	fi
	if [ "$(date +%s)" -ge "$e2e_deadline" ]; then
		echo "timed out waiting for ntwire clients to connect" >&2
		exit 1
	fi
	sleep 1
done

$e2e_compose up --detach verify-direct verify-relay
while :; do
	completed=0
	for service in verify-direct verify-relay; do
		container=$($e2e_compose ps -q "$service")
		[ -n "$container" ] || continue
		state=$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$container")
		case "$state" in
			exited\ 0) completed=$((completed + 1)) ;;
			exited\ *) exit 1 ;;
		esac
	done
	if [ "$completed" -eq 2 ]; then
		echo "ntwire E2E direct and relay scenarios passed"
		exit 0
	fi
	if [ "$(date +%s)" -ge "$e2e_deadline" ]; then
		echo "timed out waiting for ntwire E2E probes" >&2
		exit 1
	fi
	sleep 1
done
