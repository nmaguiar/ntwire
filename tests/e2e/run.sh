#!/bin/sh
set -eu

e2e_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
e2e_state=$(mktemp -d "${TMPDIR:-/tmp}/ntwire-e2e.XXXXXX")
e2e_project="ntwire-e2e-$$"
e2e_compose="docker compose --project-name $e2e_project --file $e2e_root/tests/e2e/docker-compose.yml"
e2e_direct_network="${e2e_project}_direct"

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "ntwire E2E diagnostics (project: $e2e_project)" >&2
		echo "direct client transport state" >&2
		$e2e_compose exec -T direct-client /ntwire transport >&2 || true
		echo "relay client transport state" >&2
		$e2e_compose exec -T relay-client /ntwire transport >&2 || true
		echo "direct multipath events" >&2
		$e2e_compose logs --no-color direct-client direct-server 2>&1 |
			grep -E 'multipath|transport candidate|WebSocket|websocket|session renewed|connected to' >&2 || true
		echo "verifier tails" >&2
		$e2e_compose logs --no-color --tail 40 verify-direct verify-relay >&2 || true
		echo "relay tails" >&2
		$e2e_compose logs --no-color --tail 80 relay-client relayed-server relay >&2 || true
		$e2e_compose ps >&2 || true
	fi
	$e2e_compose down --volumes --remove-orphans >/dev/null 2>&1 || true
	docker network rm "$e2e_direct_network" >/dev/null 2>&1 || true
	rm -rf "$e2e_state"
	exit "$status"
}
trap cleanup EXIT INT TERM

export E2E_STATE_DIR="$e2e_state"
export E2E_DIRECT_NETWORK="$e2e_direct_network"
e2e_direct_subnet="192.168.200.0/24"
docker network create --subnet="$e2e_direct_subnet" "$e2e_direct_network" >/dev/null
e2e_direct_server_ip="${e2e_direct_subnet%%/*}"
e2e_direct_server_ip="${e2e_direct_server_ip%.*}.2"
export E2E_DIRECT_SERVER_IP="$e2e_direct_server_ip"
e2e_cache="${TMPDIR:-/tmp}/ntwire-e2e-gocache"
mkdir -p "$e2e_cache"
GOCACHE="$e2e_cache" go run ./tests/e2e/fixtures -out "$e2e_state" -direct-subnet "$e2e_direct_subnet"

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

# Prove the intended negotiation shape, not only tunnel reachability: the
# direct topology has two live carriers and must expose both v3 candidates;
# the relay fixture intentionally offers WSS only and must remain on the
# single-path data plane with no multipath paths in status.
while :; do
	direct_status=$($e2e_compose exec -T direct-client /ntwire status --json 2>/dev/null || true)
	if echo "$direct_status" | grep -q '"name": "wss"' && echo "$direct_status" | grep -q '"name": "direct-udp"'; then
		break
	fi
	if [ "$(date +%s)" -ge "$e2e_deadline" ]; then
		echo "direct client did not expose both v3 candidates" >&2
		exit 1
	fi
	sleep 1
done
relay_status=$($e2e_compose exec -T relay-client /ntwire status --json)
if echo "$relay_status" | grep -q '"paths"'; then
	echo "WSS-only relay unexpectedly negotiated multipath" >&2
	exit 1
fi

while :; do
	if $e2e_compose up --detach --no-deps verify-direct verify-relay; then
		break
	fi
	if [ "$(date +%s)" -ge "$e2e_deadline" ]; then
		echo "timed out starting ntwire E2E probe containers" >&2
		exit 1
	fi
	sleep 1
done
while :; do
	completed=0
	for service in verify-direct verify-relay; do
		container=$($e2e_compose ps -aq "$service")
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
		for service in verify-direct verify-relay; do
			container=$($e2e_compose ps -aq "$service")
			[ -n "$container" ] || continue
			echo "$service state: $(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$container")" >&2
		done
		exit 1
	fi
	sleep 1
done
