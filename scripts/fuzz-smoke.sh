#!/usr/bin/env sh
# Run every public-input fuzz target for a short, bounded release smoke test.
# Override FUZZ_TIME (for example, FUZZ_TIME=30s) when more coverage is wanted.
set -eu

fuzz_time=${FUZZ_TIME:-5s}
go_cache=${GOCACHE:-/tmp/ntwire-gocache}
mkdir -p "$go_cache"
export GOCACHE="$go_cache"

run_fuzz() {
	package=$1
	target=$2
	go test "$package" -run '^$' -fuzz "^${target}$" -fuzztime "$fuzz_time"
}

run_fuzz ./pkg/protocol FuzzSigningPayload
run_fuzz ./pkg/protocol FuzzAuthRequestDecoding
run_fuzz ./pkg/socks FuzzServeConn
run_fuzz ./pkg/wstransport FuzzAccept
run_fuzz ./pkg/wstransport FuzzControlFrameDecoding
