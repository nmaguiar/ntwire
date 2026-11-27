#!/bin/sh
# Apply netem only inside a new anonymous Linux network namespace.
set -eu

if [ "$#" -lt 6 ] || [ "$5" != -- ]; then
    printf '%s\n' 'usage: linux-netem.sh DELAY_MS LOSS_PERCENT RATE_MBIT SEED -- COMMAND [ARGS...]' >&2
    exit 2
fi
delay=$1 loss=$2 rate=$3 seed=$4
shift 5

if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'netem requires a Linux worker' >&2
    exit 2
fi
# Use a shell argument boundary for every value, including the command.
namespace=$(readlink /proc/self/ns/net)
exec unshare --net sh -eu -c '
    namespace=$1 delay=$2 loss=$3 rate=$4 seed=$5
    shift 5
    if [ "$(readlink /proc/self/ns/net)" = "$namespace" ]; then
        printf "%s\n" "refusing to shape the caller network namespace" >&2
        exit 1
    fi

    ip link set lo up
    tc qdisc add dev lo root netem limit 1024 delay "$delay"ms loss random "$loss"% seed "$seed" rate "$rate"mbit
    status=0
    "$@" || status=$?
    stats=$(tc -s -j qdisc show dev lo)
    printf "ntwire netem qdisc %s\n" "$stats" >&2
    exit "$status"
' netem "$namespace" "$delay" "$loss" "$rate" "$seed" "$@"
