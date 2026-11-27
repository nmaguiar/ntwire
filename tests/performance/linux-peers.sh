#!/bin/sh
# A fresh PID namespace guarantees that the peers and their network namespaces
# disappear together, including after a timeout in the benchmark runner.
set -eu

queue_packets=1024
if [ "${1:-}" = --queue-packets ]; then
    queue_packets=${2:-}
    case "$queue_packets" in
        ""|*[!0-9]*|??????*) printf '%s\n' 'invalid peer queue capacity' >&2; exit 2 ;;
    esac
    if [ "$queue_packets" -lt 16 ] || [ "$queue_packets" -gt 32768 ]; then
        printf '%s\n' 'peer queue capacity must be 16 to 32768 packets' >&2
        exit 2
    fi
    shift 2
fi

if [ "$#" -lt 11 ] || [ "$9" != -- ]; then
    printf '%s\n' 'usage: linux-peers.sh [--queue-packets LIMIT] UP_DELAY UP_LOSS UP_RATE UP_SEED DOWN_DELAY DOWN_LOSS DOWN_RATE DOWN_SEED -- LAB TRANSPORT [FLAGS...]' >&2
    exit 2
fi
if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'the peer laboratory requires Linux' >&2
    exit 2
fi
outer=$(readlink /proc/self/ns/net)
outer_mount=$(readlink /proc/self/ns/mnt)
exec unshare --net --pid --fork --kill-child --mount-proc sh -eu -c '
    outer=$1 outer_mount=$2 queue_packets=$3
    shift 3
    up_delay=$1 up_loss=$2 up_rate=$3 up_seed=$4
    down_delay=$5 down_loss=$6 down_rate=$7 down_seed=$8
    shift 9
    lab=$1 transport=$2
    shift 2
    server_ns=$(readlink /proc/self/ns/net)
    if [ "$server_ns" = "$outer" ] || [ "$(readlink /proc/self/ns/mnt)" = "$outer_mount" ]; then
        printf "%s\n" "refusing to configure caller network namespace" >&2
        exit 1
    fi
    mount -t tmpfs -o size=2m,mode=0700,nosuid,nodev,noexec ntwire-peer-state /dev/shm
    state=$(mktemp -d /dev/shm/ntwire-peers.XXXXXX)
    server=
    client=
    fault=
    sampler=
    cleanup() {
        if [ -n "$sampler" ]; then
            kill "$sampler" 2>/dev/null || true
            wait "$sampler" 2>/dev/null || true
        fi
        if [ -n "$fault" ]; then
            kill "$fault" 2>/dev/null || true
            wait "$fault" || true
        fi
        if [ -n "$server" ]; then
            kill -INT "$server" 2>/dev/null || true
            wait "$server" || true
        fi
        if [ -n "$client" ]; then
            kill "$client" 2>/dev/null || true
            wait "$client" || true
        fi
        rm -rf -- "$state"
    }
    trap cleanup EXIT
    trap "exit 130" INT TERM
    unshare --net sleep 600 &
    client=$!
    i=0
    until client_ns=$(readlink "/proc/$client/ns/net") && [ "$client_ns" != "$server_ns" ] && [ "$client_ns" != "$outer" ]; do
        i=$((i + 1))
        if [ "$i" -ge 100 ] || ! kill -0 "$client" 2>/dev/null; then
            printf "%s\n" "could not verify a fresh client network namespace" >&2
            exit 1
        fi
        sleep 0.05
    done

    ip link add bench0 type veth peer name bench0 netns "$client"
    ip addr add 198.18.40.2/30 dev bench0
    ip link set lo up
    ip link set bench0 up
    nsenter -t "$client" -n ip addr add 198.18.40.1/30 dev bench0
    nsenter -t "$client" -n ip link set lo up
    nsenter -t "$client" -n ip link set bench0 up
    tc qdisc add dev bench0 root netem limit "$queue_packets" delay "${down_delay}ms" loss random "${down_loss}%" seed "$down_seed" rate "${down_rate}mbit"
    nsenter -t "$client" -n tc qdisc add dev bench0 root netem limit "$queue_packets" delay "${up_delay}ms" loss random "${up_loss}%" seed "$up_seed" rate "${up_rate}mbit"

    if [ "$transport" = native-wireguard-kernel ]; then
        nsenter -t "$client" -n ip link add benchwg type wireguard
        nsenter -t "$client" -n ip addr add 100.70.0.2/32 dev benchwg
        nsenter -t "$client" -n ip link set benchwg mtu 1420 up
        nsenter -t "$client" -n ip route add 100.70.0.1/32 dev benchwg
    fi
    "$lab" peer-server "$state" "$@" --transport "$transport" &
    server=$!
    i=0
    until [ -f "$state/ready.json" ]; do
        i=$((i + 1))
        if [ "$i" -ge 300 ] || ! kill -0 "$server" 2>/dev/null; then
            printf "%s\n" "peer server did not become ready" >&2
            exit 1
        fi
        sleep 0.05
    done

    for arg in "$@"; do
        case "$arg" in
            --link-outage=*)
                outage=${arg#*=}
                case "$outage" in
                    *ms) milliseconds=${outage%ms} ;;
                    *) exit 2 ;;
                esac
                case "$milliseconds" in
                    ""|*[!0-9]*) exit 2 ;;
                esac
                if [ "$milliseconds" -lt 100 ] || [ "$milliseconds" -gt 10000 ]; then
                    exit 2
                fi
                (
                    while [ ! -f "$state/measurement-start" ]; do sleep 0.02; done
                    sleep 1
                    nsenter -t "$client" -n ip link set bench0 down
                    sleep "$((milliseconds / 1000)).$(printf %03d "$((milliseconds % 1000))")"
                    nsenter -t "$client" -n ip link set bench0 up
                    touch "$state/link-restored"
                ) &
                fault=$!
                break
                ;;
        esac
    done
    if [ "${NTWIRE_BENCH_WSS_TCP:-0}" = 1 ] && [ "$transport" = wss ]; then
        command -v ss >/dev/null
        # Only established TCP sockets between the two disposable veth peers.
        # Record the two directions in the measured interval, outside Go.
        (
            while [ ! -f "$state/measurement-start" ]; do sleep 0.02; done
            sample=0
            while [ "$sample" -lt 1200 ] && [ ! -f "$state/measurement-end" ]; do
                down=$(ss -HOnit state established src 198.18.40.2 dst 198.18.40.1)
                up=$(nsenter -t "$client" -n ss -HOnit state established src 198.18.40.1 dst 198.18.40.2)
                printf "%s\n" "$down" | while IFS= read -r line; do
                    [ -z "$line" ] || printf "ntwire wss tcp downstream %s %s\n" "$sample" "$line" >&2
                done
                printf "%s\n" "$up" | while IFS= read -r line; do
                    [ -z "$line" ] || printf "ntwire wss tcp upstream %s %s\n" "$sample" "$line" >&2
                done
                sample=$((sample + 1))
                sleep 0.25
            done
        ) &
        sampler=$!
    fi
    result=0
    nsenter -t "$client" -n "$lab" peer-client "$state" "$@" --transport "$transport" || result=$?
    if [ -n "$sampler" ] && [ "$result" -eq 0 ]; then
        if [ -f "$state/measurement-end" ]; then
            wait "$sampler" || result=$?
            sampler=
        else
            printf "%s\n" "fixture did not mark the TCP sampling interval" >&2
            result=1
        fi
    fi
    if [ -n "$fault" ] && [ "$result" -eq 0 ]; then
        if [ ! -f "$state/link-restored" ]; then
            printf "%s\n" "benchmark ended before fixture link restoration" >&2
            result=1
        fi
    fi
    printf "ntwire netem upstream %s\n" "$(nsenter -t "$client" -n tc -s -d -j qdisc show dev bench0)" >&2
    printf "ntwire netem downstream %s\n" "$(tc -s -d -j qdisc show dev bench0)" >&2
    if [ -r "/proc/$server/status" ]; then
        while read -r field value unit; do
            if [ "$field" = "VmHWM:" ] && [ "$unit" = "kB" ]; then
                printf "ntwire server peak RSS KiB %s\n" "$value" >&2
                break
            fi
        done < "/proc/$server/status"
    fi
    for arg in "$@"; do
        case "$arg" in
            --server-udp-buffer-bytes=*)
                while IFS= read -r line; do
                    case "$line" in
                        Udp:*) printf "ntwire udp server %s\n" "$line" >&2 ;;
                    esac
                done < /proc/net/snmp
                break
                ;;
        esac
    done
    exit "$result"
' peers "$outer" "$outer_mount" "$queue_packets" "$@"
