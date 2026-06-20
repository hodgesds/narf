#!/usr/bin/env bash
# run_local.sh — LOCAL validation of the mt-echo workload on this host.
#
# Builds the server + loadgen, then runs the SERVER and the LOAD GEN on
# this multicore host (127.0.0.1) at increasing server thread counts,
# showing that aggregate throughput scales with the number of server
# threads (each thread = one SO_REUSEPORT listener the kernel steers
# distinct flows to). This is the host-only proof that the workload
# parallelizes; the NARF-vs-Linux-over-tap comparison is documented in
# README.md and wired into xtask separately.
#
# IMPORTANT: the server binary is a NARF/musl-static x86_64 ELF. It is
# ALSO a perfectly valid Linux ELF, so it runs natively here for the
# local scaling demo.
#
# Usage: ./run_local.sh [PORT] [CONNS] [DURATION] [CLIENT_THREADS]
set -euo pipefail
cd "$(dirname "$0")"

PORT="${1:-7100}"
CONNS="${2:-64}"
DUR="${3:-5}"
CLIENT_THREADS="${4:-16}"
SERVER="./mt_echo_server_x86_64"
LOADGEN="./loadgen"

echo "== build =="
./build.sh >/dev/null
echo "built: $SERVER $LOADGEN"
echo

cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true; }
trap cleanup EXIT

run_case() {
    local sthreads="$1"
    # Start the server with $sthreads worker threads.
    "$SERVER" "$PORT" "$sthreads" >/tmp/mtecho_srv.$$ 2>&1 &
    SRV_PID=$!
    # Wait for the readiness marker.
    for _ in $(seq 1 100); do
        if grep -q "mt-echo: listening" /tmp/mtecho_srv.$$ 2>/dev/null; then break; fi
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            echo "server died:"; cat /tmp/mtecho_srv.$$; exit 1
        fi
        sleep 0.05
    done
    # Drive the load.
    printf 'server_threads=%-2s  ' "$sthreads"
    "$LOADGEN" 127.0.0.1 "$PORT" "$CONNS" "$DUR" "$CLIENT_THREADS" 16 \
        2>/dev/null | sed 's/^RESULT //'
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
    rm -f /tmp/mtecho_srv.$$
}

echo "== local scaling: conns=$CONNS dur=${DUR}s client_threads=$CLIENT_THREADS =="
echo "   (throughput should rise as server_threads increases)"
echo
for ST in 1 2 4 8; do
    run_case "$ST"
done
echo
echo "Done. rps = requests/sec (higher better); p*_us = latency microseconds."
