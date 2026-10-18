#!/bin/bash

# Stops N (default 16) CVM instances started by cvm-instance.sh.
# Usage: ./cvm-stop-all.sh [count]

set -euo pipefail

count=${1:-16}
[[ "$count" =~ ^[0-9]+$ ]] && (( count >= 1 && count <= 16 )) || {
    echo "Usage: $0 [count: 1-16]" >&2
    exit 2
}

for ((n = 1; n <= count; n++)); do
    instance=$(printf '%02d' "$n")
    pidfile="/tmp/tdx-demo-cvm${instance}-pid.pid"
    pid=$(cat "$pidfile" 2>/dev/null || true)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid"
        echo "stopped cvm-$instance (pid $pid)"
    fi
    rm -f "$pidfile"
done
