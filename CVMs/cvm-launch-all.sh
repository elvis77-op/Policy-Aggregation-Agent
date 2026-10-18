#!/bin/bash

# Launches N (default 16) independent CVM instances via cvm-instance.sh.
# Usage: ./cvm-launch-all.sh [count]

set -euo pipefail

count=${1:-16}
[[ "$count" =~ ^[0-9]+$ ]] && (( count >= 1 && count <= 16 )) || {
    echo "Usage: $0 [count: 1-16]" >&2
    exit 2
}

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

for ((n = 1; n <= count; n++)); do
    "$dir/cvm-instance.sh" "$n"
done
