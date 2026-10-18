#!/bin/bash

# Drives a synchronized policy_client test across the CVM fleet:
#   - Computes one release_ns shared by every CVM (and their 2 local clients).
#   - Launches launch-client.sh on all instances in parallel over SSH.
#   - Collects each instance's summary.log output and produces one
#     fleet-wide aggregate summary.
#
# Usage: ./cvm-fleet-test.sh [instance-count] [clients-per-instance] [lead-seconds]

set -euo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
key="$dir/cvm-fleet-key"

instances=${1:-16}
clients_per_instance=${2:-2}
lead_seconds=${3:-5}

[[ "$instances" =~ ^[0-9]+$ ]] && (( instances >= 1 && instances <= 16 )) || {
    echo "Usage: $0 [instance-count: 1-16] [clients-per-instance] [lead-seconds]" >&2
    exit 2
}

run_id=$(date +%Y%m%d-%H%M%S)
fleet_dir="$dir/fleet-runs/$run_id"
mkdir -p "$fleet_dir"
ln -sfn "$fleet_dir" "$dir/fleet-runs/latest"

release_ns=$(( $(date +%s%N) + lead_seconds * 1000000000 ))
echo "fleet run_id=$run_id release_ns=$release_ns lead_seconds=$lead_seconds instances=$instances clients_per_instance=$clients_per_instance"

pids=()
for ((n = 1; n <= instances; n++)); do
    instance=$(printf '%02d' "$n")
    port=$((21000 + n))
    out="$fleet_dir/cvm-$instance.log"
    (
        set +e
        ssh -i "$key" -p "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new root@localhost \
            "cd /root/containers && CVM_INSTANCE_ID=$instance RELEASE_NS=$release_ns ./launch-client.sh $clients_per_instance" \
            > "$out" 2>&1
        rc=$?
        echo "$rc" > "$fleet_dir/cvm-$instance.exit"
    ) &
    pids+=($!)
done

for pid in "${pids[@]}"; do
    wait "$pid" || true
done

# --- aggregate ---
fleet_summary="$fleet_dir/fleet-summary.log"
total_clients=0
total_success=0
total_failed=0
total_elapsed_ms=0
min_elapsed_ms=
max_elapsed_ms=0
earliest_start=
latest_start=
ssh_failed=0

{
    echo "=== CVM fleet synchronized elapsed-time summary ==="
    printf 'run_id=%s\nrelease_ns=%s\ninstances=%s\nclients_per_instance=%s\n' \
        "$run_id" "$release_ns" "$instances" "$clients_per_instance"
} | tee "$fleet_summary"

for ((n = 1; n <= instances; n++)); do
    instance=$(printf '%02d' "$n")
    exit_code=$(cat "$fleet_dir/cvm-$instance.exit" 2>/dev/null || echo 255)
    log="$fleet_dir/cvm-$instance.log"

    if (( exit_code == 255 )); then
        ssh_failed=$((ssh_failed + 1))
        printf 'cvm-%s: SSH_FAILED\n' "$instance" | tee -a "$fleet_summary"
        continue
    fi

    requested=$(sed -n 's/^requested_clients=//p' "$log" | tail -n 1)
    successful=$(sed -n 's/^successful_clients=//p' "$log" | tail -n 1)
    failed=$(sed -n 's/^failed_clients=//p' "$log" | tail -n 1)
    inst_min=$(sed -n 's/^min_elapsed_ms=//p' "$log" | tail -n 1)
    inst_max=$(sed -n 's/^max_elapsed_ms=//p' "$log" | tail -n 1)
    inst_total=$(sed -n 's/^total_client_elapsed_ms=//p' "$log" | tail -n 1)
    spread=$(sed -n 's/^first_message_spread_ms=//p' "$log" | tail -n 1)

    printf 'cvm-%s: requested=%s successful=%s failed=%s min_ms=%s max_ms=%s spread_ms=%s\n' \
        "$instance" "${requested:-N/A}" "${successful:-0}" "${failed:-0}" "${inst_min:-N/A}" "${inst_max:-N/A}" "${spread:-N/A}" \
        | tee -a "$fleet_summary"

    total_clients=$((total_clients + ${requested:-0}))
    total_success=$((total_success + ${successful:-0}))
    total_failed=$((total_failed + ${failed:-0}))
    total_elapsed_ms=$((total_elapsed_ms + ${inst_total:-0}))

    if [[ -n "${inst_min:-}" && "$inst_min" != "N/A" ]]; then
        [[ -z "$min_elapsed_ms" || "$inst_min" -lt "$min_elapsed_ms" ]] && min_elapsed_ms="$inst_min"
    fi
    if [[ -n "${inst_max:-}" && "$inst_max" != "N/A" ]]; then
        (( inst_max > max_elapsed_ms )) && max_elapsed_ms="$inst_max"
    fi

    # first client "start" time across the fleet, derived from START_SKEW_MS rows.
    while read -r skew_ms; do
        [[ "$skew_ms" == "N/A" || -z "$skew_ms" ]] && continue
        start_ns=$((release_ns + skew_ms * 1000000))
        [[ -z "$earliest_start" || "$start_ns" -lt "$earliest_start" ]] && earliest_start="$start_ns"
        [[ -z "$latest_start" || "$start_ns" -gt "$latest_start" ]] && latest_start="$start_ns"
    done < <(awk '$3 ~ /^[0-9]+$/ && NF==5 {print $3}' "$log")
done

if [[ -n "$earliest_start" && -n "$latest_start" ]]; then
    fleet_spread_ms=$(( (latest_start - earliest_start) / 1000000 ))
else
    fleet_spread_ms=N/A
fi
if (( total_success > 0 )); then
    average_ms=$(awk "BEGIN { printf \"%.3f\", $total_elapsed_ms / $total_success }")
else
    average_ms=N/A
fi

{
    printf 'total_requested_clients=%s\ntotal_successful_clients=%s\ntotal_failed_clients=%s\nssh_failed_instances=%s\n' \
        "$total_clients" "$total_success" "$total_failed" "$ssh_failed"
    printf 'fleet_first_message_spread_ms=%s\n' "$fleet_spread_ms"
    printf 'total_client_elapsed_ms=%s\nmin_elapsed_ms=%s\naverage_elapsed_ms=%s\nmax_elapsed_ms=%s\n' \
        "$total_elapsed_ms" "${min_elapsed_ms:-N/A}" "$average_ms" "$max_elapsed_ms"
    printf 'logs=%s\n' "$fleet_dir"
} | tee -a "$fleet_summary"

exit $(( total_failed > 0 || ssh_failed > 0 ))
