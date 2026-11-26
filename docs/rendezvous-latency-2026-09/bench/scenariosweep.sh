#!/usr/bin/env bash
# Run all four fault scenarios n times at deliberately unlocked start phases.
#
# `phasesweep.sh` is the same idea for `--scenario=healthy`; this one exists
# because stage 2 has to land a delivery window, and a window is only landed
# when every fault scenario passes at it repeatedly. A plain loop phase-locks
# to the delivery-window grid (see `stage-1-fixround-report.md` §1), so the
# uniform random sleep in [0, W) between batches is not decoration.
#
#   docs/rendezvous-latency-2026-09/bench/scenariosweep.sh \
#     <runs> <window-ms> <store-port-base> <page-port> <out-dir> [deadline-ms]
#
# Run from the repository root. `--scenario=all` takes four store port pairs
# from <store-port-base>, so leave eight ports free there. Each batch's full
# stdout lands in <out-dir>; the summary table, the final
# `append window-finalized` counts and the exit code are echoed as it goes.
set -u
RUNS=$1; W=$2; SPB=$3; PP=$4; OUT=$5; DL=${6:-180000}
mkdir -p "$OUT"
for i in $(seq 1 "$RUNS"); do
  MS=$(( RANDOM % W ))                       # uniform in [0, W) milliseconds
  perl -e "select(undef,undef,undef,$MS/1000)"
  LOG="$OUT/all-w${W}-$(printf '%02d' "$i").txt"
  node docs/e2e/blind-two-store/run.mjs --scenario=all \
    --window-ms="$W" --store-port-base="$SPB" --page-port="$PP" \
    --deadline-ms="$DL" >"$LOG" 2>&1
  echo "batch $i rc=$? slept=${MS}ms window=${W}ms -> $LOG"
  grep -E 'final count|^(healthy|kill-a|withhold-a|unreachable-b-for-one) ' "$LOG" | sed 's/^ *//'
  grep -E '^TWO-STORE' "$LOG"
  echo "---"
done
