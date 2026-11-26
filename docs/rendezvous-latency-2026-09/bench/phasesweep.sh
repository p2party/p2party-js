#!/usr/bin/env bash
# Run the two-store E2E harness n times at deliberately unlocked start phases.
#
# A `--scenario=healthy` run takes almost exactly an integer number of delivery
# windows, so a plain loop resamples nearly the same start phase `p` every time
# and every mean over such a batch is a mean over one point of the phase space.
# Sleeping a uniform random fraction of one window between runs breaks the lock.
#
#   docs/rendezvous-latency-2026-09/bench/phasesweep.sh \
#     <runs> <window-ms> <store-port-base> <page-port> <out-dir>
#
# Run from the repository root. Each run's full stdout lands in <out-dir>; the
# start phase, the per-window request counts, the item-15 per-route breakdown
# and the verdict are echoed as it goes.
set -u
RUNS=$1; W=$2; SPB=$3; PP=$4; OUT=$5
mkdir -p "$OUT"
for i in $(seq 1 "$RUNS"); do
  MS=$(( RANDOM % W ))                       # uniform in [0, W) milliseconds
  perl -e "select(undef,undef,undef,$MS/1000)"
  LOG="$OUT/run-$(printf '%02d' "$i").txt"
  node docs/e2e/blind-two-store/run.mjs --scenario=healthy \
    --window-ms="$W" --store-port-base="$SPB" --page-port="$PP" >"$LOG" 2>&1
  echo "run $i rc=$? slept=${MS}ms"
  grep -E 'start phase|item 16|^SCENARIO healthy|final count' "$LOG" | sed 's/^ *//'
  echo "---"
done
