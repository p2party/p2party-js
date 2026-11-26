#!/usr/bin/env bash
# Apply one `perl -0pi` mutation, prove it landed, run one test file, restore,
# prove the restoration.
#
# A mutation that matched nothing is the failure mode this guards: the test
# would then "survive" a change that was never applied, and the survival would
# be recorded as evidence. The hash comparison aborts on that case.
#
#   docs/rendezvous-latency-2026-09/bench/mutate.sh \
#     <file> <pristine-copy> <test-path> <label> '<perl -0pi expression>'
#
# `<pristine-copy>` must be taken before any edit; the script restores from it
# and `diff`s. Run from the repository root.
set -uo pipefail
FILE="$1"; PRISTINE="$2"; TESTS="$3"; LABEL="$4"; shift 4
echo "### MUTATION: $LABEL"
before=$(shasum -a256 "$FILE" | cut -d' ' -f1)
perl -0pi -e "$1" "$FILE"
after=$(shasum -a256 "$FILE" | cut -d' ' -f1)
if [ "$before" = "$after" ]; then echo "!!! MUTATION DID NOT CHANGE THE FILE — ABORT"; exit 3; fi
echo "--- mutation diff ---"; diff -u "$PRISTINE" "$FILE" | sed -n '4,40p'
echo "--- test result ---"
bun test $TESTS 2>&1 | grep -E "^\(fail\)|^\(pass\)|error:|expect|Expected|Received|[0-9]+ pass|[0-9]+ fail" | head -40
cp "$PRISTINE" "$FILE"
echo "--- restoration ---"; diff "$PRISTINE" "$FILE" && echo "RESTORED byte-identical"
