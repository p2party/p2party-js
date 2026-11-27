#!/usr/bin/env bash
# Build the browser bundle for the two-store blind-rendezvous E2E harness.
#
#   bash docs/e2e/blind-two-store/build.sh
#
# Serve the WASM built with the checkout's loader. After a release build this
# is the production binary whose digest is recorded in libcrypto.provenance.json.
# Both bundle.js and the local copy of the binary are generated artifacts.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/../../.." && pwd)"

cd "${root}"
bun build docs/e2e/blind-two-store/entry.ts \
  --target=browser \
  --outfile=docs/e2e/blind-two-store/bundle.js \
  --define:process.env.NODE_ENV='"production"'
cp src/cryptography/libcrypto.wasm docs/e2e/blind-two-store/libcrypto.wasm

echo "built docs/e2e/blind-two-store/bundle.js (+ libcrypto.wasm)"
