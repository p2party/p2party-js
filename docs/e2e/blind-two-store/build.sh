#!/usr/bin/env bash
# Build the browser bundle for the two-store blind-rendezvous E2E harness.
#
#   bash docs/e2e/blind-two-store/build.sh
#
# Both outputs are generated and must NOT be committed: `bundle.js` beside this
# script, and a copy of the DEVELOPMENT `libcrypto.wasm` the page fetches.
#
# Do not run `npm run predist` first: it overwrites src/cryptography/libcrypto.wasm
# with the web-only production build, which is not what wasmLoader.ts is pinned
# to in a checkout.
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
