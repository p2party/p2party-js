# SDK 0.15.0 release verification

Local release checks on November 27, 2026 used server 0.2.0 at `759ce45`,
the site at `e7f445f`, disposable PostgreSQL, and separate Chromium browser
profiles. The server health response reported signaling protocol 5. The peer
encryption protocol remains 4.

| Artifact | SHA-256 |
| --- | --- |
| `p2party-0.15.0.tgz` from Linux CI (871,783 bytes) | `d2eb1fbc40a585da0144413a0da9bbf5b17a03536cd5f982e0c20d429078353b` |
| `libcrypto.wasm` (232,181 bytes) | `34a866df90d13b43292a0b1eaa3182b01d1994e03fc533c799ce01bdf11691a2` |

The website vendors the Linux CI archive and self-hosts its WASM at site
revision `c30b968`. Verify the compressed archive against the first digest
in the table. [SDK CI archive](https://github.com/p2party/p2party-js/actions/runs/45983904833)

The two local builds of SDK implementation `eaca5e6` used Homebrew Node
26.13.1, npm 12.2.3, Bun 1.4.5 and Emscripten 7.0.0. Homebrew Node's
system zlib produced an 870,702-byte gzip stream with SHA-256
`813e9035cf57ba900f8179e0bf0bed6271644aa8dd62fd9f487432b9ed1d0473`.
Both gzip streams decompress to the same 2,878,464-byte tar archive,
SHA-256 `9d0773b2488366cd5c76b5d903481b13b31bfca92eae527e23bf1e416137e4e6`.
All 73 files, their metadata and their order match. Recompressing the local
tar stream with the official Node distribution's bundled zlib reproduces
the Linux CI digest.

The native TypeScript 7.0.2 compiler checks
both projects. The SDK declaration packager, Rollup and ESLint use the
TypeScript 6 JavaScript API.

The SDK passed 2,440 tests and the standalone encrypted-session example, the
site passed 186 tests, and the server passed 341 tests against PostgreSQL
18.7. The SDK and site npm lockfiles had zero reported advisories. The
ML-KEM known-answer tests covered all three supported parameter sets. The
archived multi-chunk session root and frame digests matched. The prior and
upgraded cryptographic builds could decrypt each other's messages.

## Reproducing the browser checks

From the site checkout, build the production site and start its preview in
one terminal. Use a disposable v5 signaling server and database. The
addresses below were used for this run.

```sh
npm run provenance:check
npm run build
npm run preview -- --host 127.0.0.1 --port 5864 --strictPort
```

Start a loopback-only coturn listener in a separate terminal. The release
run used UDP port 15940 and synthetic rooms. In the site checkout, run the
acceptance tests with that listener.

```sh
# Run the listener in its own terminal.
turnserver -n --stun-only --listening-ip=127.0.0.1 --listening-port=15940 --no-tcp --no-tls --no-dtls --no-cli --log-file=stdout --pidfile=/tmp/p2party-local-stun.pid
```

```sh
export STUN_URL=stun:127.0.0.1:15940
export APP_URL=http://127.0.0.1:5864
export SIGNALING_URL=ws://127.0.0.1:5865/ws
node e2e/run.mjs
node e2e/release-upgrade.mjs
node e2e/mesh-and-pin.mjs
node e2e/csp-hydration.mjs
```

The two-browser run exchanged text and files, recovered a deliberately
dropped chunk and verified the persisted 16 MiB file after a page reload.
The 64 MiB test stopped forwarding data after eight frames, observed
partial progress at the receiver, reloaded the sender, and verified every
byte and the authenticated sender key after resumption. The receiver then
observed the v5 leave notification and the departed member disappeared from
its roster. Purging removed the stored room and the previously verified
64 MiB OPFS file. Three peers authenticated all their edges, delivered text,
and recovered after a wrong room PIN. The retry delay survived a reload.
The saved contact and block entry remained effective after the signaling
server assigned new routing IDs. Chromium and macOS WebKit both exercised
the native local-WASM path under CSP.

For the separate blind-rendezvous prototype, run the following from the SDK
checkout after building the release.

```sh
bash docs/e2e/blind-two-store/build.sh
node docs/e2e/blind-two-store/run.mjs --scenario=healthy --page-port=15920 --store-port-base=15910
```

Both browsers verified their peer at about 24 seconds using the two
disposable stores. The stable WASM digest above matched the binary served by
the harness. The site CSP test visited all 15 prerendered routes, with zero
hydration errors, CSP violations or unexpected requests.
