# Contributing

Contributions and adversarial review are welcome.

## Development setup

Use a fresh recursive clone and the pinned release toolchain: Node 26.13.1, npm
12.2.3, Bun 1.4.5, and Emscripten 7.0.0. npm and `package-lock.json` are the
dependency authority. Bun runs the tests. Type checking uses the native
TypeScript 7 compiler. Rollup and ESLint use the TypeScript 6 JavaScript API.

```sh
git clone --recurse-submodules https://github.com/p2party/p2party-js.git
cd p2party-js
git -C libsodium fetch --depth=1 origin 05de1ce8088d4281a6264800070baf4ddf17b6a4
npm ci
npm run predist
npm run check
```

### Check Merkle proofs against the compiled WASM

After building the production WASM, run the bounded property suite offline.
The normal `npm test` and CI `npm run check` also include it.

```sh
bun test ./tests/cryptography/merkleWasmProperties.test.ts
```

The suite verifies the binary against its recorded SHA-256 and exercises the
SDK's normal leaf, root, proof and verification wrappers. Seed `0x50325035`
selects 32 reproducible trees of 1–65 leaves. Synthetic chunks range from
0 to 512 bytes and include SHA-512 padding boundaries. An independent Node
SHA-512 calculation checks the root, including odd-node promotion. The
verifier checks selected first, last and interior leaves, then checks changed
payloads, roots and sibling hashes. Failing test names identify the case and
tree size. Coverage is limited to those Merkle operations and bounds.
Production network traffic, memory sanitizers and the rest of the
cryptographic module are outside this suite.

## Building from source

Needed whenever you change the cryptography, and whenever you want to
reproduce the published artifact yourself. The release build reproduces the pinned WASM and fails rather
than emit an artifact it cannot attest, so the toolchain is exact:

| Requirement | Version                                                      |
| ----------- | ------------------------------------------------------------ |
| Node        | 26.x (exact major)                                           |
| npm         | 12.2.3                                                       |
| Emscripten  | 7.0.0, with `emsdk` on `PATH`                                |
| Submodules  | pinned libsodium (`git submodule update --init --recursive`) |

```sh
git submodule update --init --recursive
npm ci
npm run release:pack
npm install "./p2party-$(node -p "require('./package.json').version").tgz"
```

`src/cryptography/libcrypto.wasm` is not checked in and the test suite loads it
from disk, so build it once before the first test run:

```sh
npm run build          # compiles libcrypto.wasm via Emscripten, then bundles
bun test               # the suite runs under bun, not npm
```

Use only synthetic identities, room capabilities, PINs, snapshots, and files.
Do not use production signaling/CDN credentials, TURN secrets, user data, or
live room secrets in tests or reports.

Before opening a pull request:

- keep protocol changes fail-closed and document their threat model and wire
  compatibility;
- add focused tests for success, tampering, replay, cancellation, persistence,
  and failure paths as applicable;
- run `npm run check`;
- do not commit generated tarballs, local WASM binaries, credentials, or
  editor state; and
- use `npm run release:pack` only when validating a release candidate.

Security reports belong at `security@p2party.com`, not in a public issue.

## Public history

`master` carries the public history. Publish from this repository root with
`git push`; a separate export checkout is not needed. When ready, push the
stable tag matching `package.json` (for example `vX.Y.Z`). The tagged workflow
publishes the SDK to npm and the CDN. Prerelease versions use `release:pack`
for local testing.

Start public changes from `master`. Keep older private research histories on
their existing branches, and bring reviewed changes across with selected
cherry-picks rather than merging private history into the public branch.

By contributing, you agree that your contribution is licensed under
Apache-2.0.
