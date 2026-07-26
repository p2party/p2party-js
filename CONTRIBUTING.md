# Contributing

Contributions and adversarial review are welcome.

## Development setup

Use a fresh recursive clone and the pinned release toolchain: Node 24.11.1, npm
11.6.2, Bun 1.3.14, and Emscripten 6.0.2. npm and `package-lock.json` are the
dependency authority; Bun is the test runner.

```sh
git clone --recurse-submodules https://github.com/p2party/p2party-js.git
cd p2party-js
git -C libsodium fetch --depth=1 origin 2ce4d906a68eae82b27b4867f3d4172ec508cb27
npm ci
npm run predist
npm run check
```

## Building from source

Needed until 0.13.0 is on the registry, and whenever you change the
cryptography. The release build reproduces the pinned WASM and fails rather
than emit an artifact it cannot attest, so the toolchain is exact:

| Requirement | Version                                                      |
| ----------- | ------------------------------------------------------------ |
| Node        | 24.x (exact major)                                           |
| npm         | 11.6.2                                                       |
| Emscripten  | 6.0.2, with `emsdk` on `PATH`                                |
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

Public publication needs a fresh or squashed history authored with
`@p2party.com` identities. Preparing that public history is a release-owner
operation and is not part of an ordinary contribution.

By contributing, you agree that your contribution is licensed under
Apache-2.0.
