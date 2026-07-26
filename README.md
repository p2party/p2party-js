<p align="center">
  <a href="https://p2party.com">
    <img src="docs/assets/p2party-cat.svg" width="180" alt="p2party cat logo">
  </a>
</p>

# p2party

Protocol-v4 end-to-end encryption and reliable file transfer over a WebRTC
room mesh.

Apache-2.0 · [LICENSE.md](LICENSE.md)

> Status: protocol v4 is an intentional wire break — v3 peers and persisted v3
> crypto rows are not resumed. The current code has not completed an
> independent third-party security audit.

## What is shipped

- Every peer in a room connects to every other present peer through WebRTC;
  the signaling service is not the message hub.
- Every peer edge performs authenticated interactive 3DH plus an
  authenticated, room-fixed ML-KEM-512, ML-KEM-768 (default), or ML-KEM-1024
  bootstrap. PIN rooms additionally authenticate with CPace.
- Three chained key-confirmation messages complete the application-layer
  cryptographic handshake. An `RTCDataChannel` becoming `open` establishes the
  transport; it is not a substitute for that confirmation.
- Per-peer Double Ratchet state protects messages after the handshake.
- Message data travels in fixed 65,490-byte protocol-v4 frames. Cryptographic
  overhead is absorbed inside that fixed cell budget; randomized padding and
  decoy slots can hide a message's exact payload length within its transfer.
- Each outbound message has its own transfer identity and data channel, a
  cancellable handle, authenticated receipts, selective retransmission, and
  reconnect resume.
- Text and files up to the enforced 10 GiB application limit are supported.
  Browser builds use IndexedDB and, where available, OPFS for disk-backed large
  file receipt.
- Room capabilities have a compact 43-character base64url form, a versioned
  fragment invite, and an optional checksum-protected 24-word representation.
- `p2party/session` exposes the cryptography without Redux, IndexedDB, WebRTC,
  signaling, `window`, or `localStorage`.

Immediate delivery over the existing signaling rendezvous is the shipped
default. Scheduled timing cover is also wired as of 0.14.0: a room policy may
pin a cadence, lane count, and frames per cell, and every edge in the room then
emits fixed-size cells on that schedule whether or not there is data to send.
Sparse post-quantum healing (the OFFER/ADVANCE/ACK epoch exchange) is likewise
live on the mesh path, with persistence before dispatch and application traffic
blocked while an epoch is in flight.

The public `connect()` path still rejects opaque and blind meeting points —
any `rendezvousMode` other than `legacy-signaling` — because that transport is
not wired. The private BitTorrent extension remains a research direction, not a
shipped property.

The current signaling operator can observe room membership, peer identities,
network metadata, and timing. Fixed message cells and in-transfer decoys do not
by themselves provide continuous traffic-analysis resistance.

## Install

```sh
npm install p2party
```

That is the whole setup. The package ships its own WebAssembly cryptography and
its own database worker; there is no build step, no postinstall, and no native
dependency to compile.

Releases are published with npm provenance, so you can check that the tarball
was built by the tagged GitHub Actions run rather than uploaded by hand:

```sh
npm audit signatures
```

To build the artifact yourself instead, see
[Building from source](CONTRIBUTING.md#building-from-source). That path needs an
exact toolchain (Node 24, Emscripten 6.0.3, pinned submodules), because the
release build reproduces the pinned WASM and refuses to emit an artifact it
cannot attest.

## Send a message between two browsers

A complete working page is in
[`examples/browser-mesh/`](examples/browser-mesh/) — serve it, open it twice,
paste the invite from the first tab into the second tab's URL fragment:

```sh
bunx vite examples/browser-mesh
```

The part that matters is short:

```ts
import p2party from "p2party";

// One 256-bit capability. Share the invite; anyone holding it can join.
const invite = p2party.generateRoomInvite();
const room = await p2party.joinRoom(invite);

// Fires once per fully-arrived message, already decoded.
p2party.onMessage(room.id, ({ message }) => {
  console.log("received", message);
});

// A room id does not mean anyone can receive yet.
await p2party.waitForPeers(room.id);
await p2party.sendMessage("hello", "chat", room.id).done;
```

`joinRoom` resolves once the signaling service has assigned the room its id. It
rejects on a timeout rather than waiting forever, and takes an `AbortSignal` if
the user navigates away:

```ts
const room = await p2party.joinRoom(invite, undefined, undefined, {
  timeoutMs: 10_000,
  signal: controller.signal,
});
```

Reading an inbound message needs its Merkle root, which arrives on the room's
`messages` state:

```ts
const rooms = p2party.roomSelector(p2party.store.getState());
const latest = rooms.find((r) => r.id === room.id)?.messages.at(-1);
if (latest) {
  const opened = await p2party.readMessage(latest.merkleRootHex);
  console.log(opened.message);
}
```

## Choose your integration

**`p2party`** — the browser room mesh. It owns signaling, full-mesh WebRTC,
Redux state, IndexedDB/OPFS, the handshake, the ratchet, and transfer with
resume. You own the room capability and policy, the UI, and the optional PIN.

**`p2party/session`** — the cryptography alone, for Node, Bun, native shells or
a custom network. It owns the handshake, the ratchet, uniform encrypted
envelopes and snapshots. **You own the transport**, including message-delimited
framing, peer-key trust and storage — see
[docs/session-api.md](docs/session-api.md).

**`p2party/session` + `p2party/libcrypto.wasm`** — the same, with the exact
release-built cryptographic module loaded from bytes you supply, for offline or
integrity-pinned deployments.

Deeper guides:

- [Getting started](docs/getting-started.md) — the browser tutorial
- [Wire format](docs/wire-format.md) — frame layouts and the handshake ladder
- [Store-free session API](docs/session-api.md) — the `p2party/session` contract
- [Protocol-v4 security boundary](docs/protocol-v4-security.md) — what is and
  is not a guarantee
- [References](docs/references.md) — standards, papers and related projects
- [Roadmap](ROADMAP.md) — what is next, and the open problems it depends on

## Browser mesh

Every peer present in the same room connects to every other peer. The signaling
service coordinates discovery and WebRTC setup; it is not the message hub. A
room with `n` participants therefore has up to `n(n - 1) / 2` peer edges.

`joinRoom()` covers the common case. The two steps underneath it are separate
when you need them — `connect()` starts the join and returns immediately,
`waitForRoom()` resolves once the id arrives:

```ts
await p2party.connect(invite);
// ...render a joining state, wire up other listeners...
const room = await p2party.waitForRoom(invite, { timeoutMs: 10_000 });
```

`joinRoom()` resolving does not mean every peer edge has finished its
handshake. The library gates message cryptography on that separately, so render
peer and message state from the exported store rather than treating the room as
ready for everything at once.

An open RTCDataChannel means its DTLS/SCTP transport is ready. It is not the
protocol-v4 acknowledgement: p2party next runs its authenticated HELLO plus
three chained confirmation flights over the main channel. Message receipts are
a third, delivery-level acknowledgement.

## Wire format

Fixed 65,490-byte cells, a 65-byte receipt frame, and outer frame tags that make
an application cell, a decoy and a post-quantum healing record indistinguishable
by size. Byte layouts, the handshake ladder and the healing exchange are in
[docs/wire-format.md](docs/wire-format.md).

## Room invites

Generate one 256-bit room capability and derive each human-facing form from the
same bytes:

```ts
const capability = p2party.generateRoomCapability();
const compact = p2party.encodeRoomCapabilityBase64Url(capability); // 43 chars
const fragment = p2party.encodeRoomInviteFragment(capability); // v1.<compact>
const words = await p2party.encodeRoomCapabilityWords(capability); // 24 words

await p2party.connect(fragment);

const fromWords = await p2party.decodeRoomCapabilityWords(words);
const sameCompact = p2party.encodeRoomCapabilityBase64Url(fromWords);
console.assert(sameCompact === compact);
```

`generateRoomInvite()` is the versioned-fragment shortcut. Put it after `#` in
an HTTPS URL to keep it out of ordinary HTTP requests. The shipped
`legacy-signaling` route still sends the normalized capability to signaling;
the fragment alone is not server-blind rendezvous.

## PIN and exact ML-KEM room policy

Room policy is immutable after the room is created locally, every peer must use
the same policy and the same PIN bytes, and the ML-KEM suite is fixed before the
handshake — there is no in-band negotiation, downgrade, or classical fallback.
PIN mode adds CPace on top of identity authentication; it does not replace it.

The worked example, including how the PIN buffer is wiped, is in
[docs/getting-started.md](docs/getting-started.md#pin-room-with-an-exact-ml-kem-suite).

## Send, cancel, and read

`sendMessage()` returns a `MessageTransferHandle`, not a promise: `transferId`
identifies this logical send, `cancel()` works even during hashing and channel
setup, and `done` settles after every started peer send and cleanup.

`done` **rejects** when no peer took delivery — an empty room, or a cancel.
Both are ordinary outcomes. The rejection is a `MessageDeliveryError` whose
`result.outcomes` carries the same per-peer detail a resolved value would, so
handle it rather than treating it as a crash. The quickstart above shows the
shape; [docs/getting-started.md](docs/getting-started.md#send-cancel-and-read)
covers reading inbound messages and the metadata-only read that avoids
materializing large files.

## Cryptography without WebRTC

`p2party/session` is the same protocol-v4 cryptography with no Redux, no
IndexedDB, no WebRTC, no signaling, no `window` and no `localStorage` — for
Node, Bun, a native shell, a CLI, or any transport you already have.

Nothing to configure. The WASM loads from the installed package, so this runs
offline:

```ts
import { generateSessionIdentity } from "p2party/session";

const identity = await generateSessionIdentity();
```

Two peers, end to end. Each side needs the other's Ed25519 public key and a
pair of byte pipes — `send` and `recv` over your socket, pipe, queue, or
anything else that delivers whole messages in order:

```ts
import { createSession } from "p2party/session";

const alice = await createSession({
  role: "initiator",
  identity: aliceIdentity,
  peerIdentityEd25519PublicKey: bobPublicKey,
  channel: binding,
  transport: { send, recv },
  mode: "nopin",
});

const sealed = await alice.encrypt(new TextEncoder().encode("hello bob"));
const opened = await bob.decrypt(sealed);
```

`createSession()` runs the full handshake — 3DH ⊕ ML-KEM, Ed25519 cross-signed
identities, three chained confirmations — and resolves with a live Double
Ratchet. `encrypt()` returns uniform fixed-size frames; `decrypt()` takes them
back. `serialize()` hands you a snapshot and `restoreSession()` resumes the
same ratchet in a new process.

Run the complete two-party script, healing exchange included:

```sh
bun run examples/standalone-e2ee.ts
```

Four things stay yours, because no library can decide them for you:

| You own               | Because                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| Peer-key trust        | `peerIdentityEd25519PublicKey` must be pinned or explicitly TOFU-accepted; the session never guesses |
| Message framing       | `encrypt()` returns opaque frames — your transport must delimit and length-check records itself      |
| Snapshot storage      | `serialize()` is plaintext secret material: encrypt at rest, and protect against rollback            |
| The `channel` binding | A channel id and two endpoint fingerprints, bound into the transcript so a relay cannot swap sides   |

Outside WebRTC there are no DTLS fingerprints to bind, so derive the channel
binding from whatever your transport authenticates — a TLS exporter, a session
id, or random bytes both sides agree on out of band. The full contract, the
envelope codec and the sparse-PQ healing hooks are in
[docs/session-api.md](docs/session-api.md).

## Local, self-hosted, or release-pinned WASM

The browser root always fetches the exact versioned CDN WASM with a build-pinned
SHA-384 SRI value by default. A self-hosted browser app can point it at the
same release bytes before calling `connect()`:

```ts
import p2party from "p2party";

p2party.setWasmSourceUrl(
  new URL("/vendor/p2party-0.14.0/libcrypto.wasm", window.location.href),
);
```

The SRI check remains active, so a URL serving different bytes fails closed.

### Download the WASM from the CDN

Every release publishes its cryptographic module as an immutable, versioned
object. The path carries the version, so a URL always names exactly one build
and is safe to cache forever:

```sh
curl -O https://cdn.p2party.com/@0.14.0/libcrypto.wasm
curl -O https://cdn.p2party.com/@0.14.0/libcrypto.provenance.json
```

Check what you downloaded before you serve it. The SHA-256 and the SRI value
are both recorded in the provenance file that sits next to it:

```sh
shasum -a 256 libcrypto.wasm
openssl dgst -sha384 -binary libcrypto.wasm | openssl base64 -A
```

For 0.14.0 those are
`7eea31157e69ac61f3a512b624d5c210296302fd289fc2b65c63ecc31a056267` and
`sha384-pBMyUqQ3KBztxgeJMgDFZeohfj9QlAFNwt4/gRlqT0vlZ2kbkKxv+q5DwbZOBuUP`.
They are the same bytes npm ships — the release workflow uploads the CDN object
from the very tarball it publishes, then re-downloads and compares before
`npm publish` runs, so the two can never diverge.

Serve the file yourself and point the browser root at it with
`setWasmSourceUrl()` above, or hand the bytes straight to `p2party/session`.

On Node and Bun, `p2party/session` needs none of this: it reads the WASM from
the installed package and checks it against the same pinned SHA-384, so an
offline or air-gapped install works with no configuration and no network call.
Supply `wasmBinary` only to override that — bytes you host, embed, or verify
yourself:

```ts
import { readFile } from "node:fs/promises";
import { generateSessionIdentity } from "p2party/session";

const wasmBinary = await readFile("/opt/p2party/libcrypto.wasm");
const identity = await generateSessionIdentity({ wasmBinary });
```

The package also exports `p2party/libcrypto.provenance.json`, recording the
libsodium and mlkem-native commits, the Emscripten release, and the artifact's
digests. JavaScript and WASM are one release unit; never pair this release's
JavaScript with an older module.

The release gate runs packaged identity generation through both Node ESM and
CommonJS, once with explicit bytes and once with no arguments at all — the
second pass with `fetch` stubbed to throw, so a silent CDN fallback fails the
release rather than surfacing later as a broken offline install.

## Development

The reproducible release toolchain is Node 24.11.1, npm 11.6.2, Bun 1.3.14,
Emscripten 6.0.3, and the repository's pinned libsodium source object. npm and
`package-lock.json` are the dependency authority; Bun is the test runner.

```sh
git clone --recurse-submodules https://github.com/p2party/p2party-js.git
cd p2party-js
git -C libsodium fetch --depth=1 origin 2ce4d906a68eae82b27b4867f3d4172ec508cb27
npm ci
npm run predist
npm run check
```

`npm run release:pack` is the only supported package build. It rebuilds and
validates the cryptographic artifacts in a fresh staging tree, checks the
vendored source digests and provenance, enforces the tarball allowlist, and
produces `p2party-<version>.tgz`. Direct source-tree publication is refused.

Tagged releases publish immutable CDN objects first, fetch the public WASM back
and compare its exact bytes, SHA-256, and SRI to the validated build, and only
then publish the npm tarball with provenance.

## Security and licensing

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
Contributions are covered by [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

p2party is licensed under [Apache-2.0](LICENSE.md). Vendored and bundled
components retain their own terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
