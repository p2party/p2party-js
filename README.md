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
default. Scheduled timing cover is also wired as of 0.13.0: a room policy may
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
npm install p2party@0.13.0
```

> **Not published yet — and do not drop the version.** `npm install p2party`
> currently _succeeds_ and installs `0.8.0`, an older AGPL-3.0 line with no
> `p2party/session` export. Everything in these docs is 0.13.0, protocol v4,
> Apache-2.0. Pinning the version makes npm fail with `No matching version`
> instead of silently giving you the wrong library under the wrong licence.
>
> Until 0.13.0 is on the registry, build the tarball from a checkout:
> [Building from source](CONTRIBUTING.md#building-from-source). That path needs
> an exact toolchain (Node 24, Emscripten 6.0.2, pinned submodules), because the
> release build reproduces the pinned WASM and refuses to emit an artifact it
> cannot attest.

## Send a message between two browsers

The whole thing, end to end. Open this page in two tabs with the same URL
fragment and they will find each other.

```ts
import p2party from "p2party";

// One 256-bit capability. Share the invite; anyone holding it can join.
const invite = p2party.generateRoomInvite();
const room = await p2party.joinRoom(invite);

// Wait for someone else to arrive, then send.
const handle = p2party.sendMessage("hello", "chat", room.id);
try {
  const result = await handle.done;
  console.table(result?.outcomes);
} catch (error) {
  // `done` REJECTS when no peer took delivery. With a single tab open and
  // nobody else in the room, this is the expected result, not a bug.
  if (error instanceof p2party.MessageDeliveryError)
    console.table(error.result.outcomes);
}
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

| Goal                                 | Entry point                                     | p2party owns                                                                                  | Application owns                                                   |
| ------------------------------------ | ----------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Browser room mesh                    | `p2party`                                       | Signaling, full-mesh WebRTC, Redux state, IndexedDB/OPFS, handshake, ratchet, transfer/resume | Room capability and policy, UI, optional PIN                       |
| Node, Bun, native, or custom network | `p2party/session`                               | Handshake, ratchet, uniform encrypted envelopes, snapshots                                    | Reliable message transport, peer-key trust, storage, outer framing |
| Offline or pinned cryptography       | `p2party/session` plus `p2party/libcrypto.wasm` | Exact release-built cryptographic module                                                      | Loading and passing the pinned bytes                               |

Deeper guides:

- [Getting started](docs/getting-started.md)
- [Store-free session API](docs/session-api.md)
- [Protocol-v4 security boundary](docs/protocol-v4-security.md)
- [References](docs/references.md) — the standards, papers, and open-source
  projects p2party is built from and built on
- [Related work and prior art](docs/paper-prior-art-and-related-work.md) — the
  full research treatment, with a per-claim novelty assessment
- [Roadmap](ROADMAP.md) — what is next, and which open problems it depends on

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

Every byte below is derived from [`src/utils/constants.ts`](src/utils/constants.ts),
which is the single source of truth and is byte-matched in `utils.h`.

### Outer frame types

One tag byte leads every frame on a data channel.

| Tag | Name         | Size on the wire | Carries                         |
| --- | ------------ | ---------------- | ------------------------------- |
| 1   | `HANDSHAKE`  | step-dependent   | HELLO, CONFIRM, FINISH          |
| 2   | `CHUNK`      | 65,490 B         | one fixed application cell      |
| 3   | `RECEIPT`    | 65 B             | SHA-512 acknowledgement token   |
| 4   | `COVER`      | 65,490 B         | a scheduled cell, real or decoy |
| 5   | `PQ_CONTROL` | 65,490 B         | sparse-PQ OFFER / ADVANCE / ACK |

Tags 2, 4, and 5 are deliberately identical in size. An observer cannot tell an
application cell from a decoy or from a healing exchange by looking at the wire.

### Chunk frame — 65,490 bytes

```text
 0        1                     33      41      49        57         69                        65,474    65,490
 +--------+---------------------+-------+-------+---------+----------+-------------------------+---------+
 | type=2 | ratchet dhPub (32)  | N (8) | PN(8) | pqEpoch | nonce    | ciphertext (65,405)     | tag(16) |
 |  (1)   |                     |  BE   |  BE   |  (8) BE |   (12)   |                         |         |
 +--------+---------------------+-------+-------+---------+----------+-------------------------+---------+
 |<------------------ AAD: 57 bytes ------------------->|          |
 |<------------------- clear header: 69 bytes ---------------------->|
```

- The 57-byte AAD is authenticated but excludes the fresh random nonce.
- `pqEpoch` is an unsigned 64-bit counter. v3 used a single byte; v4 widened it
  so the sparse-PQ healing epoch cannot wrap.
- The plaintext cell is always 65,405 bytes, so at most **61,912 bytes** are
  caller payload; the remainder is metadata, the Merkle proof, and padding.
- ChaCha20-Poly1305 supplies the 16-byte tag.

### Receipt frame — 65 bytes

```text
 0        1                                                          65
 +--------+-----------------------------------------------------------+
 | type=3 | SHA-512 receipt token (64)                                 |
 +--------+-----------------------------------------------------------+
```

Both per-chunk acknowledgements and the terminal content-hash acknowledgement
use this exact geometry, so a completion is not distinguishable by size.

### Handshake ladder

```text
initiator                                                     responder
    |                                                              |
    |-- HELLO    = tag ‖ sid(32) ‖ EK(32) ‖ Y(32) ‖ idX25519(32)   |
    |             ‖ crossSig(64) ‖ mlkemPub(pk) ‖ mlkemCt(0…)  --> |
    |                                                              |
    | <-- HELLO  = same layout; pub all-zero, ct encapsulates ----- |
    |                                                              |
    | <-- CONFIRM = tag ‖ dhPub(32) ‖ mac(64) --------------------- |
    |-- CONFIRM  = tag ‖ dhPub(32) ‖ mac(64) --------------------> |
    | <-- FINISH  = tag ‖ mac(64) --------------------------------- |
    |                                                              |
  established                                                 established
```

The unused fixed-width KEM field must be canonical all-zero — a non-zero
spelling poisons the transcript rather than being ignored. The initiator is
established only after verifying FINISH; the responder after sending it.

### Sparse post-quantum healing

```text
    A                                                    B
    |-- OFFER   (new ML-KEM public key, epoch e+1) ---->  |
    | <-- ADVANCE (echoes the complete OFFER, + ct) ----- |
    |-- ACK     (confirms the epoch is live) ---------->  |
```

An ADVANCE embeds the entire OFFER it answers, so a fork is byte-detectable
rather than something both sides have to reconcile. Each side persists its
mutated state **before** dispatching, and application traffic is blocked while
an epoch is in flight.

### Room policy — 32 bytes

A room's policy is a fixed 32-byte record (magic `"P2RP"`) that pins the ML-KEM
suite, PIN mode, rendezvous mode, and the cover schedule. It is immutable after
first contact and hashed into the handshake transcript, so two peers that
disagree about it fail to authenticate rather than negotiating. Its canonical
base64url spelling is 43 characters — the same codec as the room capability,
which rejects non-canonical spellings so the final sextet's unused bits cannot
carry a watermark.

Scheduled cover has a hard floor: `cadence / (lanes × frames) >= 25 ms`.
Validate a schedule with `p2party.validateRoomPolicyV1()` before building a
policy rather than discovering the rejection at connect time.

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

The room fixes exactly one hybrid suite before the handshake. Every peer
supplies the same immutable policy and PIN; there is no suite negotiation,
downgrade, or classical fallback.

```ts
import p2party, { type RoomPolicyV1 } from "p2party";

const invite = p2party.generateRoomInvite();
const policy = {
  ...p2party.DEFAULT_ROOM_POLICY_V1,
  authMode: "pin",
  pqMode: "hybrid-mlkem1024",
} satisfies RoomPolicyV1;
const pin = new TextEncoder().encode("replace with a room secret");

try {
  await p2party.connect(invite, undefined, undefined, { policy, pin });
} finally {
  // connect() copied it into the in-memory room PIN vault.
  pin.fill(0);
}
```

Supported values are `hybrid-mlkem512`, `hybrid-mlkem768` (default), and
`hybrid-mlkem1024`. PIN bytes never enter room policy, Redux, persistent room
records, or logs.

## Send, cancel, and read

`sendMessage()` returns a handle immediately. Its `done` promise settles after
all started peer sends and cleanup and contains ordered per-peer outcomes.

```ts
const handle = p2party.sendMessage("hello room", "chat", room.id);
console.log(handle.transferId);

// Attach this to a cancel button; it works during hashing/channel setup too.
const cancelButton =
  document.querySelector<HTMLButtonElement>("#cancel-transfer");
cancelButton?.addEventListener("click", () => void handle.cancel());

const result = await handle.done;
if (result) {
  console.table(result.outcomes);
  const opened = await p2party.readMessage(result.merkleRootHex);
  console.log(opened.message, opened.percentage);
}
```

For received messages, read identifiers from room state. Pass
`materialize = false` to inspect completed file metadata without assembling its
Blob:

```ts
const current = p2party
  .roomSelector(p2party.store.getState())
  .find((candidate) => candidate.id === room.id);
const received = current?.messages.at(-1);

if (received) {
  const metadata = await p2party.readMessage(
    received.merkleRootHex,
    received.sha512Hex,
    false,
  );
  console.log(metadata.filename, metadata.size);
}
```

## Store-free session API

This Node/Bun example supplies a custom, reliable, ordered, message-delimited
transport and restores a ratchet snapshot. Replace the in-memory pipes with
your network adapter.

```ts
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  type HandshakeTransport,
} from "p2party/session";

const require = createRequire(import.meta.url);
const wasmBinary = Uint8Array.from(
  await readFile(require.resolve("p2party/libcrypto.wasm")),
);
const cryptoOptions = { wasmBinary };

const makePipe = (): HandshakeTransport => {
  const queued: Uint8Array[] = [];
  const waiters: Array<(bytes: Uint8Array) => void> = [];
  return {
    send(bytes): void {
      const owned = Uint8Array.from(bytes);
      const waiter = waiters.shift();
      if (waiter) waiter(owned);
      else queued.push(owned);
    },
    recv(): Promise<Uint8Array> {
      const bytes = queued.shift();
      return bytes
        ? Promise.resolve(bytes)
        : new Promise((resolve) => waiters.push(resolve));
    },
  };
};

const [aliceIdentity, bobIdentity] = await Promise.all([
  generateSessionIdentity(cryptoOptions),
  generateSessionIdentity(cryptoOptions),
]);
const aliceToBob = makePipe();
const bobToAlice = makePipe();
const channelId = globalThis.crypto.getRandomValues(new Uint8Array(16));
const aliceFingerprint = globalThis.crypto.getRandomValues(new Uint8Array(32));
const bobFingerprint = globalThis.crypto.getRandomValues(new Uint8Array(32));

const [alice, bob] = await Promise.all([
  createSession({
    role: "initiator",
    identity: aliceIdentity,
    peerIdentityEd25519PublicKey: bobIdentity.ed25519PublicKey,
    channel: {
      channelId,
      localFingerprint: aliceFingerprint,
      remoteFingerprint: bobFingerprint,
    },
    transport: { send: aliceToBob.send, recv: bobToAlice.recv },
    mode: "nopin",
    pqMode: "hybrid-mlkem768",
    crypto: cryptoOptions,
  }),
  createSession({
    role: "responder",
    identity: bobIdentity,
    peerIdentityEd25519PublicKey: aliceIdentity.ed25519PublicKey,
    channel: {
      channelId,
      localFingerprint: bobFingerprint,
      remoteFingerprint: aliceFingerprint,
    },
    transport: { send: bobToAlice.send, recv: aliceToBob.recv },
    mode: "nopin",
    pqMode: "hybrid-mlkem768",
    crypto: cryptoOptions,
  }),
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder();
console.log(
  decoder.decode(await bob.decrypt(await alice.encrypt(encoder.encode("hi")))),
);

// Plaintext secret: encrypt at rest and add rollback protection before storage.
const snapshot = await alice.serialize();
await alice.destroy();
const restoredAlice = await restoreSession(snapshot, cryptoOptions);
snapshot.fill(0);

const reply = await bob.encrypt(encoder.encode("after restore"));
console.log(decoder.decode(await restoredAlice.decrypt(reply)));

await Promise.all([restoredAlice.destroy(), bob.destroy()]);
aliceIdentity.ed25519SecretKey.fill(0);
aliceIdentity.x25519SecretKey.fill(0);
bobIdentity.ed25519SecretKey.fill(0);
bobIdentity.x25519SecretKey.fill(0);
```

In production, pin or explicitly TOFU-accept the peer's Ed25519 key and derive
the 32-byte endpoint fingerprints from the authenticated transport. The
`identity.x25519SecretKey` field is the X25519 identity-DH secret, never the
Ed25519 signing secret.

The complete two-peer transport example, including simultaneous first messages
and snapshot restore, is
[`examples/standalone-e2ee.ts`](examples/standalone-e2ee.ts):

```sh
bun run examples/standalone-e2ee.ts
```

The same source is included in the package as
`p2party/examples/standalone-e2ee.ts`. It detects whether it is running from a
source checkout or an installed package and uses the corresponding public
session build and release-matched WASM.

## Local, self-hosted, or release-pinned WASM

The browser root always fetches the exact versioned CDN WASM with a build-pinned
SHA-384 SRI value by default. A self-hosted browser app can point it at the
same release bytes before calling `connect()`:

```ts
import p2party from "p2party";

p2party.setWasmSourceUrl(
  new URL("/vendor/p2party-0.13.0/libcrypto.wasm", window.location.href),
);
```

The SRI check remains active, so a URL serving different bytes fails closed.
`p2party/session` additionally accepts local bytes, which is the recommended
Node, Bun, offline, and native path:

```ts
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { generateSessionIdentity } from "p2party/session";

const require = createRequire(import.meta.url);
const wasmBinary = Uint8Array.from(
  await readFile(require.resolve("p2party/libcrypto.wasm")),
);

const identity = await generateSessionIdentity({ wasmBinary });
```

The package also exports `p2party/libcrypto.provenance.json`. JavaScript and
WASM are one release unit; do not pair 0.12 code with an older module. Omitting
`wasmBinary` makes the session loader use the same immutable versioned CDN
artifact as the browser root. The release gate executes packaged identity
generation through both Node ESM and CommonJS, so non-browser entropy is tested
at runtime rather than inferred from successful imports.

## Development

The reproducible release toolchain is Node 24.11.1, npm 11.6.2, Bun 1.3.14,
Emscripten 6.0.2, and the repository's pinned libsodium source object. npm and
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
