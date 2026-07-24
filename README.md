# p2party

Protocol-v3 end-to-end encryption and reliable file transfer over a WebRTC
room mesh.

[![npm](https://img.shields.io/npm/v/p2party)](https://www.npmjs.com/package/p2party)
[![license](https://img.shields.io/npm/l/p2party)](LICENSE.md)

> Status: protocol v3 is an intentional wire break. The current code has not
> completed an independent third-party security audit.

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
- Message data travels in fixed 65,490-byte protocol-v3 frames. Cryptographic
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
default. The room-policy schema also describes scheduled timing cover and
opaque/blind meeting points, but the public `connect()` path rejects those
modes because their transport wiring is not complete. An internal sparse
post-quantum healing state-machine core is implemented and tested; production
crash-safe persistence, authenticated control routing, message-key integration,
and scheduler wiring remain gated. The private BitTorrent extension is likewise
a research direction, not a shipped property.

The current signaling operator can observe room membership, peer identities,
network metadata, and timing. Fixed message cells and in-transfer decoys do not
by themselves provide continuous traffic-analysis resistance.

## Install

Until the `v0.12.0` tag publishes the registry and immutable CDN artifacts,
install the reproducible release candidate from this checkout:

```sh
npm ci
npm run release:pack
npm install ./p2party-0.12.0.tgz
```

After the tagged release:

```sh
npm install p2party@0.12.0
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
- [Protocol-v3 security boundary](docs/protocol-v3-security.md)

## Browser mesh

The browser root connects every peer present in the same room to every other
peer. `connect()` starts the join; observe the exported store for the
signaling-assigned room ID.

```ts
import p2party, { type Room } from "p2party";

const invite = p2party.generateRoomInvite();
const roomContext = p2party.normalizeRoomCapability(invite);
await p2party.connect(invite);

const room = await new Promise<Room>((resolve) => {
  let unsubscribe = () => {};
  const inspect = () => {
    const candidate = p2party
      .roomSelector(p2party.store.getState())
      .find((item) => item.url === roomContext);
    if (!candidate?.id) return;
    unsubscribe();
    resolve(candidate);
  };
  unsubscribe = p2party.store.subscribe(inspect);
  inspect();
});

console.log("joined", room.id);
```

An open RTCDataChannel means its DTLS/SCTP transport is ready. It is not the
protocol-v3 acknowledgement: p2party next runs its authenticated HELLO plus
three chained confirmation flights over the main channel. Message receipts are
a third, delivery-level acknowledgement.

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

## Local, self-hosted, or release-pinned WASM

The browser root always fetches the exact versioned CDN WASM with a build-pinned
SHA-384 SRI value by default. A self-hosted browser app can point it at the
same release bytes before calling `connect()`:

```ts
import p2party from "p2party";

p2party.setWasmSourceUrl(
  new URL("/vendor/p2party-0.12.0/libcrypto.wasm", window.location.href),
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
