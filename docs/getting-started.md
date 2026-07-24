# Getting started with p2party 0.12

p2party has two entry points:

- `p2party` owns the browser room mesh: signaling, WebRTC, Redux state,
  IndexedDB, OPFS when available, the protocol-v3 handshake, and message
  transfer.
- `p2party/session` owns only the protocol-v3 handshake and message
  cryptography. Use it with Node, Bun, a native shell, tests, or your own
  transport and storage.

Until `v0.12.0` publishes the registry and CDN artifacts, build and install the
reproducible release candidate from a source checkout:

```sh
npm ci
npm run release:pack
npm install ./p2party-0.12.0.tgz
```

After the tagged release:

```sh
npm install p2party@0.12.0
```

## Browser room mesh

The root entry point requires a browser with WebRTC, WebAssembly, WebCrypto,
Worker, and IndexedDB. OPFS is optional; the receive path falls back to
IndexedDB when it is unavailable.

```ts
import p2party, { type Room } from "p2party";

const invite = p2party.generateRoomInvite();
const roomContext = p2party.normalizeRoomCapability(invite);

await p2party.connect(invite);

// connect() starts the join. Observe the store for the signaling-assigned ID.
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

console.log("joined room", room.id);
```

Every peer that joins the same room is connected to every other present peer.
The signaling service coordinates discovery and WebRTC setup; it is not the
message hub. A room with `n` participants therefore has up to `n(n - 1) / 2`
peer edges.

`connect()` resolving does not by itself mean that every peer edge has
completed protocol-v3 authentication. The library gates message cryptography on
the authenticated handshake. A UI should render peer and message state from
the exported store rather than treating `connect()` as a global room-ready
event.

## Compact, fragment, and word invites

Generate one capability and derive every presentation from the same bytes:

```ts
const capability = p2party.generateRoomCapability();

const compact = p2party.encodeRoomCapabilityBase64Url(capability); // 43 chars
const fragment = p2party.encodeRoomInviteFragment(capability); // v1.<compact>
const words = await p2party.encodeRoomCapabilityWords(capability); // 24 words

const fromCompact = p2party.decodeRoomCapabilityBase64Url(compact);
const fromFragment = p2party.decodeRoomInviteFragment(`#${fragment}`);
const fromWords = await p2party.decodeRoomCapabilityWords(words);

await p2party.connect(fragment);
```

`generateRoomInvite()` is the one-line form when only the versioned fragment is
needed. Put it after `#` in an HTTPS URL so ordinary HTTP requests do not carry
the capability. The current `legacy-signaling` connection path still sends a
normalized form to the signaling service, so this is not server-blind
rendezvous.

The word form is a checksum-protected encoding of the same 256-bit capability,
not a lower-entropy replacement. Its fixed word-list identifier is exported as
`ROOM_INVITE_WORDLIST_ID`.

## PIN room with an exact ML-KEM suite

Room policy is immutable after local room creation. Every peer must use the
same policy and the same PIN bytes. The suite is fixed before the handshake;
there is no in-band negotiation, downgrade, or classical fallback.

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
  // connect() copied it into the in-memory room vault.
  pin.fill(0);
}
```

The exact supported `pqMode` values are `hybrid-mlkem512`,
`hybrid-mlkem768`, and `hybrid-mlkem1024`; ML-KEM-768 is the default. PIN
bytes are deliberately absent from the public policy, Redux, persistent room
records, and logs. PIN mode adds CPace authentication to the identity and
ML-KEM handshake; it does not replace identity possession.

The policy schema can encode `scheduled` cover and private rendezvous modes,
but the public 0.12 `connect()` path rejects those modes because their live
transport wiring is not complete.

## Send, cancel, and read

Wait until the room has peers before sending. Each logical send has a random
transfer ID and opens a per-message data channel on every eligible peer edge.

```ts
const handle = p2party.sendMessage("hello room", "chat", room.id);

console.log("transfer", handle.transferId);

// Wire this to a cancel button. It also works during hashing/channel setup.
const cancel = () => handle.cancel();

const result = await handle.done;
if (result) {
  console.table(result.outcomes);

  const opened = await p2party.readMessage(result.merkleRootHex);
  console.log(opened.message, opened.percentage);
}

void cancel; // Remove when a UI event uses it.
```

`sendMessage()` returns a `MessageTransferHandle`, not a promise. `done`
settles after all started peer sends and cleanup and reports ordered per-peer
outcomes. A peer may be delivered, failed during setup/transfer, or skipped
because it is disconnected, unauthenticated, or the transfer was cancelled.

For an inbound message, take `merkleRootHex` (and, if needed, `sha512Hex`) from
the room's exported `messages` state:

```ts
const rooms = p2party.roomSelector(p2party.store.getState());
const message = rooms
  .find((candidate) => candidate.id === room.id)
  ?.messages.at(-1);

if (message) {
  const metadataOnly = await p2party.readMessage(
    message.merkleRootHex,
    message.sha512Hex,
    false,
  );
  console.log(metadataOnly.filename, metadataOnly.size);
}
```

`materialize = false` avoids assembling a completed file Blob; text is always
returned. The application limit is 10 GiB. Cancellation is scoped most
precisely by the handle's transfer ID, so prefer `handle.cancel()` over a
content-hash lookup for concurrent identical sends.

## Package artifacts and WASM

The 0.12 package exports:

- `p2party` — browser ESM/CJS root with declarations;
- `p2party/session` — store-free ESM/CJS session API with declarations;
- `p2party/libcrypto.wasm` — the exact compiled cryptographic module;
- `p2party/libcrypto.provenance.json` — source/toolchain/digest provenance;
- `p2party/THIRD_PARTY_NOTICES.md`; and
- `p2party/package.json`.

The tarball also contains the UMD browser build and generated database worker.
The root bundle embeds the worker source; normal package consumers do not
construct its URL.

The browser root loads
`https://cdn.p2party.com/@0.12.0/libcrypto.wasm` with a build-pinned SHA-384
Subresource Integrity value. JavaScript and WASM versions are one release unit:
never pair 0.12 JavaScript with an older WASM. The release workflow publishes
the immutable CDN object, fetches it back, verifies its bytes, SHA-256, and SRI,
and only then publishes npm.

The browser root can use a self-hosted copy of the exact release bytes. Set its
URL before `connect()` or any cryptographic operation; the build-pinned SRI
still applies:

```ts
import p2party from "p2party";

p2party.setWasmSourceUrl(
  new URL("/vendor/p2party-0.12.0/libcrypto.wasm", window.location.href),
);
```

Offline, Node, and Bun applications should use `p2party/session` and pass the
exported bytes:

```ts
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const wasmBinary = Uint8Array.from(
  await readFile(require.resolve("p2party/libcrypto.wasm")),
);

const cryptoOptions = { wasmBinary };
```

In a browser application using only `p2party/session`, fetch a pinned local
asset and pass its `ArrayBuffer` in the same field:

```ts
const response = await fetch("/vendor/p2party-0.12.0/libcrypto.wasm");
if (!response.ok) throw new Error(`WASM fetch failed: ${response.status}`);
const cryptoOptions = { wasmBinary: await response.arrayBuffer() };
```

See [Store-free session API](session-api.md) for the transport and snapshot
contract and [Protocol-v3 security](protocol-v3-security.md) before deciding
what metadata your deployment exposes.
