# Getting started with p2party 0.14

p2party has two entry points:

- `p2party` owns the browser room mesh: signaling, WebRTC, Redux state,
  IndexedDB, OPFS when available, the protocol-v4 handshake, and message
  transfer.
- `p2party/session` owns only the protocol-v4 handshake and message
  cryptography. Use it with Node, Bun, a native shell, tests, or your own
  transport and storage.

Install is in the [README](../README.md#install). This guide assumes you have
the package and picks up from there.

## Browser room mesh

The root entry point requires a browser with WebRTC, WebAssembly, WebCrypto,
Worker, and IndexedDB. OPFS is optional; the receive path falls back to
IndexedDB when it is unavailable.

```ts
import p2party from "p2party";

const invite = p2party.generateRoomInvite();
const room = await p2party.joinRoom(invite);

console.log("joined room", room.id);
```

`joinRoom()` is `connect()` plus a wait for the signaling service to assign the
room its id. Use the two separately when you want to render a joining state, or
when you need a deadline or cancellation:

```ts
await p2party.connect(invite);
const room = await p2party.waitForRoom(invite, {
  timeoutMs: 10_000,
  signal: controller.signal,
});
```

Every peer that joins the same room is connected to every other present peer.
The signaling service coordinates discovery and WebRTC setup; it is not the
message hub. A room with `n` participants therefore has up to `n(n - 1) / 2`
peer edges.

`connect()` resolving does not by itself mean that every peer edge has
completed protocol-v4 authentication. The library gates message cryptography on
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

The SDK retries an unexpectedly closed signaling socket with bounded backoff.
Let that controller own recovery: do not call `connect()` on every disconnected
render or browser focus event. Call it for initial admission and a deliberate
retry, such as entering a corrected PIN. Terminal PIN or policy failures stay
visible and do not trigger automatic peer discovery or transport retries.
A fresh connection request from the other peer can retry that peer's failed
edge; the existing PIN-attempt throttle still applies.

Scheduled timing cover is wired as of 0.14: a policy may pin `coverMode:
"scheduled"` with a cadence, lane count, and frames per cell, and every edge in
the room then emits fixed-size cells on that schedule whether or not data is
queued. Private rendezvous modes are still rejected by `connect()` because
their live transport wiring is not complete.

## Send, cancel, and read

Wait until the room has known recipient identities before sending. Each logical
send has a random transfer ID. Immediate mode opens a per-message data channel
on each eligible edge; scheduled mode places its chunks into the existing
fixed-cadence cover lanes.

```ts
const handle = p2party.sendMessage("hello room", "chat", room.id);

console.log("transfer", handle.transferId);

// Wire this to a cancel button. It also works during hashing/channel setup.
const cancel = () => handle.cancel();

try {
  const result = await handle.done;
  console.table(result?.outcomes);

  const opened = await p2party.readMessage(result!.merkleRootHex);
  console.log(opened.message, opened.percentage);
} catch (error) {
  // `done` REJECTS when no peer took delivery — an empty room, or a cancel.
  // Both are ordinary outcomes, not bugs. The error carries the same per-peer
  // detail a resolved value would have.
  if (error instanceof p2party.MessageDeliveryError)
    console.table(error.result.outcomes);
}

void cancel; // Remove when a UI event uses it.
```

`sendMessage()` returns a `MessageTransferHandle`, not a promise. `done`
settles after all started peer sends and cleanup and reports ordered per-peer
outcomes for that attempt. A peer may be delivered, failed during setup/transfer,
or skipped because it is disconnected, unauthenticated, or the transfer was
cancelled. A rejected attempt can still have a durable pending transfer: do not
label it delivered, or assume that its resend source was discarded.

The sender publishes its outbox record only after every staged chunk, the
Merkle tree, and its local message copy have committed. A reload before that
point cannot resume preparation; select the original file again. After
publication, a reload or an exhausted reconnect budget retains the original
transfer ID, Merkle root and staged bytes for retry. Nothing is rehashed or
randomly repadded on a resumed send.

```ts
import type { PendingMessage } from "p2party";

const pending: PendingMessage[] = await p2party.listPendingMessages(room.id);
for (const message of pending) {
  console.log(message.filename, message.phase, message.remainingRecipients);
}

// Use a deliberate retry button. It may take the room's scheduled delivery
// time to settle; leave cancellation available while this promise is pending.
try {
  const attempts = await p2party.resumePendingMessages(room.id);
  for (const attempt of attempts) console.table(attempt.outcomes);
} catch (error) {
  // AggregateError.errors contains failed attempts; their pending records stay
  // available unless explicitly cancelled or expired.
  console.error(error);
}

// Exact logical-send cancellation also works after the original handle was
// lost to a reload. It fences queued writes before removing retained staging.
if (pending[0])
  await p2party.cancelPendingMessage(room.id, pending[0].transferId);
```

Authenticated-peer events trigger a serialized retry pass, including a bounded
claim after an old tab's lease expires. A failed pass does not start an endless
retry timer. Explicit retry requires verified signaling and a matching
currently authenticated recipient; it never calls `connect()`, prompts for a
passkey, or supplies a PIN. A PIN room must first be admitted with the user's
current in-memory PIN. PIN and policy failures remain terminal until a deliberate
authentication retry.

The immutable outbox binds the sender's public key and durable identity
revision, room capability and canonical policy, channel, and recipient public
keys. Session peer IDs may change. Only one tab can own a transfer's 30-second
lease at a time; it renews every 10 seconds. A stale tab cannot publish queued
writes or renew a replacement owner's lease. Terminal signaling refusal stops
its current owners, and switching identity invalidates the old outbox.

Confirmed recipients are recorded separately and never retried. A recipient's
explicit cancellation also ends retries to that recipient without cancelling
other recipients. Immediate retries rebuild the have-set from authenticated
receipt replay, so older receivers that discarded a closed channel's partial
can still recover. Scheduled retries preserve the receipt bitmap and send
missing chunks plus at most one already-received real chunk as a completion
probe. The fixed cover cadence and lane count remain unchanged.

Retention and admission have explicit limits:

- Published pending transfers expire 24 hours after publication. Active owners
  are protected while they run; a completed recipient is never reported as a
  new delivery merely because staging remains.
- Interrupted preparation expires after one hour. Its `phase` remains
  `"staging"`; an expired `retryAfter` means its owner is gone, not that the
  unfinished file can resume.
- At most 32 pending transfers and 64 recipients per transfer are admitted.
  Their aggregate storage reservation is capped at 12 GiB and charges padded
  cells, metadata, proofs and the sender's local copy. Browser quota can impose
  a smaller limit than the 10 GiB per-message protocol maximum. Admission
  refuses excess work rather than evicting another pending send.
- Incomplete received transfers expire after 24 hours without local receive
  activity. Cleanup uses the device's activity clock, not the sender's message
  timestamp. It protects active writes, completed messages and sender copies,
  checks the room/receive owner, and fences writes queued before cancellation.

Storage sweeps run when pending transfers are listed or an authentication event
checks for resumable work. Maintenance runs immediately on the first check,
then at most once every 30 seconds, and defers while receive queues are busy.
Committed expiry also removes the old room view and retires its mapped receive
key, preserving newer receives and connection generations.
Cancelling or deleting a message removes its pending
outbox; leaving a room discards that room's pending work. Successful completion
removes resend staging while retaining completed local history.

The outbox reuses the already-staged message bytes in browser storage; it is
not a new encryption-at-rest guarantee for files or message history. It stores
no PIN, passkey assertion, plaintext ratchet key or message key. A resumed send
derives fresh message encryption state from the currently authenticated edge.

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

## Back up and restore an identity

The identity behind every room is an Ed25519 key pair in browser storage, and
only an identity created from a recovery phrase can be brought back after that
storage is gone. `getIdentityBackupStatus()` says which kind is in use,
`createRecoverableIdentity()` replaces the current identity with one a phrase
reproduces and returns that phrase exactly once, and
`restoreIdentityFromMnemonic()` adopts the identity a phrase encodes. The
derivation is one way — an identity generated randomly, which is every identity
that existed before these calls, cannot be exported to a phrase — and both
calls replace the account key, so contacts see an identity change and signaling
is left disconnected until you `connect()` again. The full contract, including
what survives a restore and what a mistyped phrase costs, is in the
[README](../README.md#back-up-and-restore-your-identity).

## Package artifacts and WASM

The 0.14 package exports:

- `p2party` — browser ESM/CJS root with declarations;
- `p2party/session` — store-free ESM/CJS session API with declarations;
- `p2party/libcrypto.wasm` — the exact compiled cryptographic module;
- `p2party/libcrypto.provenance.json` — source/toolchain/digest provenance;
- `p2party/docs/getting-started.md`, `p2party/docs/session-api.md`, and
  `p2party/docs/protocol-v4-security.md` — installed developer and threat-model
  documentation;
- `p2party/examples/standalone-e2ee.ts` — a runnable source-checkout and
  installed-package session example;
- `p2party/THIRD_PARTY_NOTICES.md`; and
- `p2party/package.json`.

The tarball also contains the UMD browser build and generated database worker.
The root bundle embeds the worker source; normal package consumers do not
construct its URL.

The browser root fetches the exact versioned CDN WASM under a build-pinned
SHA-384 Subresource Integrity value. JavaScript and WASM are one release unit —
never pair 0.14 JavaScript with an older WASM.

Self-hosting those bytes, and passing them directly to `p2party/session`, are
both covered in the
[README](../README.md#local-self-hosted-or-release-pinned-wasm).
