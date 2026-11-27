# Getting started with p2party 0.15

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

Upgrade the signaling server to 0.2.0-rc.0 or a compatible protocol-5 release
before deploying this SDK. The peer handshake still uses protocol 4. When a
server explicitly reports an incompatible signaling version, `joinRoom()`
rejects with `SignalingVersionMismatchError` and the SDK stops reconnecting
to that endpoint. A server that rejects the HTTP upgrade before opening the
WebSocket can only surface a connection failure in the browser.

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
the capability. Signaling sends the SHA-512 digest of the normalized capability
as a stable room locator. The service can link connections that join the same room.

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
edge; the PIN-attempt limits below still apply.

### Failed PIN attempts

A wrong PIN shows up as a failed key confirmation. Each device limits these
failures per room in two layers. IndexedDB stores both under the locator derived from the room capability.

- **Per peer identity.** Failures are counted per room and per peer Ed25519
  identity. The first two cost nothing. From the third, that identity waits
  500 ms, doubling with each further failure up to five minutes. A successful
  PIN handshake clears its count.
- **Per room.** A five-minute window opens at the room's first failure. Once
  it holds 30 failures, the device refuses PIN handshakes with every identity
  that has never completed a PIN handshake with it in this room, until the
  window ends. The refused peer's status is `failed` with reason
  `pin-throttled`, and `retryAfter` is the window's end. Identities that have
  completed one are not refused by this window; their own per-identity limit
  still applies. Failures from any identity count toward the window, and a
  successful handshake does not close it.

What remains:

- An attacker who rotates fresh identities can fill the window over and over.
  While it is full, first-time joiners are refused for up to five minutes at a
  time; established members are not.
- Windows are fixed, not sliding. The long-run rate is 30 failures per five
  minutes, but up to 60 can land within seconds: 30 at the end of one window
  and 30 at the start of the next. Handshakes that were already running when
  the window filled are not stopped, so concurrent attempts can also push one
  window past 30.
- Authenticated status is not tied to the PIN. After a PIN change, a former
  member keeps its exemption from the room window and is limited only by its
  own per-identity backoff.
- If the device cannot read its PIN records, the attempt fails before the
  handshake as a transport failure and the edge re-dials. When the window
  write for a failure fails, the failure still counts in the open tab's copy
  of the window, but not after a reload.
- Calling `connect()` with a PIN for a room this page has already loaded
  clears both limits for that room and keeps its record of authenticated
  identities. Purging the room clears all three.
- **Reload against a hostile signaling server.** The same invite derives the same locator after a reload.
  The PIN failure window, identity backoff, and authenticated-peer record
  survive a change to the room UUID assigned by the server. Upgrading to
  signaling v5 discards PIN records keyed by the former server room IDs.

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
// The send is cancelled either way. The promise rejects with
// p2party.StorageFailedError when the browser refused to remove a file kept
// for the message (see "When a received file cannot be removed").
const cancel = () =>
  handle.cancel().catch((error: unknown) => {
    if (!(error instanceof p2party.StorageFailedError)) throw error;
    console.warn("cancelled, but still on this device:", error.failures);
  });

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
// It rejects as handle.cancel() does.
if (pending[0])
  try {
    await p2party.cancelPendingMessage(room.id, pending[0].transferId);
  } catch (error) {
    if (!(error instanceof p2party.StorageFailedError)) throw error;
    console.warn("cancelled, but still on this device:", error.failures);
  }
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

`deleteMessage` and `cancelMessage` take a Merkle root or a hash in one of two
forms: the 128 lower-case hexadecimal characters the SDK reports
(`merkleRootHex`, `sha512Hex`), or the 64 bytes those encode as a
`Uint8Array`. Any other form (upper-case hexadecimal, another length) rejects
with `p2party.InvalidMessageHashError` (`code` is `"invalid-message-hash"`,
`argument` is `"merkleRoot"` or `"hash"`) before anything is looked up.

### When a received message cannot be stored

A received chunk this device cannot store is not acknowledged. Its sender gets
no receipt for it and either retransmits it or reports that the transfer ended
without receiver confirmation. Subscribe to see why:

```ts
const stop = p2party.onReceiveStorageError((error) => {
  // error.code: "insufficient-quota" | "quota-exceeded" | "storage-failed"
  //             | "integrity" | "not-removed"
  console.warn(error.code, error.filename, error.fromPeerId, error.totalSize);
});
```

Each transfer and code is reported once, until a later chunk of that transfer
is stored again.

- `insufficient-quota`: before the first byte of a new transfer is written,
  its size is compared with the browser's free storage estimate
  (`quota - usage`). A larger transfer is refused and nothing is written;
  `requiredBytes` and `availableBytes` say by how much. If no estimate is
  available, the transfer is accepted and the next code covers a full disk.
  Two consequences for a room member, who may send any announced size:
  - The refusal is visible to the sender, who can learn roughly how much free
    storage this device has by announcing different sizes.
  - Once one chunk of a transfer is accepted, its file is sized to the
    announced total, so a member can reserve that much storage here until the
    transfer completes or expires after 24 hours without receive activity.
- `quota-exceeded`: the browser refused a write for lack of space.
- `storage-failed`: any other storage fault, including the database worker
  failing or the database being unavailable (see below). Once the database
  worker has failed, every later database call rejects at once with
  `p2party.DatabaseWorkerError`; the worker is not restarted, so the
  application should reload the page.
- `integrity`: the last chunk of a received file arrived, but the stored file
  does not hash to the whole-file SHA-512 its message carries. The file is not
  marked complete, the sender gets no final receipt, and its stored chunks are
  dropped. The progress shown for it returns to 0 at once. `readMessage` for
  that file throws `p2party.ReceiveIntegrityError` instead of returning bytes.
  Nothing is requested again while the connection stays up: every chunk was
  already acknowledged, so the sender only waits for the final receipt and
  then gives up. On the next connection the sender's resume finds that this
  device holds none of the file and sends it again in full; once that copy
  completes and verifies, the file reads normally. If the browser refuses to
  remove the dropped file, `not-removed` is reported as well.
- `not-removed`: the SDK deleted a message's records itself, and the browser
  refused to remove its file. `cause` is the browser's error. See "When a
  received file cannot be removed" below.

Each received file is verified once, when its last chunk arrives. That chunk
is stored and acknowledged, but held out of the file's progress until the
database worker has read the stored file once in chunk order, including the
last chunk as written, and hashed it. The hashing runs outside the
connection's receive queue, so chat messages, receipts and other transfers on
the same connection keep flowing, and the worker answers other requests
between reads of about 1 MiB. While it hashes, the receiver re-sends that
transfer's ordinary receipt (all chunks acknowledged, not complete) at most
once every 10 s (a third of the sender's 30 s silence bound), and only when
the hash has advanced since the receipt it last sent. A stuck verification
sends nothing, so the sender's silence bound ends its wait. What is visible on
the wire meanwhile:

- Immediate mode: the same 65-byte receipt frame the receiver already sent
  for the held last chunk, repeated on the transfer's message channel about
  every 10 s, then the final receipt. The repeats say a verification is still
  running. Their rate does not depend on how fast the device hashes, and they
  stop when it stalls.
- Scheduled mode: nothing new. The repeated token rides in a reverse cover
  cell, in a slot that would otherwise carry a dummy, so cell size and cadence
  are unchanged.

Nothing is re-sent for a verification that runs without its sender (at the
next start, below) until that sender reconnects. Only when the hash is done is
the file marked complete and the final receipt sent. If the connection to that peer is torn down first, or the
room is left, nothing completes on that connection. When the sender
reconnects while the file is still being verified, its copy of the last chunk
joins that verification and the file completes on the new connection. If that
connection's predecessor goes away meanwhile, only it leaves the verification;
the file is stopped only when no connection is left to complete it. A copy of
the last chunk that arrives while a stopped verification is still ending is
not turned away: it waits for that run to end, and the file is then verified
again from the start for the connection that brought it.

A file left unverified (the page was reloaded mid-verification, or its
connection went away) holds every byte it needs. It is verified without the
sender when the SDK loads its room to show it, with the same events and
outcomes. Loading several rooms queues those files: the files left over from
before are verified one after another. That queue is only for them. A file
whose last chunk arrives on a connection meanwhile is verified at once,
alongside it. Deleting a room starts none. If another tab of this site holds
the file (it is verifying or writing it), the file is tried again when that
tab's hold ends, and again each time the hold turns out to have been renewed,
for at most about 22 minutes (the longest a sender waits for a 10 GiB file);
after that it is left for the next time the room is loaded. A later copy of the last chunk is answered from the
recorded outcome. Reading a completed file later does not re-verify it. Text
messages are not verified as a whole; each of their chunks is checked against
the message's Merkle root as it arrives, like every file chunk.

### When a received file cannot be removed

A received file is plaintext on disk. It is one file in the SDK's directory of
the origin private file system (`p2party-reassembled`), named by its message's
Merkle root in hex. So is a partly received file, and the copy of a sent file
that is assembled when you read it back. (Where that file system is
unavailable the bytes stay in the database and go with the message's
records; nothing below applies.)

Deleting a message or a room stops a running verification of a file and then
removes it in two steps. First the message's records are deleted from the
database, in one transaction: its row, its chunk records, and with them its
place in the room's list. Then the file is removed. `p2party.purge()` removes
the whole directory and then deletes the database, whatever became of the
files. The browser can refuse to remove a file. HeadlessChrome 159 refuses to
remove a file, or a directory holding one, while any sync access handle or
writable stream on that file is open, in this tab or another, and leaves it as
it was (`NoModificationAllowedError`; measured by
`docs/e2e/opfs-remove/probe.mjs`, no other browser was measured). The SDK
closes its own handles, and waits for its own reads and writes of the file,
before it removes one, so in practice the file is one that another tab of
this site holds open.

When the file is refused:

- What is already gone: the message's records. The message is no longer
  listed, here or after a reload, `readMessage` no longer returns it, and a
  sender that resumes finds nothing of it on this device.
- What is still there: the file's bytes, in that directory, until a later
  removal succeeds. Nothing lists them and the SDK does not read them again.
- A refused removal is never reported as done, and is reported once per call,
  by one of two routes.

A call you make to delete rejects with `p2party.StorageFailedError`, after
everything else it had to do was done. `failures` lists each file that is
still on disk: `merkleRootHex`, and `error`, which is an `Error` with the
`name` and `message` the browser threw. No event is raised for it.

- `p2party.deleteMessage(roomId, merkleRoot)` and
  `p2party.cancelMessage(roomId, channelLabel, merkleRoot)`: `cause` is the
  browser's error for the one file.
- `handle.cancel()` and `p2party.cancelPendingMessage(roomId, transferId)`:
  both cancel through `cancelMessage` and reject as it does. The send is
  cancelled; the file is the copy of the sent file that was assembled when
  you read it back.
- `p2party.disconnectFromRoom(roomId, true)` and
  `p2party.disconnectFromAllRooms(true, exceptRoomIds)`: every other message
  and room was removed; `cause` is what the deletes threw.
- `p2party.purgeRoom(roomUrl)`: every other step was done (the room, its
  connections, its pins).
- `p2party.purge()`: every other step was done (the database, the rooms, the
  identity), and every file that could be removed was removed.

A removal the SDK started itself is reported through
`p2party.onReceiveStorageError` with the code `not-removed`; `cause` is the
browser's error. That covers a `deleteMessage` action you dispatch to the
store yourself, `p2party.blacklistPeer`, a peer cancelling or abandoning a
transfer it was sending, an incomplete receive expiring after 24 hours, a
file dropped after it failed verification, and the retries described below
that the SDK makes itself. A file is reported once per page load, and again
only after a chunk of it has been stored again.
A report raised before your application subscribed is given to the first
listener when it subscribes. The retry at start reads `roomId`, `fromPeerId`,
`filename` and `totalSize` from whatever record is left, so they can be empty
or 0.

A call that is not a delete returns its result. `p2party.listPendingMessages`
and `resumePendingMessages` run the storage sweep, report a file the sweep
could not remove through the event, and still return what they return
otherwise. `cancelPendingMessage` runs the sweep too: a file of another
message that the sweep could not remove is reported through the event, and
only a file of the message it cancels rejects the call.

The removal is tried again without a purge:

- Every time the SDK's database worker starts, which is once per page load.
  If a room purge was interrupted after its room record was deleted, the
  worker resumes deletion under each available file lock. Rejoining the room
  under the same ID before recovery preserves its remaining messages. The
  worker also lists the directory and removes every file that no record owns. A file
  another tab is receiving, verifying or reading has its records and is left
  alone. Requests that create, read or remove a file wait for this pass, for
  at most 5 seconds; after that they are served while the pass goes on. The
  pass decides each removal while it holds the file's lock, from the records
  as they are at that moment, so a file whose receive started meanwhile is
  kept.
- When you repeat the call with the same arguments, in the same session or
  after a reload. The message or the room is no longer listed; the call
  finds what it left and tries the file again. It rejects as before while the
  browser refuses a file that the call can identify as pending.
  - `deleteMessage` and `cancelMessage`: by the Merkle root, the hash or (for
    `cancelMessage`, `handle.cancel()` and `cancelPendingMessage`) the
    transfer ID the first call used.
  - `disconnectFromRoom(roomId, true)`: every file an earlier delete of that
    room's messages left.
  - `disconnectFromAllRooms(true, exceptRoomIds)`: the same for every room,
    listed or not, the excepted ones aside.
  - `purgeRoom(roomUrl)`: every file the room's messages left, also when the
    room itself was already removed. Repeating the purge waits for the file
    locks and finishes an interrupted removal. Pending rows carry a SHA-512
    digest of a fixed prefix and the room URL. A successful removal clears
    this digest from the transfer record.
  - `purge()`: every file.
- When the storage sweep comes back to a deleted transfer after 24 hours.

A repeated call acts only on what the room it names left behind. It resolves
without touching anything when a record owns the file again (the same message
is being received again, in this tab or another), and when the records name
another room for it: `deleteMessage(roomId, merkleRoot)` never removes a file
of another room's message, listed or left behind. So "resolved" from a
repeated call means that nothing this room left under that name is on disk,
not that no file with that name exists. A file that no record names at all
(what `purge()` leaves when it is refused) is tried again by a
`deleteMessage` that names its Merkle root, whatever room it names.

What your application can do: tell the user that the file is still on this
device, ask them to close the site's other tabs, and repeat the call or reload
the page. Keep the Merkle roots from `failures` if you want to repeat
`deleteMessage` for them, since the messages are not listed any more.

The database stays usable across tabs of different versions in one
direction. A tab of this version closes its database connection when another
tab needs to upgrade the database. When this version's own upgrade is blocked
by an older tab that keeps its connection open, calls that need the database
fail at once instead of waiting: those that report errors reject with
`p2party.DatabaseUpgradeBlockedError` (a `p2party.DatabaseUnavailableError`),
some lookups return an empty result, and received chunks are reported as
`storage-failed`. Ask the user to close the site's other tabs and reload.
After this upgrade, a tab using the previous database schema must reload
with the updated SDK to open the database.

The first received file in a page also asks the browser once for persistent
storage (`navigator.storage.persist()`), so storage pressure does not evict a
partly received file. The answer is not awaited, and a refusal changes nothing
else. Firefox may show a permission prompt.

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

## Saving and blocking peers

Save a verified identity with `addPeerToAddressBook(username, peerId, peerPublicKey)`
or block it with `blacklistPeer(peerId, peerPublicKey)`. Supply its Ed25519 public
key (64 lowercase hexadecimal characters) to `getPeerAddressBookEntry`,
`getPeerIsBlacklisted`, `deletePeerFromAddressBook` and `removePeerFromBlacklist`.
An ID alone raises `TypeError`. Stored entries keep their key when a signaling
server reassigns IDs. The SDK checks that key again after the peer authenticates
and before its encrypted connection opens.
