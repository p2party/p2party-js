# Changelog

All notable changes to the **p2party** SDK are documented here. This project
adheres to [Semantic Versioning](https://semver.org/) and the spirit of
[Keep a Changelog](https://keepachangelog.com/).

## [0.14.7] — 2026-09-03

Three recovery gaps left open by 0.14.5, each one a case where the software
waited instead of acting. Still protocol v4; no wire shape changes. The room
PIN feedback needs a re-vendored app to be visible, and nothing here needs a
signaling-server change.

### Fixed

- An edge that re-authenticates in place now has ten seconds to finish. When a
  peer that slept comes back and re-binds its surviving connection, the peer's
  new handshake can be unreachable on that connection: its stream association
  accepts our new channels and not theirs. Recovery used to wait out the
  thirty-second handshake step timeout. It now rebuilds the edge at the
  deadline, which took a sleeping responder carrying an eight-mebibyte transfer
  from 37.5 seconds to 17.5 seconds, measured three times with identical
  results, transfer byte-exact and the sender reporting delivered.

- A room PIN that is rejected is now something you can see and answer. The SDK
  already classified the failure, but a rejected joiner is dropped from the
  roster before the app can attach the failure to anyone, so the room merely
  looked empty and the PIN could not be typed again. A handshake failure now
  carries the peer's stable Ed25519 identity, which is what lets an app show a
  rejected join without resurrecting a stale warning for a peer that has since
  reconnected under a new signaling id.

- An active room with nobody in it now asks again. A verified socket whose
  roster is empty, or whose peers have never authenticated, re-requests the
  room's peers on a backoff that stops the moment one appears, and never runs
  for an inactive room or an unverified socket. Recovery could not come from an
  inbound frame: the server answers a peer request by introducing you to the
  other members and sending the requester nothing, so a client whose
  introductions were lost had nothing to react to. Two healthy sockets could sit
  either side of an empty room indefinitely.

### Verification

The reproduction harness in `docs/e2e/desync/` gained a `--socket=stranded`
mode, which keeps a frozen client registered while cutting its signalling in
both directions until well past the thaw. It is the first scenario to leave two
healthy sockets with two empty rosters and no inbound frame able to start the
recovery, which is what the roster reconciliation had to be measured against:
both identity roles converge about six seconds after the fault clears, where
the same configuration previously never recovered at all. The relay's heartbeat
now goes through the same drop gate as every routed frame, because a real
network fault does not spare pings and sparing them was what made the client's
own liveness watchdog untestable.

Eight regression scenarios were re-run unchanged: baseline and socket-drop at
half a second, the twenty-second freeze in both identity roles with the socket
dropped and with it kept, the forty-five-second freeze, and both in-flight
transfer directions, all byte-exact.

### Changed

- The Emscripten pin moves 6.0.3 → 6.0.9, in `scripts/buildRelease.mjs`, both
  GitHub workflows and the two documents that state the toolchain. This closes
  a gap rather than opening one: 0.14.5 and 0.14.6 were packaged by hand around
  the version gate, against a compiler newer than the pin, so their provenance
  recorded a toolchain the README did not promise. The release script now runs
  its own validation again, and the version it enforces is the version the
  provenance records.

  The release artifact is unchanged by the move. `libcrypto.wasm` is
  byte-identical to the one 6.0.8 produced — 211,350 bytes, the same SHA-256
  and the same pinned SRI — so the optimized output converges across those two
  compiler releases even though the development build, which carries assertions
  and heap checks, does not. Only the attestation changed, and it now names the
  compiler the pin enforces.

- The release script no longer fails on the one documentation line it owns.
  `syncDocumentedIntegrity` rewrites the README's pasteable bundle `src`,
  version included, so that the pinned hash and the URL naming its build stay a
  matched pair — but the stale-version scan ran first and rejected exactly that
  line, so no release could pass validation without hand-editing it. That was
  the manual step the sync exists to remove. The scan now skips it and judges
  every other reference as before.

### Deployment note

No signaling-server change. An app must re-vendor this SDK for the PIN failure
to reach its interface, because the app reads the new identity field on a
handshake failure.

## [0.14.6] — 2026-09-03

Identity backup and restore. An identity lived in exactly one browser profile:
losing the profile lost the account, and the phrase-to-key derivation that could
have prevented that was exported but unreachable — nothing in the SDK ever
created a _stored_ identity from a phrase. These calls close that gap in the one
direction the derivation runs. Still protocol v4; no wire shape changes.

What the feature cannot do is as much of this release as what it can. Only an
identity **created** from a recovery phrase can be restored from one. The
derivation runs one way, so an identity that already exists — every identity the
SDK has generated to date, and every one it still generates on first connect —
cannot be exported to a phrase at all; the only route to a recoverable identity
is `createRecoverableIdentity()`, which _replaces_ the current one. Restoring is
not a merge either: it adopts the phrase's identity in place of whatever that
device held, and deletes the cross-signed X25519 identity so the next connection
regenerates and re-signs it. Contacts see both as an identity-key change,
exactly as they would after a purge.

### Added

- `createRecoverableIdentity({ strength?, password? })` replaces the identity in
  use with one derived from a fresh recovery phrase, and returns that phrase
  exactly once — 24 words by default, 12 at `strength: 128`. Neither the SDK nor
  its storage keeps a copy, by design: a phrase at rest is the identity at rest.
  The optional password is folded into the derivation and is never stored or
  checked, so restoring with a different one silently derives a different
  identity.

- `restoreIdentityFromMnemonic(mnemonic, password?)` adopts the identity a
  phrase encodes. The phrase is validated and derived before anything is torn
  down, so a mistyped one rejects with the new `InvalidRecoveryPhraseError`
  having disconnected nothing, and argon2id does not run holding the global
  lock. Only a phrase that derives a key opens the exclusive boundary a purge
  takes: no connection attempt, room operation or identity bootstrap can
  interleave, and any in-flight attempt is cancelled before it can write the
  outgoing identity back to storage. Inside it, signaling is disconnected, every
  room's WebRTC transport is brought to a terminal state, and the cross-signed
  X25519 identity is deleted for the next bootstrap to regenerate and re-sign —
  all three settle even when one fails, and a failure there aborts the swap
  rather than moving the identity out from under a transport that may still be
  live. The Ed25519 key is persisted before the in-memory identity is adopted,
  so a key that could not be stored never survives only until a reload. Rooms,
  messages, the address book and cached room PINs are kept, so the caller can
  reconnect to the same rooms; peers see the identity-key change exactly as they
  would after a purge. Signaling is left disconnected — call `connect()`
  afterwards.

- `getIdentityBackupStatus()` reports the current Ed25519 public key and whether
  a phrase can reproduce it, without requiring a connection first. The
  provenance is recorded at rest bound to the key it describes, and a flag that
  no longer binds to the stored key is reported as unknown rather than carried
  over: claiming recoverability for a key that was never derived from a phrase
  would hand the user a backup that restores someone else's identity. A newly
  generated identity — and the adopted legacy `localStorage` one — is recorded
  as `"random"`; an identity already in storage before this shipped has no
  record and reads `null`. Neither can be exported, and the only route to a
  recoverable one is to replace it.

- Identity-derivation provenance is persisted, because how an account key came
  into being is not derivable from the key and has to survive a reload. It is a
  non-secret record under a new `identityDerivation` id in the existing
  out-of-line `meta` store — no schema change, no `dbVersion` bump — carrying a
  record version, the flag, and the 32-byte Ed25519 public key it was written
  against. That binding is read inside the same transaction that writes the
  flag, so a concurrent rotation cannot be recorded as the key the claim
  describes. Bootstrap writes `"random"` on both paths that install an
  unrecoverable key, `createRecoverableIdentity()` and
  `restoreIdentityFromMnemonic()` write `"mnemonic"`, and the identity purge
  deletes the record as its own settlement step, after the key it describes is
  gone. A malformed row, a future record version, or a binding that no longer
  matches the stored key all read back as `null` rather than throwing: no
  protocol step depends on the value, so failing signaling bootstrap over it
  would be the worse error, and the fail-safe reading of an unreadable
  provenance hint is "this cannot be promised recoverable".

- `validateMnemonicWords(words)` and `validateMnemonic(phrase)` are exported.
  The first is synchronous — word count and wordlist membership, naming the
  first mistyped word — so a restore form can check on every keystroke; the
  checksum needs SHA-512, which Web Crypto only exposes asynchronously. The
  `MnemonicValidation`, `CreatedRecoverableIdentity`,
  `CreateRecoverableIdentityOptions`, `RestoredIdentity` and
  `IdentityDerivation` types are exported with them.
  `src/cryptography/mnemonic.ts` also gains `normalizeMnemonic(phrase)` and
  `validateMnemonicPhrase(phrase)` — the normalisation the derivation contract
  is now stated in terms of, and the full check reported in the same shape as
  the synchronous one — as module exports, not package-root ones.

### Changed

- Recovery-phrase normalisation is now part of the derivation contract: NFKD,
  runs of whitespace collapsed to one space, trimmed, lowercased. A phrase
  transcribed from paper or a password manager arrives with a trailing newline,
  a double space or an autocapitalised first word, and the wordlist lookup used
  to reject all of those outright. How a phrase was typed can no longer change
  the identity it restores. Every phrase that derived a key before was already
  canonical, so no existing backup changes meaning, and a known-answer test pins
  the public key of a fixed phrase to prove it.

- The mnemonic module is runtime-agnostic. It reached for `window.crypto`, which
  does not exist under Bun, Node or a worker, so every mnemonic path threw
  outside a document and none of it was covered by a test; it now goes through
  `globalThis.crypto` and fails loudly when Web Crypto is missing.
  `keyPairFromMnemonic()` also accepts an optional preloaded WASM module, like
  every other operation helper. Argon2id parameters and the salt scheme are
  untouched.

- Secrets on the mnemonic path are wiped: the argon2id seed and the salt after
  the key pair is built, the encoded password and its digest after the salt is
  taken, and the entropy and its hash after the words are formed.

- Documentation, no behaviour change: the recovery-phrase documentation
  described primitives nobody could reach, and now describes the shipped flow
  and what it costs — an identity created randomly cannot be exported, and
  becoming recoverable means replacing it, which contacts see as an
  identity-key change. The README's backup section states in the place a user
  looks for it that these phrases borrow the BIP-39 English words and nothing
  else, so no BIP-39 wallet restores one of these identities; 0.14.5 had already
  corrected the encoding claims themselves, and `docs/references.md` now says
  which of the two encodings sharing that wordlist is the one that restores an
  identity. `docs/getting-started.md` points at the contract, ADR-A1 in
  `docs/design-decisions-and-security-findings.md` records the shipped state and
  the one-way ("option A") decision, and `ROADMAP.md` no longer lists the SDK
  flow as missing.

### Verification

`npm run check` green on the release commit: lint, format:check, both typecheck
projects, 1224 tests / 0 failures across 146 files, and the standalone session
example printing OK.

Recorded 2026-09-03, before this release commit: a 17-step run through the real
app UI in headless Chromium, against the local signaling stack and a tarball
packed by hand from this source. Creating an identity from a phrase replaces the
random one; the phrase panel keeps its Done control disabled until the
written-it-down checkbox is ticked; a second peer joins, messages go byte-exact
in both directions, and the peer saves the contact; the first device is dropped
entirely; a fresh browser context restores from the 24 words and derives the
identical Ed25519 key; it rejoins under the same peer id, which the server
reissues because the key is reproduced exactly; messages flow byte-exact again;
and the peer's client raises no identity-key-change warning, because the key did
not change.

Not covered: that run is a recorded manual one, n = 2 over loopback, and is not
in the automated suite. Nothing migrates the identities already in the field —
one created before this release still reads `null` and still cannot be exported.

### Deployment note

No signaling-server change: this release adds no wire shape and no signaling
message, so the requirement is the one 0.14.5 already carries, `p2party-server`
0.1.1. Everything new is local — the identity API, one `meta` row, and the
mnemonic module.

The p2party.com Identity menu needs this SDK version: its "Back up identity" and
"Restore identity" dialogs call `getIdentityBackupStatus`,
`createRecoverableIdentity`, `restoreIdentityFromMnemonic` and
`validateMnemonicWords`, none of which exist before 0.14.6. A frontend that
vendors the SDK tarball must re-vendor this release for those dialogs to work at
all.

## [0.14.5] — 2026-09-02

Peer-edge transport binding and liveness. A phone backgrounded with its radio
off for less than the ~30 s ICE consent timeout woke holding a peer connection
that still read `connected`, while its peer had already torn that edge down and
built a fresh one. The woken side reused the stale transport, its zombie `main`
channel blocked a replacement, no handshake ever ran on the peer's new
transport, and the split was permanent until a manual reconnect: one side showed
the peer reachable and its sends failed as undelivered, the other showed no
handshake at all and its sends hung forever. This is still protocol v4 and
changes no wire shape; every change below is on the local recovery path.

### Fixed

- A peer edge is now bound to the DTLS certificate it was authenticated
  against. When the remote certificate on an incoming description differs from
  the one already applied, the edge is re-authenticated rather than reused: the
  in-flight handshake transcript is rejected, the ratchet-gate lease is
  replaced, and the PQ orchestrator, ratchet, message-key caches and scheduled
  cover of the old certificate are destroyed. Keeping a ratchet across a remote
  certificate change also violated transport binding, since the handshake
  transcript binds both DTLS fingerprints.

  An edge that has been _authenticated_ on this connection is REPLACED rather
  than rebound in place, because the old SCTP association is dead on the far
  side but still writable locally: the replacement `main` opened before DTLS
  re-ran, the handshake read the old remote certificate out of `getStats()` and
  failed as a fingerprint mismatch. A never-authenticated connection is still
  rebound in place, and at most once — a second fingerprint change replaces it,
  so a peer that keeps presenting new certificates always converges on a
  replacement instead of livelocking against a local certificate the peer has
  already retired.

- An answer carrying the DTLS fingerprint of a transport this side has retired
  is discarded, with its queued ICE, before anything is built or applied. A
  fresh connection's first `setRemoteDescription` had no binding check at all —
  there is nothing on the wire correlating an answer with the offer it answers —
  so a stale answer drained from a frozen peer's socket backlog could bind a
  brand-new connection to a dead certificate, after which the correct answer was
  dropped as stale and neither transport ever connected. Offers are deliberately
  not blocked: an offer on a retired transport is evidence that retiring it was
  premature, and answering it rebinds the edge immediately. The retired set is
  bounded to 4 fingerprints per edge with a 120 s TTL, and forgotten when a room
  is left or purged, so a peer can never be locked out.

- Every failure teardown re-dials the room, under its own debounce budget.
  A grace-timer teardown, a `main` channel close or error, and a handshake
  transport failure previously either re-dialed under the room-join budget — which
  the reconnect's own roster request had just consumed — or not at all, because
  `disconnectFromPeer` nulls the handlers before closing and `close()` fires no
  `connectionstatechange`. Deliberate teardowns (the public `disconnectFromPeer`,
  purge, leave, address-book removal) still never re-dial, and neither does a PIN
  or policy failure, which would only burn another attempt against the throttle.
  A first offer that is never answered is torn down and re-dialed after 15 s.

- A handshake attempt that has been superseded now dies quietly. An in-place
  edge re-authentication rejects the transcript on a connection it deliberately
  keeps alive, and the `main` channel's catch had no stale-lease guard, so it
  read its own supersession as a transport failure: it dispatched a `failed`
  status over the `authenticating` the reset had just set, closed the connection
  the reset meant to keep, and re-dialed. It now closes only its own channel.

- A send to a peer that never authenticates fails with a clear error inside a
  bounded wait instead of hanging forever. Every gate wait on the send path
  (reconcile, scheduled fan-out, and transfer cipher binding) now races the
  ratchet gate against a 45 s budget — chosen to outlast the 30 s handshake step
  timeout, so a handshake that fails on its own still rejects the gate first —
  and surfaces "Peer is not authenticated on this transport: the handshake did
  not complete within the wait budget" as that peer's outcome.

- A half-open signaling socket is detected instead of being believed. When a
  page freezes with the radio off, the server drops the client after a missed
  ping, but no local `close` event fires until the TCP stack gives up, so Redux
  kept reporting a live verified socket and nothing reconnected. A heartbeat
  watchdog with an injected clock now declares the socket dead after 25 s
  without an answered server heartbeat, checking every 5 s and immediately on
  `visibilitychange`, `pageshow`, `online` and `focus` because timers are
  throttled while the page is hidden. The close bookkeeping became one shared
  run-once settlement that the watchdog invokes directly.

- `RTCPeerConnection` operations settle when the connection closes underneath
  them. Closing a connection aborts its in-flight operations without settling
  their promises, so an awaited `addIceCandidate` or `setRemoteDescription` that
  raced a teardown never returned — stranding the per-peer negotiation mutex and,
  because those dispatches are awaited from the socket's strictly serial ingress
  queue, stopping every later frame on that socket (measured: a peer's
  introductions went unanswered for two minutes after a candidate raced a
  teardown). Each operation is now polled alongside the transport and settles on
  its own result, on `closed`, or on a timeout; an abandoned operation's later
  rejection is consumed.

- An interrupted transfer resumes across an edge re-authentication instead of
  being reported as a peer cancellation. A transfer belongs to the ratchet
  generation it was sealed under, identified by that generation's gate lease:
  the sender's cancel classifier now also requires the lease to be unchanged, so
  a locally retired channel falls through to resume, and the cipher-binding
  shortcut is generation-aware, so a re-bind on the same connection re-runs the
  gate wait and the ratchet step instead of sealing with a key that was just
  wiped. A re-bind that fails owes the transfer another of its bounded resume
  attempts; a genuine cancel and a gate-wait timeout stay terminal. The
  re-authentication itself now retires every channel of the old generation
  (each per-message channel plus any stale registry entry, not only `main`),
  because a channel carrying that generation's lease could only have its next
  inbound frame rejected as unauthenticated application data, which closed the
  channel and cascaded into tearing down the very edge the re-bind exists to
  keep.

- Documentation only, no behaviour change: the roadmap's "Where things stand"
  and "Near term" were re-checked claim by claim against the source and the
  deployed services; the README's `sealed.root` length (64 bytes, SHA-512), its
  CDN and npm install paths (which pointed at objects that answer 404), and its
  recovery-phrase description (p2party's word encoding is not BIP-39 — SHA-512
  checksum, 12-48 words, argon2id seed — and nothing calls it yet) were
  corrected; `docs/session-api.md` and `SessionCryptoOptions` now say what
  `wasmLoader.ts` actually does (packaged file first with an SRI check on Node
  and Bun, CDN only as a fallback); a `protocol-v3` label on a `protocolVersion:
4` interface was dropped; and the claim that sparse-PQ control cells
  substitute into scheduled cover slots was removed from the 0.13.0 entry and
  `coverRuntime.ts` — no such code has ever existed.

### Verification

A reproduction harness of two separate headless-Chromium processes, one
SIGSTOPped whole-process-tree with the kernel receive buffers of its UDP host
candidates flooded (a phone asleep with the radio off), against a Bun relay
mirroring the signaling server's message flow. It is preserved with its pass
criteria in `docs/e2e/desync/` and `docs/e2e/README.md`.

Recorded 2026-09-02: the seven-scenario matrix passes — baseline, socket drop,
a 20 s freeze in both identity roles with the socket dropped and with it kept,
and a 45 s freeze — with both sides re-authenticating 1-6 s after wake and
exchanging byte-exact messages in both directions by 6.5 s (0 s and 0.5 s
respectively in the two scenarios with no wake). Four in-flight 8 MiB transfer
configurations complete byte-exact with the sender resolving `delivered`; the
configuration that previously failed deterministically now passes 3/3. Unit and
integration suite: 1196 tests, 0 failures.

Known follow-up, recorded rather than claimed fixed: in the one configuration
where a frozen identity _responder_ carries an in-flight transfer, convergence
takes ~37 s rather than ~7 s, because the surviving transport's SCTP
association accepts our new streams but not the peer's, so recovery waits out
the 30 s handshake step timeout. The outcome is correct; the latency is not.

Not covered: an in-flight send does not survive reloading the sending page (a
reloaded receiver does resume, by replaying receipts for the leaf-hashes it
durably holds), and the harness runs n = 2 over loopback.

### Deployment note

No signaling-server change is required: 0.14.5 is wire-compatible with
`p2party-server` 0.1.1, which 0.14.4 already required, and every change is on
the SDK's local recovery path. Frontends that vendor the SDK tarball must
re-vendor it to get the fix; nothing in the browser mesh recovers a stale edge
without the new SDK on at least the woken side.

## [0.14.4] — 2026-07-28

WebRTC, signaling, TURN, and terminal-purge correctness. This is still protocol
v4 and preserves the existing room invitation UX; it does not claim the future
blind-rendezvous threat model.

### Added

- Correlated room requests and room-leave acknowledgements. Every new room
  request carries a UUIDv4 echoed by the server, so a delayed response cannot
  configure the wrong room. `purgeRoom()` sends an exact
  room-capability-bound `leaveRoom`/`roomLeft` exchange—even before a server
  room UUID exists—and exports
  `RemoteRoomRevocationUnconfirmedError` for offline or non-acknowledging
  servers; local WebRTC, memory, and durable room state are terminal before
  that error is reported, without rotating the socket shared by other rooms.
- Managed TURN credential lifecycle. Room responses may carry bounded TURN
  URLs, username, credential, and absolute expiry. Caller-provided
  `RTCConfiguration` remains a separate source of truth; managed relay entries
  are merged, applied to every live peer connection, proactively refreshed,
  and removed or failed closed at expiry.
- Explicit signaling resource budgets: the browser's per-socket ingress FIFO
  is capped at 128 frames and 2 MiB, room rosters and live/initializing mesh
  edges are capped at 64 peers, channel state is bounded, and unknown-peer ICE
  lock state is released after each operation.

### Changed

- The coordinated protocol-v4 room wire is intentionally strict and breaking:
  `roomRequestId`, `roomUrl`, `roomLeaveId`, and absolute TURN expiry use one
  exact shape. There is no legacy request, response, credential, or
  acknowledgement fallback. Existing invitation URLs and the room-join UX are
  unchanged.
- `connectToSignalingServer()` remains available only as a thin delegate to the
  canonical room connection path. First joins, reconnects, and frontend
  reconnect requests therefore share one policy/admission implementation.

### Fixed

- A send started while an authenticated peer edge is undergoing its bounded ICE
  restart no longer fails immediately as `not-connected`. Immediate and
  scheduled fanout wait through the repair window, then either use the recovered
  edge or return the normal per-peer failure result.
- Signaling frames are processed in arrival order instead of allowing async
  WebSocket handlers to overlap. Exact server heartbeats are answered
  synchronously so slow IndexedDB, SDP, or ICE work cannot create a false
  disconnect; protocol data and malformed heartbeat lookalikes cannot use that
  bypass.
- Fresh socket proof now refreshes every active room, while exact-server
  binding prevents retained capabilities from being disclosed to a different
  rendezvous URL after a disconnect.
- Socket attempts, joins, disconnects, room purges, identity purges, and full
  purges are serialized so a delayed IndexedDB, proof, or WebRTC operation
  cannot resurrect terminal state. Full purge removes room capabilities from
  memory instead of retaining policy tombstones.
- TURN rotation updates live `RTCPeerConnection` configuration before
  restarting negotiated ICE, rolls back atomically on failure, scopes timers
  and responses to their exact generation, and closes rather than continuing
  with an expired or partially applied generation.
- Long-lived WebRTC callbacks read the current authenticated peer identity
  instead of sending a creation-time `peerId` on a replacement socket.
  Unknown or inactive-room introductions, SDP, and ICE now fail closed.
- PIN-room reconnects pass through the same persisted-policy admission path as
  first joins; the legacy reconnect helper can no longer bypass the PIN vault
  or reactivate an inactive room with default policy.
- Release packaging now copies the README only after synchronizing the exact
  bundle and worker SRI values, then verifies those values inside the packed
  tarball.
- Documentation only: the 0.13.0 entry below and the header comment in
  `src/handlers/coverRuntime.ts` both said sparse-PQ control cells substitute
  into scheduled cover slots. No such code has ever existed. The one outbound
  path for a control cell is the orchestrator's `sendControlFrame`, whose sole
  implementation writes to the persistent `main` channel, in scheduled rooms as
  well as immediate ones; the runtime's `"control"` cover job carries scheduled
  receipts. Both statements corrected. No behaviour changed.

### Deployment note

Confirmed remote room unlinking and room-scoped TURN configuration require the
matching `p2party-server` 0.1.1. This is a coordinated protocol-v4 cutover:
room request correlation, managed TURN responses, and room-leave
acknowledgements use one mandatory wire shape with no older-server fallback.

The matching server release also serializes each socket's signaling frames,
bounds retained work, lets only an exact pong from the proved current socket
owner bypass slow work, and rechecks exact source and target ownership after
every awaited database/routing boundary. Same-identity fencing and membership
ordering across different server processes remain explicit nonclaims; 0.1.1
does not implement blind rendezvous or hide rooms, identities, or the social
graph from the signaling operator.

## [0.14.3] — 2026-07-27

### Added

- `getTransferAcks(roomId, transferId)`. Live outbound progress for one logical
  send: for every peer edge, how many chunks that peer has receipted so far and
  whether the transfer completed. Pair it with the message row's `totalChunks`
  for a percentage.

  The sender already knew this -- every receipt lands in the have-set that
  drives selective retransmit -- but nothing outside the module could read it,
  so a UI could say "sending" and then show nothing at all until the transfer
  settled. On a large file that is a progress bar's worth of silence.

  The counts are real chunks, not frames: a decoy receipt does not resolve to a
  staged chunk on the sender, so cover traffic never inflates the number. Wire
  totals including cover remain derivable as `totalChunks * WIRE_CHUNK_FRAME_LEN`.

  Derived from the same state selective retransmit uses, so it cannot drift
  from what the sender believes was delivered. Read-only and defensively
  copied; polling it never affects the transfer.

## [0.14.2] — 2026-07-26

### Added

- `getRoomStats(roomId)`. Aggregate history for one saved room: message counts
  split into sent and received, byte totals for each direction, and the
  distinct peers this device has received from. The arithmetic runs inside the
  database worker rather than shipping every `MessageData` row to the main
  thread so a UI can sum a few numbers, which for a busy room means serialising
  thousands of objects across the worker boundary on every render.

  Sizes are logical message bytes, not wire bytes. p2party pads everything to
  uniform 65,490-byte cells, so what crossed the network is always larger and
  is a property of the padding policy rather than of the conversation.
  A partially received message counts what arrived, not what was promised, so
  an abandoned transfer cannot inflate the total.

## [0.14.1] — 2026-07-26

Cross-browser and release-integrity fixes. No wire change: 0.14.0 and 0.14.1
peers interoperate.

### Fixed

- **p2party could not connect at all in Firefox.** The post-connect DTLS check
  reads the live certificate from `getStats()` and fails closed when it cannot
  confirm it. Firefox implements neither the `transport` stat nor `certificate`
  rows, so every peer edge aborted with a fingerprint mismatch that was really
  a browser unable to answer the question. A browser reporting no certificate
  statistics now proceeds with a warning; where the browser can answer, a
  disagreement is still fatal.
- A peer edge that entered `disconnected` was torn down after eight seconds
  with no attempt to repair it, so a room quiet for a few minutes failed the
  next send with `not-connected` while the roster still listed the peer. The
  edge now attempts an ICE restart first.
- Redux logged a non-serializable-state warning on every send and every ICE
  candidate. RTK Query echoes a mutation's arguments — live `RTCDataChannel`
  and `RTCIceCandidate` handles — back on each action; both API slices are now
  exempt from that check while application reducers stay checked.
- The CDN immutability guard compared gzip bytes, which embed an MTIME, so
  re-running a published tag reported a violation that had not happened. It now
  compares decoded content.
- Crypto provenance recorded the raw `emcc --version` banner, which differs by
  install method (`6.0.3-git` from Homebrew, `6.0.3 (<commit>)` from emsdk) for
  the same compiler and byte-identical WASM. It records the semantic version,
  so any Emscripten 6.0.3 reproduces the artifact and the provenance.
- The failure log said "protocol-v3 handshake failed" on protocol v4.

## [0.14.0] — 2026-07-26

Developer experience, plus an Emscripten toolchain bump. No wire change: v4
peers on 0.13.0 and 0.14.0 interoperate.

### Added

- `joinRoom()` and `waitForRoom()`. Learning a room's id previously required
  hand-rolling a store subscription with a mutable `unsubscribe` binding, a
  synchronous re-check for the already-joined case, and no timeout — thirteen
  lines for one string. `waitForRoom()` owns that wait, with a timeout and an
  `AbortSignal`; `joinRoom()` is `connect()` plus the wait.
- `waitForPeers()`. Resolves once the room has authenticated peer edges — not
  merely present ones. Waiting for a peer to _appear_ is the bug callers
  actually wrote: a peer is in the room a beat before its protocol-v4
  handshake completes, and a send in that window is skipped as
  unauthenticated, so the message silently goes nowhere. Takes a peer `count`,
  a timeout, and an `AbortSignal`; on timeout it reports how many peers did
  authenticate.
- `onMessage()`. Fires once per fully-arrived message with the payload already
  decoded, replacing a manual `store.subscribe` diff against
  `room.messages` plus a `readMessage()` call. A throwing handler is isolated.
- `setDebugLogging(boolean)`, and the `p2party:debug` localStorage key.
- `examples/browser-mesh/` — a runnable two-tab page, and `docs/wire-format.md`,
  moved out of the README.

### Changed

- Diagnostic logging is off by default. 34 `console.log` calls across the
  signaling, WebRTC and middleware paths filled an embedding application's
  console — `[roomListenerMiddleware] setRoom: {...}` on every room change —
  with no way to silence them. They are retained but gated; errors and
  warnings are unaffected.
- The Emscripten pin moves 6.0.2 → 6.0.3, so `libcrypto.wasm` and its SRI
  change. CI and the release workflow move with it.
- `MessageDeliveryError` is exported, and `handle.done`'s rejection is
  documented where callers meet it.
- Install is `npm install p2party`, with `npm audit signatures` for checking
  release provenance.

### Fixed

- `error instanceof MessageDeliveryError` on a rejected `handle.done` could
  never be true, which is the check the docs told callers to write. RTK Query
  serializes an error thrown from a `queryFn` into a plain object, discarding
  the prototype and the `result` field carrying the per-peer outcomes;
  `sendMessageQuery` now returns `{ error }` so the instance survives.
- The release build no longer ships documentation naming a version other than
  the one being released. The check derives its flag set from the CHANGELOG's
  own release headings and scans every tracked Markdown file, exempting only
  the files whose purpose is recording history. The previous allowlist omitted
  `ROADMAP.md`, which had drifted to `0.13.0`.
- `getDBPeerIsBlacklisted()` fails closed. A worker error resolved it to
  `false` — "not blacklisted" — so a database fault silently readmitted a
  blocked peer. Worker `error`/`messageerror` events now reject every pending
  call instead of leaving them hanging forever.
- The room listener effect no longer leaks an unhandled promise rejection into
  the host application when IndexedDB is unavailable.
- `scripts/buildRelease.mjs` still packaged `docs/protocol-v3-security.md`,
  renamed in 0.13.0 — the release build failed at the copy step.

## [0.13.0] — 2026-07-25

Protocol **v4**: a clean, incompatible wire/session break (v3 peers and
persisted v3 crypto rows are not resumed). Adds sparse post-quantum healing
and room-wide scheduled timing cover.

### Added

- **Sparse PQ healing (immediate mode).** An authenticated 64-bit PQ epoch is
  carried in every uniform 65,490-byte cell and mixed into the message AEAD
  AAD. A store-free sparse-PQ state machine performs standard ML-KEM
  OFFER/ADVANCE/ACK exchanges; a live WebRTC orchestrator drives due-time
  initiation (64 messages / 24 h, stable-role turn, quiescent boundary),
  exact-frame retransmission (5 s × 8), and fail-closed fork/exhaustion
  handling. Combined message keys live in an epoch-bound active receive-key
  collection persisted in one atomic encrypted edge checkpoint alongside the
  Double Ratchet.
- **Scheduled timing cover.** An authenticated room policy opens exactly
  `coverLanes` fixed-schedule lanes per edge, each emitting `coverFramesPerCell`
  authenticated 65,490-byte cells per epoch for `coverDurationEpochs`, closing
  only at cycle boundaries. Real message chunks, receipts, and an encrypted
  CANCEL substitute into scheduled slots; dummy cover cells fill the rest.
  (This entry originally also listed sparse-PQ control cells. It was wrong when
  written and is corrected here: a PQ control cell has only ever ridden the
  persistent `main` channel, in every room. See the 0.14.4 note below.)
  Absolute room-phased cycles derived from the policy hash; browser
  visibility/freeze/pagehide/offline suspend cover and resume only at a future
  boundary. Surfaced status (`starting|active|degraded|suspended|stopped`) so a
  browser-imposed gap is never claimed as cover.
- **Public session API v4.** `pqEpoch` / `healingInProgress`, PQ-combined
  `encrypt`/`decrypt`, snapshot format 4 (rejects v3) carrying the PQ machine +
  active receive keys, and a store-free `prepareHealing`/`acceptControlFrame`/
  `pendingControl` control surface with an explicit persist-before-send
  contract.

### Changed

- `PROTOCOL_VERSION` is now `4`; the public epoch is an authenticated u64 (was
  a fixed reserved zero byte). `CHUNK_PLAINTEXT_LEN` drops from 65,412 to
  65,405 bytes (the seven epoch bytes consume padding); the outer cell stays
  exactly 65,490 bytes. Room-policy encoding/hash KATs updated for the v4
  wire-version byte.

### Verified

- Full source gate green (lint, format, typecheck, tests, standalone example).
- Real headless-Chromium E2E: immediate sparse-PQ mesh at n=2/3/4; scheduled
  cover lanes over real WebRTC; and a full app-stack run (Redux + IndexedDB +
  WebRTC) delivering byte-exact messages in immediate, PIN, and scheduled
  rooms.

## [0.12.0] — 2026-07-24

### Added

- Authenticated room-wide ML-KEM-512, ML-KEM-768 (default), and ML-KEM-1024
  bootstrap profiles. The selected suite is fixed before the handshake and
  bound into framing, channel input, root KDF domains, confirmation proofs,
  ratchet persistence, and standalone snapshots; there is no negotiation,
  inference from length, downgrade, or classical fallback.
- A third chained handshake confirmation. The initiator proof commits to the
  responder proof, the responder FINISH commits to both, and the initiator
  cannot establish until FINISH verifies.
- Compact 256-bit room capabilities (43-character unpadded base64url),
  versioned fragment invites, strict legacy-hex normalization, and an optional
  checksum-protected 24-word encoding of the same capability bytes.
- An internal sparse PQ-healing state-machine core. Production nonzero epochs
  remain gated on crash-safe persistence, authenticated control routing,
  message-key integration, and scheduler wiring.

### Fixed

- Concurrent room joins now allocate every signaled WebRTC edge, restoring the
  intended n-party full mesh rather than leaving identity-initiator edges idle.
- WebCrypto randomness is staged through fixed `ArrayBuffer`s before entering
  resizable WebAssembly memory, restoring compatibility with newer Chromium.

### Security

- Tampering either of the first two key-confirmation proofs now prevents both
  endpoints from completing. A tampered final FINISH is rejected by the
  initiator. As with every finite handshake over a lossy transport, dropping a
  valid last packet can still leave the sender complete while the receiver
  waits; this is an availability/common-knowledge boundary, not key disclosure.

### Release engineering

- npm and `package-lock.json` are now the release dependency authority. Package
  exports and files are allowlisted, direct source-tree publishing is refused,
  and tagged npm releases carry provenance.
- Pull requests build the pinned cryptographic source before running checks.
  Tagged releases publish immutable versioned CDN objects, fetch the public
  WASM back, and verify its exact bytes, SHA-256, and SRI before npm publication.
- Release validation now pins and hashes the vendored mlkem-native source tree
  and p2party wrappers, packages the provenance manifest and third-party
  notices, and rejects unexpected tarball entries.
- Added security, contribution, conduct, and attribution metadata for public
  development.

## [0.10.0] — 2026-07-23

Protocol v3 is an intentional wire break. Versionless, legacy, and downgraded
peers fail closed.

### Added

- Mandatory X25519 interactive 3DH plus ML-KEM-768 bootstrap for every peer
  edge; PIN rooms additionally authenticate with CPace.
- Per-peer Double Ratchet message encryption, wrapped persistent ratchet state,
  DTLS fingerprint binding, exact tagged receipts, and room/peer-scoped
  transport ownership.
- Store-free `p2party/session` exports: `createSession`, `restoreSession`, and
  `generateSessionIdentity`, usable outside browsers.
- Per-message transfer handles with cancellation and per-peer mesh delivery
  outcomes.

### Changed

- Outbound transfers now have independent random identities, including
  concurrent sends of identical content.
- The WASM release uses an exact stable libsodium source commit through its
  configured build, public APIs, checked initialization, no LTO, and a packaged
  provenance manifest.
- The SDK is now licensed under Apache-2.0.

### Not included in 0.10.0

Scheduled timing cover, sparse post-quantum ratchet healing, server-blind
rendezvous, and the private BitTorrent extension are next-version work, not
0.10.0 shipped properties.

## [0.9.2] — 2026-07-21

Receive-side storage for files is re-architected so a received file's bytes live
in exactly one place — its disk-backed OPFS file — instead of being buffered in
IndexedDB and reassembled on read. This halves peak storage for large transfers
and makes reload-resume fill only the still-missing gaps. **No wire-protocol
change** and **no public-API change** — `readMessage` still returns a disk-backed
`File`; a 0.9.2 peer interoperates with 0.9.1/0.9.0.

### Changed

- **Receive-time OPFS writes (no double storage).** Each received real FILE chunk
  is now written straight into a per-message OPFS file at its byte offset
  (`chunkIndex × uniformSize`) as it arrives — out of order — into a file
  pre-sized to the total size (zero-filled). IndexedDB keeps only the per-chunk
  leaf-hash "have-set" (bytesless records), not the bytes. Previously every
  received chunk's bytes were stored in IndexedDB **and** the whole file was
  reassembled into OPFS on read, doubling peak disk for the duration; that
  reassembly pass is gone. `uniformSize` (real bytes per full chunk) is a
  per-send tunable not carried on the wire, so it is learned empirically
  (`max(realLen)`, exact after two chunks or from chunk 0); the ≤1 chunk that
  arrives before it is known is kept in IndexedDB and migrated into OPFS when the
  file is opened.
- **Reload-resume fills only the gaps.** Because the OPFS file (with zeros in the
  not-yet-received gaps) and the leaf-hash have-set both persist across a page
  reload, a resumed transfer overwrites only the remaining gaps rather than
  restarting. The have-set is a strict subset of the bytes actually on disk
  (bytes are written before the record is recorded), so a resumed sender never
  skips a chunk whose bytes are missing.

### Notes

- Text messages and the sender's own copy of a sent file are unchanged (still
  stored in IndexedDB); only the receive path for files changed.
- Where worker OPFS is unavailable (very old browsers), received file bytes fall
  back to IndexedDB and the in-memory `Blob` read path, exactly as before.

## [0.9.1] — 2026-07-21

Reliability and scale for the peer-to-peer file transfer layer: an in-flight
transfer now survives a dropped connection, and arbitrarily large files stream
through disk instead of ever sitting in memory. **No wire-protocol change** — a
0.9.1 peer interoperates with a 0.9.0 peer.

### Added

- **Resume-on-reconnect.** An in-flight message no longer fails when the WebRTC
  connection is fully torn down and re-established mid-transfer (network drop,
  ICE failure, peer refresh). The sender re-opens its per-message channel on the
  peer's fresh connection and continues; the receiver re-emits the leaf-hash
  receipts for the chunks it already holds, so only the still-missing chunks are
  resent — no full re-send, no wire change. Reconnect recoveries surface in the
  existing `retransmits` telemetry.
- **Arbitrary large files (GB+), never held whole in RAM.**
  - _Send:_ the whole-message SHA-512 is now computed incrementally, streaming
    the file from disk one window at a time through a new WebAssembly streaming
    hash — the file is never fully loaded to hash it.
  - _Receive:_ a completed file is reassembled by streaming its stored chunks
    straight to a disk-backed file in the **Origin Private File System (OPFS)**
    inside the storage worker, and `readMessage` returns a disk-backed `File` —
    the whole file is never built as an in-memory `Blob`. Reassembly is
    idempotent and content-addressed (repeat reads are O(1)); concurrent reads
    of the same file are coalesced; assembled files are reclaimed when the
    message or database is deleted.
- **`getSendChunksCount(hashHex)`** — a read-only diagnostic returning how many
  outbound chunks are still buffered for a message (0 once a send completes or is
  abandoned). Useful for surfacing send-buffer usage.
- **`readMessage(merkleRootHex, hashHex?, materialize?)`** — a `materialize`
  flag (default `true`, backward-compatible). Pass `false` to read a completed
  file's metadata (name/size/category) **without** reassembling the file — so a
  UI can render list previews and file bubbles cheaply and only materialize the
  `File` on open/download/save. Consumers can then offer a "Save as…" that
  streams the disk-backed `File` straight to a user-chosen location
  (`showSaveFilePicker`) without ever holding it in RAM.

### Changed

- The per-message channel's completion close now drains its send buffer before
  closing (mirrors the graceful-close path), so a completing transfer never
  wipes an un-flushed frame.

### Fixed

- The sender's per-message send buffer (`newChunks`) is now reliably reclaimed
  from IndexedDB after a transfer completes **or** is permanently abandoned —
  previously an edge case could leave a completed/aborted transfer's data behind.

### Browser support

- The **never-in-RAM** guarantee for large-file receive applies to browsers with
  worker OPFS: Chrome/Edge, Firefox 111+, and Safari 16.4+. Older browsers fall
  back to an in-memory reassembly (correct, but memory-bound).

### Deploying 0.9.1

This release adds new exports to `libcrypto.wasm` and pins the WASM URL to
`@0.9.1` (`cdn.p2party.com/@0.9.1/libcrypto.wasm`), leaving `@0.9.0` untouched
for existing clients. To publish:

```sh
npm run predist      # rebuild the production WASM + re-pin its SRI
npm run uploadcdn    # upload the WASM to the CDN (needs AWS credentials)
```

The JavaScript that calls the new streaming-hash export cannot run until the
`@0.9.1` WASM is live on the CDN. The signaling server is unchanged and does not
need redeployment.

## [0.9.0] — 2026-07-20

Protocol-v2 security hardening and the reliable-transfer foundation.

### Security

- Bind per-chunk sender authentication to a domain-separated transcript
  (`DOMAIN || merkle_root || ephemeral_pk`) so a signature harvested from the
  server-challenge oracle cannot be replayed as chunk authentication.
- Merkle tree: domain-separated node hashing and odd-node promotion
  (CVE-2012-2459 class), and reuse of the verified leaf hash.
- Tier-1 hardening: BigInt rejection sampling for range RNG, WASM heap-leak and
  zeroization fixes, and stricter bounds validation.
- Updated libsodium and rebuilt the WASM.

### Reliability

- Selective retransmit / reconcile: receipts are the have-set; the sender resends
  only the chunks a receiver hasn't acknowledged, until completion.
- Wait-for-channel-open before the first send; drain-before-close; read-receipt
  count uniformity; and per-message transfer telemetry (total/real chunk counts,
  retransmits).

[0.12.0]: https://github.com/p2party/p2party-js/releases/tag/v0.12.0
[0.10.0]: https://github.com/p2party/p2party-js/releases/tag/v0.10.0
[0.9.2]: https://github.com/p2party/p2party-js/releases/tag/v0.9.2
[0.9.1]: https://github.com/p2party/p2party-js/releases/tag/v0.9.1
[0.9.0]: https://github.com/p2party/p2party-js/releases/tag/v0.9.0
