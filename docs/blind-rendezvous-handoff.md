# Handoff: blind rendezvous + live fixes

Written 2026-07-28 for the next agent and updated after local branch
reconciliation. The production-correctness baseline is on each repository's
local `master`; the pair-plaintext/admission-semantics increment described
below extends the current local `p2party-js` Phase-0 checkpoint. Nothing is
pushed; no PR exists.

## Offline handoff on 2026-07-28

Stop point: local `master` is clean except for the intentionally untracked
`docs/rendezvous-prior-art.md` research shelf and the two untracked
retained-operation draft files named below. Nothing was pushed or deployed.

Two reviewed checkpoints were added:

- `663a986` binds one genuine local PRESENCE to live, process-opaque
  author-epoch, stable-identity, and historical receiver custody without
  minting topology, admission, lease, or publication authority.
- `53cde9a` moves Ed25519 key-material consistency into one cryptography SSOT
  and adds versioned IndexedDB stable-identity custody. The identity row and
  persistent high-water/tombstone revision change atomically; set/set and
  identity-set/delete races allocate unique revisions; delete/recreate cannot
  ABA; the actual legacy `{pub, wrappedSecret}` row migrates coherently; and
  malformed/overflow state fails closed.

The main-realm client boundary now re-derives the complete Ed25519
seed-to-secret/public pair. It rejects `seedA || publicB`, rejects malformed
worker revisions, preserves caller-owned inputs, transfers owned copies to the
worker, explicitly wipes failed or unclaimed secret buffers, and leaves the DB
worker free of a second WASM/CDN dependency. Worker output tests perform a real
structured-clone transfer and prove the worker-side buffer is detached. The
worker's suffix comparison is only defense in depth; it is not the canonical
key-consistency proof.

Verification at this stop point:

- focused DB/custody run: 88 tests, 523 assertions;
- focused DB boundary + worker + identity trial run: 66 tests, 418 assertions;
- both TypeScript configurations and scoped ESLint passed;
- changed/new-file formatting and `git diff --check` passed;
- `build:worker` and `build:package` passed; and
- the worker artifact contains no Ed25519 derivation, WASM-loader, CDN, or
  `libcrypto.wasm` dependency.

These guarantees are intentionally narrower than “rollback proof” or
“concurrent teardown proof”:

- revisions are monotonic only while the local IndexedDB state remains intact;
  whole-origin rollback/clearing, same-origin compromise, and manual
  row-plus-counter restoration are not prevented;
- revision metadata is structurally transactional but not cryptographically
  or remotely anchored;
- JavaScript zeroization is best effort;
- `signalingServerApi.ts` does not yet use `recordRevision`, so the SDK has not
  earned multi-tab current-key convergence;
- identity deletion clears ratchets present when its transaction linearizes,
  but an already-running `setRatchetSession` can commit afterward and recreate
  one; and
- browser shutdown/offline crypto still requires the exact SRI-pinned WASM to
  be self-hosted or cached/configured before use. Only the DB worker itself is
  network-independent.

The next smallest correctness slice is DB-as-SSOT
`getOrCreateIdentityEd25519`, followed by revision-CAS for explicit rotation.
Every ratchet write must then carry the expected stable-identity revision and
check it in the same `meta + ratchetSessions` transaction. This closes both the
multi-tab key race and the reproduced post-delete ratchet recreation; do not
paper over either with lifecycle ordering.

Two untracked drafts currently pass their focused suite (19 tests,
109 assertions) and both typechecks:

- `src/blindRendezvous/retainedOperationStore.ts`
- `tests/blindRendezvous/retainedOperationStore.test.ts`

They define strict local historical manifests, exact content-address
validation, absent-versus-empty state, exclusive capacity fences, sticky
incomplete-overcapacity state, and closed CAS material. A candidate is now
owned before the first await for a complete manifest, while absent or already
incomplete state does not inspect it.

Do **not** commit or build the IndexedDB v20 adapter from this draft yet. Its
single-window CAS currently requires the candidate content key to be absent.
That conflicts with the intended room-wide content-addressed SSOT when the
same immutable operation must be referenced by several historical-window
manifests: after the first window inserts the row, the next window cannot
reuse it. The minimal repair is an exact “ensure absent-or-byte-identical
content row, then replace this manifest” transition plus a room-scoped
inventory row with its own non-reused revision and the physical unique-row
count/byte total. Per-window manifests should contain membership only. One
room-wide atomic fan-out planner/adapter must fence the inventory and all
affected manifests, scan for extra physical rows, insert absent content once,
reuse byte-identical existing content at zero physical delta, and update or
mark every affected retained window in one transaction. Manifest deletion
also needs a retained high-water/tombstone so absence cannot ABA. Count/byte
evidence must describe the room-wide physical union once, not independently
double-charge shared bytes per manifest. Empty-complete initialization must
come from a trusted complete boundary, never mere row absence. Only after that
contract is reviewed should the additive DB migration and adapter land.

Historical replay must then reuse the existing sole path
`decodeOperation -> validateAndIdentifyOperationCandidate -> coreReduce`.
Neither persisted decoded Core bytes nor a digest may mint current/historical
ownership or topology. Complete manifest replay, live key revisions, planner
and resource rows, current admission vetoes, and the exact HELLO window all
remain required before the private composite projector can mint one
pair-scoped topology capability.

## Topology/provenance continuation on 2026-07-28

The next local `master` checkpoints now exist after the older notes below:

- `94eee32` defines the exact admission capture codecs.
- `163b55c` through `a8d0051` add one-use HELLO preparation, bounded trial and
  pair-ledger state, complete admission CAS rows, planner state, admissible
  rank derivation, and Core-fact ownership verification.
- `92fcbbe` adds the pure bounded local Project semantics with separate
  projection/planner statuses and separate planner/explicit topology origins.
- `68c2f4e` makes exact retained-operation capacity fail closed.
- `1ae1742` synchronizes and strengthens the normative spec around strict-self
  deduplication, delayed HELLO projection, current policy vetoes, ephemeral
  topology provenance, and the one composite `project-and-admit` kernel
  boundary.
- `bc21d4d` removes premature pre-topology lease construction: a successful
  HELLO capture now yields only an opaque `policy-allowed-pre-topology` handle.
- `47f0b79` adds process-opaque stable Ed25519 private-key custody and carries
  the exact stable/receiver custody handles through HELLO open and admission
  capture.

The strengthened spec received a strict scoped review GO. In particular:

- logical room overcapacity remains a complete Core input and is
  deterministically rank-capped; only physical custody/resource
  incompleteness or saturation fails Project;
- delayed pair flights evaluate presence activity and permit validity at the
  signed HELLO window, while current deny/revocation/authority, planner,
  degree, ledger, outbox, and resource state remain vetoes;
- a distinct historical local-custody proof must bind exact authenticated
  operation evidence and live stable/receiver key handles;
- cloneable projection output is diagnostic only; an opaque pair topology
  handle exists only inside one `project-and-admit` invocation and is never
  persisted or reimported; and
- incoming explicit attempts require the receiver's current on-demand policy,
  not a reciprocal local UI request.

The committed implementation is still a safe non-authorizing foundation, not
that complete boundary. `localStableIdentityCustody.ts` now derives the stable
public key from an owned, internally consistent 64-byte Ed25519 secret, binds
one non-reused key-record revision, uses process-local `WeakMap` provenance,
and wipes its secret on destruction. Receiver custody retains that exact
handle and rechecks it after asynchronous ownership/KEM verification.
HELLO open, admission claim, and capture retain and recheck the exact receiver
handle; both receiver and stable-key revision rows must be present and match,
and the captured structural ownership row must contain the exact local
PRESENCE ID and live stable public key.

This proves live stable/receiver key custody and exact local PRESENCE binding
for this path. It does **not** prove that the captured local key/presence sets
are complete, that the local author private key is custodied, or that the
HELLO-time Core came from a complete authenticated operation set.
`localAdmissibleProject.ts` still accepts deeply owned but structural inputs
and deliberately cannot mint topology or publication authority. Authority
projection remains fail-closed. The HELLO preparation service still reaches
only `policy-allowed-pre-topology`.

The next production-critical work is therefore:

1. prove complete current local ownership from exact retained operations plus
   live author, stable-identity, and receiver-key custody;
2. reconstruct historical Core from the complete authenticated operation and
   author-prefix SSOT for the HELLO window, then mint the distinct historical
   local-custody proof;
3. canonical-decode and bind the planner and physical resource rows;
4. execute current/historical projection and `Admit` inside one private
   composite invocation; and
5. prepare the exact ACCEPT/outbox mutation and commit every captured fence in
   the existing fixed CAS order before any byte is publishable.

Do not “complete” steps 1 or 2 by trusting
`LocalPresenceOwnershipRecordV1`, decoded `CoreRoomStateV1` bytes, a digest, or
the pair-subject endpoint evidence bundle alone. Those are structural
selectors/fences, not non-omission or key-custody authority.

Last verification after stable-identity custody:
`bun test tests/blindRendezvous` — 383 pass, 0 fail, 2,410 assertions across
29 files. Both TypeScript configurations, focused ESLint, formatting, and
`git diff --check` passed. `bun test tests` also passes: 1,027 tests and
18,448 assertions across 128 files. A separate read-only security review
returned GO with no authorization, provenance, secret-exposure, or fail-open
finding.

## Continuation after this handoff

The next review completed later on 2026-07-28 and changes the safe next-step
ordering:

- `mergeOperationCandidateSets()` compares complete canonical signed operation
  bytes when two entries claim one `OperationId`; same-signature/different-body
  collisions no longer pass as duplicates.
- Reducer tests cover a non-revocation under the pinned authority; the current
  increment replaces the earlier five-element pending marker with canonical
  concrete Core projections.
- `derivations.ts` now owns the exact `StableIdentityCommitment`,
  `LocalPeerIdDigest`, and `LocalPeerId` equations, with room-separation and
  length-failure tests.
- Section 4.8 now has module-private `VerifiedAdmissionContextV1` and
  `TrustedAdmissionSnapshotV1` provenance, versioned pair/decision leases, an
  exact lease constructor/minimum, and a validated atomic authority-admission
  view. Do not reintroduce a caller-assembled admission input or a supplied
  `authorityAdmissionAvailable` boolean.
- The post-v0.4 roadmap places optional proof-of-work only at room-blind
  Blind-RSA token issuance. It is Sybil-costing, not personhood, membership,
  blacklist enforcement, server independence, BFT, or fairness.
- The PQ successor now recommends both-required Ed25519 + ML-DSA-65 over one
  exact shared transcript and records the browser key-custody nonclaim. No
  v0.4 field or suite ID changed.
- `PairStepEnvelopeV1` has a schema-derived codec and exact suite-1 class
  targets. Outer operation validation binds its routing tag to the signed
  semantic slot, and `coreReduce()` accepts only live results of the one
  mutation-resistant validate-and-identify ingress.
- The current signaling path now treats caller RTC configuration and
  signaling-managed credentials as separate sources, correlates every new room
  response to a wire UUID, updates live peer connections before an ICE restart,
  refreshes every active room after fresh socket proof and before credential
  expiry, and removes expired managed credentials. The coordinated v4 cutover
  requires that UUID in the one canonical request/response shape; there is no
  released-server fallback. Room leave/acknowledgement uses the stable room
  capability, so purging a join that has not received its server room UUID
  still requires authoritative remote revocation.
- The frontend message list is the sole scroll owner and the composer is a
  normal row below it. Long drafts cap at roughly six lines, layout-driven
  resizes preserve the live edge without yanking a history reader, and the
  dynamic viewport plus all four safe-area insets cover Chrome Android, iOS
  Safari geometry, and Capacitor's single-inset-owner configuration.

The working tree now also contains the proposed `PairPlaintextV1` codec and all
ten body variants, schema-derived class/padding rules, room-selected v4
handshake framing, independently generated known-answer vectors for every
pair body and legal envelope form, and a semantic-only admission-policy/lease
module. This still does **not** close the complete pair or admission boundary:
HPKE/pair AEAD, one-use routing-tag state, exact
predecessor/state validation, trusted snapshot/custody/provenance constructors,
answer-to-offer/adapter/fingerprint validation, `Admit()`, atomic persistence,
and the pre-SDP effectful gate are absent.
Nonempty `STORE_HINT` routes also fail closed until the route-family
registry/parser is frozen. Therefore a `PAIR_STEP` in
`activePairOuterOperationIds` remains outer-authenticated only, not an admitted
edge.

Verification commands for the current tree:

```sh
bunx tsc --noEmit -p tsconfig.json
bunx tsc --noEmit -p tsconfig.test.json
bunx eslint <touched TypeScript files>
python3 tests/blindRendezvous/reference/pair_plaintext_vectors.py
bun test tests/blindRendezvous
bun test tests
```

Verification after the final review edits:
`bun test tests/blindRendezvous` — 263 pass, 0 fail, 17 files; `bun test tests`
— 838 pass, 0 fail, 109 files. Both TypeScript configurations, targeted ESLint,
and `git diff --check` also pass.

## Repositories and branches

| Repo             | Path                                | Branch   | Local state                                                                     |
| ---------------- | ----------------------------------- | -------- | ------------------------------------------------------------------------------- |
| `p2party-js`     | `~/Desktop/@p2party/p2party-js`     | `master` | WebRTC/TURN baseline plus current pair/admission Phase-0 checkpoint, local only |
| `p2party-server` | `~/Desktop/@p2party/p2party-server` | `master` | TURN endpoint issuance merged; 1 commit ahead of `origin/master`                |
| `p2party.com`    | `~/Desktop/@p2party/p2party.com`    | `master` | Frontend fixes already present; 2 commits ahead of `origin/master`              |

`docs/rendezvous-prior-art.md` remains an intentionally untracked local
research shelf. Its bytes are identical to the version removed by `b2c147f`;
do not stage it unless the maintainer explicitly reverses that decision.

## Non-negotiable rules carried from the original brief

1. DRY, KISS, scoped SSOT.
2. The canonical binary schema owns wire fields, enums, widths, bounds,
   ordering, and generated projections. No second authority.
3. **Never invent placeholder hashes, release bytes, suite IDs, proofs, or
   evidence and present them as production artifacts.** If the spec does not
   define a value, it is a blocker, not a decision.
4. `normativeKernel.ts` is an internal scaffold, not a public API or canonical
   encoder. It is absent from the package barrel; keep it that way.
5. Preserve today's `generateRoomInvite()`, `/r` link, fragment extraction,
   QR/share, PIN prompt, advanced-room, and `joinRoom()` UX.
6. Rooms stay isolated capability/policy domains. A cohort is never a giant room
   or roster.
7. Frontend whitelist/blacklist/strict-address-book/authority admission gate
   SDP/ICE, and must hold against one malicious server colluding with a denied
   capability holder.
8. One server must give the S1 baseline: it may censor or omit, but must not
   learn room identifiers, room equality, identities, membership, targets, or SDP.
9. WebSockets are optional legacy compatibility only. Blind v2 must build and run
   without WebSocket or HTTP Upgrade.
10. Reuse the existing protocol-v4 session/outbox/ratchet/PQ-healing state through
    the specified adapter. Do not duplicate cryptographic state.
11. Never weaken a requirement to make a test pass. If a requirement is genuinely
    contradictory or awaits a decision, document the exact blocker and move on.
12. Do not commit or fabricate commit provenance unless asked. (The human has now
    asked for incremental commits — keep them small and reviewable.)

## What exists now

### `p2party-js/src/blindRendezvous/` (none exported from the package barrel)

| Module                | Owns                                                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `canonicalSchema.ts`  | Descriptor-driven canonical binary codec: field order, integer widths, enum bytes, collection ordering, bounds.            |
| `schemas.ts`          | Descriptors for implemented room operations, pair/non-pair payloads, store objects, and canonical Core state/faults.       |
| `projections.ts`      | Generated key tables and enum projections. No hand-maintained duplicate remains.                                           |
| `derivations.ts`      | Domain-separated hashes, HKDF-SHA-256, room/pair/operation/carrier identifiers and transcript inputs.                      |
| `roomPolicyV4.ts`     | `RoomPolicyV4` validation, canonical codec, `DEFAULT_BLIND_POLICY_V4_0`.                                                   |
| `roomInviteV2.ts`     | Closed `v1 \| v2` invitation parsing, both v2 fragment forms, the two typed errors.                                        |
| `pairStepEnvelope.ts` | Schema-derived `PairStepEnvelopeV1` framing and exact suite-1 class targets.                                               |
| `pairPlaintext.ts`    | Closed ten-body codec, minimal class/zero padding, initial slots, candidate shape/order, and v4 framing validation.        |
| `admissionPolicy.ts`  | Internal semantic-only frontend/authority policy order and bootstrap/stable-edge lease arithmetic.                         |
| `operation.ts`        | Operation codec/signatures, process-private room-validation context, active/candidate outer gates, pair-slot binding.      |
| `operationPayload.ts` | Closed non-pair codecs and intrinsic validation for grant/revoke, presence/permit, leave, and descriptor-only store hints. |
| `coreReduce.ts`       | Provenance-checked candidate ingress, payload reduction, dependency-evidence fixed point, canonical Core state/faults.     |
| `carrierEnvelope.ts`  | Envelope framing, key schedule, AAD, object identity over XChaCha20-Poly1305.                                              |
| `publicWindow.ts`     | Bucket/chunk/checkpoint hashing, append slot mapping, RFC 9162 inclusion, checkpoint predicates.                           |
| `storeDescriptor.ts`  | Store identity/routes, timeless authenticity versus explicit-time activation, scopes, chain-start equivocation.            |
| `normativeKernel.ts`  | Registry shape validators (shape only — no predicate, no evidence, no wording authorizer).                                 |

The current Phase-0 checkpoint closes these specific boundaries:

- non-pair payload field order and derivations are schema-owned, with immutable
  known-answer constants generated by a standalone Python standard-library
  reference encoder;
- public async validators canonically snapshot caller-owned values before their
  first `await`; room-operation contexts and reducer candidates additionally
  require process-private `WeakMap` provenance;
- the reducer classifies authenticated author forks/quota before nested
  signature work, revalidates bounded outer-expired evidence after restart,
  resolves cross-window `LEAVE` dependencies to a fixed point, and emits
  canonical presence, leave, descriptor-only store, revocation, capacity, and
  fault projections;
- future custody cannot fault current Core state, and historical evidence is
  inert except when a current valid dependency requires it;
- pair plaintext/body bytes, three class targets, minimal zero padding,
  initial slots, room-selected v4 frame geometry, transport-candidate order,
  pair transcript derivations, all ten complete pair bodies, and all three
  legal envelope forms execute against checked-in independent KATs; and
- frontend/authority policy precedence, revocation/fault selection, invalid
  grant mapping, and lease arithmetic execute only as explicitly untrusted
  semantics pending the protected admission constructors.

These are component-level facts, not a frozen v0.4 release registry or deployed
protocol. The pair-codec every-body/envelope vector sub-gate is complete, but
AC-035 as a whole remains open on complete outer-operation vectors, nonempty
`STORE_HINT` routes, the pre-open/post-open layer boundary, and exact
state-owned predecessor/dependency validation.

### `p2party-js/src/cryptography/`

`carrierAead.{c,h,ts}` expose XChaCha20-Poly1305 from the pinned libsodium.
**The WASM was rebuilt** — `libcrypto.wasm` 209,081 → 210,504 bytes, SRI now
`sha384-5bfyPJcX2JVKEJA8MK+YuBYDFu6VMg8Jphdt30CQBqHI8NIQSMwP1advvY5iuzXE`,
recorded in `wasmLoader.ts` and `libcrypto.provenance.json`.

### Live bug fixes (not spec work)

- **SDK**: send admission waits for a repairing peer edge
  (`PEER_ADMISSION_WAIT_MS` in `src/utils/constants.ts`); Firefox certificate
  notice deduped to once per session.
- **SDK + server**: TURN relay enabled with correlated room responses,
  identity/expiry-bound credentials, separate caller/managed configuration,
  live-PC rotation, all-room reconnect refresh, proactive bounded retry, and
  fail-closed expiry (see below).
- **Frontend**: the input remains below the message bubbles in normal flow;
  long drafts scroll internally; live-edge/history-reader behavior survives
  focus, blur, and composer growth; dynamic viewport and four-sided safe-area
  handling cover Chrome Android, iOS Safari geometry, and Capacitor. Badge
  clearance and the formerly hidden per-peer send-failure reason remain.

The SDK `0.14.4` production baseline was also exercised against
`wss://signaling.p2party.com/ws` and `https://p2party.com`: text, byte-exact
files, selective retransmission, a 16 MiB multi-window OPFS transfer,
reconnect/resume, drain-before-close, and OPFS reload persistence all completed
over real WebRTC. That run validates the legacy production transport baseline;
it is not evidence for blind-rendezvous conformance.

## Verification commands that actually work

```sh
# p2party-js
bunx tsc --noEmit -p tsconfig.json && bunx tsc --noEmit -p tsconfig.test.json
bunx eslint .
bun test tests/blindRendezvous
bun test tests

# p2party.com   -- `tsc -p tsconfig.json` checks ZERO files here; only this is real
npm run typecheck                   # tsc -b
npm test                            # 25 pass
npm run build                       # full SSG

# p2party-server
bun run typecheck
bun test tests                      # 48 pass
```

`prettier --check` over the whole `p2party-js` tree reports ~64 pre-existing
failures: the repo's `format` script covers a named subset, not the tree. Only
format files you touch.

## Blockers, precisely

### B1 — cleared

XChaCha20-Poly1305 now ships. Reproduces the published
`draft-irtf-cfrg-xchacha-03` Appendix A.3.1 vector byte for byte.

### B2 — Phase 0 is not frozen (blocks wire interop)

Integer widths in `schemas.ts` are this artifact's _proposal_ for the freeze.
§4.1 is explicit: until the binary schema, executable kernel, claim/formal
registries, HTTP protocol, default profile/planner/resource values, allocation
scheme, and compatibility hash are frozen and vector-tested, the design is
architecture-complete but **not wire-interoperable**, and implementations
"shall not independently invent release bytes and call them v0.4". No
release-registry hash has been computed.

### B3 — the store wire protocol

`p2party-server` has no append, allocation, chunk, or checkpoint endpoint; its
only entrypoint is the legacy WebSocket server. Client-side primitives can
authenticate canonical descriptors and routes, separate timeless signatures
from explicit lease activation, derive store/route scopes, verify public-window
geometry and proofs, and detect checkpoint/chain-start equivocation. They do not
form an end-to-end store implementation. What remains:

- the §4.6 HTTP route family (exact suffixes, media types, target lengths,
  status enum bytes, signature transcripts) — Phase-0 freeze items;
- the content-addressed route-family registry and parsers required before a
  nonempty `STORE_HINT` can validate;
- the §4.3.12 scheme-1 Privacy Pass allocation path — needs the frozen
  allocation registry including RFC 9578 token bytes and issuance vectors.

### B4 — `p2party.com` cannot reach the blind API

It vendors `p2party` as a hash-verified tarball (`file:vendor/p2party-<v>.tgz`,
`scripts/verifyLocalDependency.mjs` enforces the sha512). The blind modules are
deliberately not in the barrel. Integration needs a reviewed public API and a
new vendored package artifact/hash; the successful `0.14.4` production run did
not exercise blind rendezvous.

## Suggested next steps, in dependency order

1. **Freeze the remaining Phase-0 bytes.** Add complete outer-operation and
   state/layer-boundary vectors around the independently frozen
   `PairPlaintextV1` codec; freeze the content-addressed route-family
   registry/parsers (derived `RouteId` ordering itself is now executable and
   vector-tested); freeze the
   authority-view/custody persistence shapes; then freeze the store HTTP
   profiles/allocation artifacts and release compatibility hash.
2. **Implement the edge-local pair/admission boundary.** Pin a reviewed RFC
   9180 hybrid-HPKE implementation, implement pair AEAD/one-use routing tags and
   exact state-owned predecessor checks, then route the already codec-validated
   plaintext through one pure `Admit()` over a trusted atomic snapshot before
   SDP/ICE promotion.
3. **Connect the existing presence/revocation Core facts to admission and the
   pre-SDP identity gate.** Stable ownership remains a pair-private or trusted
   local lookup, not a room-wide disclosure.
4. **Implement the store client/server wire protocol and integration** only
   after the route/profile/allocation registries are frozen. Export and
   re-vendor the SDK API only after those boundaries and release gates pass.

## Gotchas discovered the hard way

- **`p2party.com` typecheck**: root `tsconfig.json` is references-only
  (`files: []`), so `tsc -p tsconfig.json` checks nothing. Use `npm run typecheck`.
- **WASM rebuild is a release action.** It re-emits an SRI-pinned,
  provenance-recorded binary that the frontend verifies. Ask before rebuilding.
  `README.md` hashes are synced by `scripts/buildRelease.mjs` at release time —
  do not hand-edit them (a previous hand-maintained paragraph went stale and
  failed the release version guard; it has been removed).
- The Android project sync was follow-up maintenance, not the root-cause fix.
  The actual defect was allocating chat-input space uniformly across mobile
  browsers and Capacitor even though they reveal the keyboard differently.
  `npx cap sync` was run only so the native wrapper consumes that frontend and
  configuration change.
- **`@capacitor-community/safe-area` requires `SystemBars.insetsHandling:
"disable"`** in `capacitor.config.ts`, else Capacitor core and the plugin both
  pad for the keyboard on different views and the offsets stack. Now set.
- **STUN-only ICE was the cause of peer flapping.** TURN is now wired
  end-to-end but needs `COTURN_URLS` rendered into the signaling env — it takes
  a **redeploy of the signaling service**, not just a client update.
- **Channel selection is not yet SSOT in the frontend.** Every `useRoom()` call
  currently owns an independent `"main"` state, while `ChannelListbox` is not
  mounted. Today both the message list and composer therefore use the same only
  active channel, but channel switching must move into one room-scoped source
  before that control is enabled.
- **Stable authority-grant expiry is deliberately not in-place in v0.4.** Stop
  post-promotion sensitive work and begin a fresh automatic pair attempt with a
  current grant while preserving the room/invitation UX. In-place refresh is
  post-v0.4 roadmap priority 18 and must first freeze the exact PQ slot, replay,
  causal-order, generation-replacement, and atomic-persistence rules.
- The canonical encoder rejects unsorted/duplicated collections _before_
  signatures, so some invalid fixtures cannot be constructed by signing. Build
  them directly with a dummy signature and assert the validator reports them.
- RFC 9162 audit paths are ordered **leaf-upward**. Verifying by walking down
  from the root silently recomputes a different root for any tree whose size is
  not a power of two. An exhaustive property test over sizes 1–17 caught this.

## Claims discipline — read before writing any user-facing text

The implementation may **not** claim S1, R2-BEC, SP1, L3 control compatibility,
shutdown-surviving messaging, PQ healing, or PQ authentication. None has its
evidence: no deployed store, no multi-client E2E, no browser or non-IP runs, no
measured cohorts, no classifier experiments, no formal results, no external
review.

No "secure", "BFT", "anonymous", or "censorship-resistant" label may appear
unless its compiled evidence predicate is actually satisfied. The runtime still
rejects `blind-meeting-point`; no UI, API, paper, or README may claim
conformance until the release gates pass.

What _is_ honestly claimable today: specific deterministic components execute,
their tests pass, the AEAD matches its published vector, HKDF matches RFC 5869
A.1/A.3, the two published policy constants re-derive exactly, and the RFC 9162
tree agrees with an independent implementation.

## Where the detail lives

- `docs/blind-rendezvous-implementation-status.md` — status, blockers, the nine
  adversarially-confirmed defects that were fixed, and the labels not earned.
- `spec/spec-architecture-l2-blind-rendezvous.md` — the normative source.
  §11 is the phase roadmap; §5 the acceptance criteria; §10 the validation gates.
- Local `master` history explains _why_ for each incremental design decision;
  it is the second-best entry point after this file.
