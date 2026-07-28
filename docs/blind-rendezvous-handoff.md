# Handoff: blind rendezvous + live fixes

Written 2026-07-28 for the next agent and updated after local branch
reconciliation. The production-correctness baseline is on each repository's
local `master`; the non-pair payload/Core-reducer increment described below is
the current local `p2party-js` Phase-0 checkpoint. Nothing is pushed; no PR
exists.

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
- Section 4.8 now has an explicit `AdmissionEvaluationInputV1`, versioned pair
  and decision leases, an exact lease constructor/minimum, and a validated
  atomic authority-admission view. Do not implement a caller-supplied
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

Non-pair payload reduction is no longer pending: the working tree contains
closed codecs and intrinsic validation for `PRESENCE`, `LEAVE`, descriptor-only
`STORE_HINT`, and `ADMISSION_REVOKE`, plus pair-private `AdmissionGrantV1`
validation and deterministic Core facts. This does **not** close the complete
operation boundary. `PairPlaintextV1` and its body union are absent, nonempty
`STORE_HINT` routes fail closed until the route-family registry/parser is
frozen, and the sole admission/view/custody kernel is still absent. Therefore a
`PAIR_STEP` in `activeOperationIds` is outer-authenticated only and the current
state is not yet the specification's complete pair/admission result.

Verification commands for the current tree:

```sh
bunx tsc --noEmit -p tsconfig.json
bunx tsc --noEmit -p tsconfig.test.json
bunx eslint <touched TypeScript files>
bun test tests/blindRendezvous
bun test tests
```

Verification after the final review edits:
`bun test tests/blindRendezvous` — 228 pass, 0 fail, 14 files; `bun test tests`
— 800 pass, 0 fail, 105 files. Both TypeScript configurations, ESLint, and
`git diff --check` also pass.

## Repositories and branches

| Repo             | Path                                | Branch   | Local state                                                                  |
| ---------------- | ----------------------------------- | -------- | ---------------------------------------------------------------------------- |
| `p2party-js`     | `~/Desktop/@p2party/p2party-js`     | `master` | WebRTC/TURN baseline and current non-pair/Core Phase-0 checkpoint merged locally |
| `p2party-server` | `~/Desktop/@p2party/p2party-server` | `master` | TURN endpoint issuance merged; 1 commit ahead of `origin/master`             |
| `p2party.com`    | `~/Desktop/@p2party/p2party.com`    | `master` | Frontend fixes already present; 2 commits ahead of `origin/master`           |

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
| `schemas.ts`          | Descriptors for implemented room operations, non-pair payloads, store objects, and canonical Core state/faults.            |
| `projections.ts`      | Generated key tables and enum projections. No hand-maintained duplicate remains.                                           |
| `derivations.ts`      | Domain-separated hashes, HKDF-SHA-256, room/operation/carrier identifiers.                                                 |
| `roomPolicyV4.ts`     | `RoomPolicyV4` validation, canonical codec, `DEFAULT_BLIND_POLICY_V4_0`.                                                   |
| `roomInviteV2.ts`     | Closed `v1 \| v2` invitation parsing, both v2 fragment forms, the two typed errors.                                        |
| `pairStepEnvelope.ts` | Schema-derived `PairStepEnvelopeV1` framing and exact suite-1 class targets.                                               |
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
  inert except when a current valid dependency requires it.

These are component-level facts, not a frozen v0.4 release registry or deployed
protocol.

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

1. **Freeze the remaining Phase-0 bytes.** Add the canonical
   `PairPlaintextV1`/closed body union and vectors; freeze the
   content-addressed route-family registry/parsers (derived `RouteId` ordering
   itself is now executable and vector-tested); freeze the
   authority-view/custody persistence shapes; then freeze the store HTTP
   profiles/allocation artifacts and release compatibility hash.
2. **Implement the edge-local pair/admission boundary.** Open pair AEAD, prove
   plaintext minimality/sequence/predecessor/body/one-use routing tag, and route
   the result through one pure `Admit()` over a trusted atomic snapshot before
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
