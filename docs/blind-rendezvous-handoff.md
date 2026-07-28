# Handoff: blind rendezvous + live fixes

Written 2026-07-28 for the next agent. Everything below is verified state, not
plan. Nothing is pushed; no PR exists.

## Continuation after this handoff

The next review completed later on 2026-07-28 and changes the safe next-step
ordering:

- `mergeOperationSets()` now compares complete canonical signed operation
  bytes when two entries claim one `OperationId`; same-signature/different-body
  collisions no longer pass as duplicates.
- Reducer tests now cover a non-revocation under the pinned authority and the
  exact five-element pending payload contract.
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

Do **not** start payload reduction as a mechanical codec task. The absent
`PairStepEnvelopeV1` codec, `STORE_HINT` ordering by derived `RouteId`, the
timeless-signature/absolute-lease split, and the authority-view/custody
constructor are Phase-0 decisions. Current `activeOperationIds` is therefore
an outer-framed candidate projection, not yet the complete specified
`OuterValidOperationSet`. The next implementation step is to freeze those
schema/kernel decisions and vectors; only then implement the closed nested
decoder and `Admit()`.

Current verification after this continuation:

```sh
bunx tsc --noEmit -p tsconfig.json
bunx tsc --noEmit -p tsconfig.test.json
bunx eslint <touched TypeScript files>
bun test tests # 629 pass, 0 fail, 85 files
```

## Repositories and branches

| Repo             | Path                                | Branch                          | State                                        |
| ---------------- | ----------------------------------- | ------------------------------- | -------------------------------------------- |
| `p2party-js`     | `~/Desktop/@p2party/p2party-js`     | `feat/blind-rendezvous-phase-0` | 14 commits ahead of `master`                 |
| `p2party-server` | `~/Desktop/@p2party/p2party-server` | `fix/enable-turn-relay`         | 1 commit ahead of `master`                   |
| `p2party.com`    | `~/Desktop/@p2party/p2party.com`    | `master`                        | 2 commits on `master` (`158de8a`, `3e21f60`) |

The frontend commits went to `master` because that matches the repo's own recent
history. Moving them to a branch is safe (nothing is pushed) if a PR is wanted.

**Do not touch these uncommitted files in `p2party-js` — they are the human's:**

- `spec/spec-architecture-l2-blind-rendezvous.md` (modified, `last_updated: 2026-07-28`)
- `docs/rendezvous-prior-art.md` (untracked, deliberately untracked by `b2c147f`)

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

| Module               | Owns                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------- |
| `canonicalSchema.ts` | Descriptor-driven canonical binary codec: field order, integer widths, enum bytes, collection ordering, bounds. |
| `schemas.ts`         | Descriptors for the §4.0–4.5 objects implemented so far.                                                        |
| `projections.ts`     | Generated key tables and enum projections. No hand-maintained duplicate remains.                                |
| `derivations.ts`     | Domain-separated hashes, HKDF-SHA-256, room/operation/carrier identifiers.                                      |
| `roomPolicyV4.ts`    | `RoomPolicyV4` validation, canonical codec, `DEFAULT_BLIND_POLICY_V4_0`.                                        |
| `roomInviteV2.ts`    | Closed `v1 \| v2` invitation parsing, both v2 fragment forms, the two typed errors.                             |
| `operation.ts`       | `AuthenticatedRoomOperationV1` codec, outer validation, Ed25519 sign/verify.                                    |
| `coreReduce.ts`      | Merge (set union) and deterministic outer-layer `CoreReduce`.                                                   |
| `carrierEnvelope.ts` | Envelope framing, key schedule, AAD, object identity over XChaCha20-Poly1305.                                   |
| `publicWindow.ts`    | Bucket/chunk/checkpoint hashing, append slot mapping, RFC 9162 inclusion, checkpoint predicates.                |
| `storeDescriptor.ts` | Store identity, routes, carrier/route-instance scopes, chain-start equivocation.                                |
| `normativeKernel.ts` | Registry shape validators (shape only — no predicate, no evidence, no wording authorizer).                      |

### `p2party-js/src/cryptography/`

`carrierAead.{c,h,ts}` expose XChaCha20-Poly1305 from the pinned libsodium.
**The WASM was rebuilt** — `libcrypto.wasm` 209,081 → 210,504 bytes, SRI now
`sha384-5bfyPJcX2JVKEJA8MK+YuBYDFu6VMg8Jphdt30CQBqHI8NIQSMwP1advvY5iuzXE`,
recorded in `wasmLoader.ts` and `libcrypto.provenance.json`.

### Live bug fixes (not spec work)

- **SDK**: send admission waits for a repairing peer edge
  (`PEER_ADMISSION_WAIT_MS` in `src/utils/constants.ts`); Firefox certificate
  notice deduped to once per session.
- **SDK + server**: TURN relay actually enabled (see below).
- **Frontend**: chat-composer positioning across mobile browsers (which reveal
  the keyboard by resizing the viewport) and Capacitor (which exposes native
  keyboard/safe-area insets), plus badge/bubble clearance and the per-peer
  send-failure reason that was hidden in two-peer rooms.

## Verification commands that actually work

```sh
# p2party-js
bunx tsc --noEmit -p tsconfig.json && bunx tsc --noEmit -p tsconfig.test.json
bunx eslint .
bun test tests                      # 625 pass, 0 fail, 85 files

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
only entrypoint is the legacy WebSocket server. The client can now verify a
store end to end _short of the wire protocol_. What remains:

- the §4.6 HTTP route family (exact suffixes, media types, target lengths,
  status enum bytes, signature transcripts) — Phase-0 freeze items;
- the §4.3.12 scheme-1 Privacy Pass allocation path — needs the frozen
  allocation registry including RFC 9578 token bytes and issuance vectors.

### B4 — `p2party.com` cannot reach the blind API

It vendors `p2party` as a hash-verified tarball (`file:vendor/p2party-<v>.tgz`,
`scripts/verifyLocalDependency.mjs` enforces the sha512). The blind modules are
deliberately not in the barrel. **The WASM rebuild also means the frontend must
re-vendor before it can load the new module.**

## Suggested next steps, in dependency order

1. **Payload-level reduction.** `coreReduceOuter` returns
   `pendingPayloadReduction` naming `observedPresences`,
   `effectiveLeaveOperationIds`, `storeCatalogFacts`, `revocationFloors`, and
   `roomCapacityState`. These need the §4.2/4.9 nested payload codecs
   (`PresenceV1`, `LeaveV1`, `StoreHintOperationV1`, `AdmissionRevokeV1`).
   Do **not** return empty arrays for these — an empty array reads as an
   observation. That is why the pending list exists.
2. **§4.8 `Admit()`** — one shared admission function, decision leases,
   `FrontendRoomControlsV1`, authority grants/revokes. Pure, testable, no wire
   freeze needed.
3. **§4.9 presence** and the pre-SDP identity gate.
4. Only then the store server (B3), once Phase 0 freezes.

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
- Commit messages on `feat/blind-rendezvous-phase-0` explain _why_ for each
  design decision; they are the second-best entry point after this file.
