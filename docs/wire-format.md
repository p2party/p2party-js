# Wire format

Chunk geometry is defined in
[`src/utils/constants.ts`](../src/utils/constants.ts) and byte-matched in
`utils.h`. Scheduled control subtypes are defined in
[`coverCell.ts`](../src/cryptography/coverCell.ts); immediate transfer controls
are defined in [`immediateDisposition.ts`](../src/handlers/immediateDisposition.ts).
For what these frames do and do not protect, read the
[protocol-v4 security boundary](protocol-v4-security.md).

## Outer frame types

One tag byte leads every frame on a data channel.

| Tag | Name                    | Size on the wire | Carries                               |
| --- | ----------------------- | ---------------- | ------------------------------------- |
| 1   | `HANDSHAKE`             | step-dependent   | HELLO, CONFIRM, FINISH                |
| 2   | `CHUNK`                 | 65,490 B         | one fixed application cell            |
| 3   | `RECEIPT`               | 65 B             | SHA-512 acknowledgement token         |
| 4   | `COVER`                 | 65,490 B         | scheduled dummy or encrypted control  |
| 5   | `PQ_CONTROL`            | 65,490 B         | sparse-PQ OFFER / ADVANCE / ACK       |
| 6   | `IMMEDIATE_DISPOSITION` | 66 B             | immediate resume capability or CANCEL |

Tags 2, 4, and 5 have equal payload lengths. The frame tags travel inside
WebRTC's DTLS transport; packetization, timing and total traffic remain
observable. Scheduled real data uses tag 2 in a scheduled lane slot.

## Chunk frame — 65,490 bytes

```text
 0        1                     33      41      49        57         69                        65,474    65,490
 +--------+---------------------+-------+-------+---------+----------+-------------------------+---------+
 | type=2 | ratchet dhPub (32)  | N (8) | PN(8) | pqEpoch | nonce    | ciphertext (65,405)     | tag(16) |
 |  (1)   |                     |  BE   |  BE   |  (8) BE |   (12)   |                         |         |
 +--------+---------------------+-------+-------+---------+----------+-------------------------+---------+
 |<---------- in AAD after the Merkle root: 57 bytes -->|          |
 |<------------------- clear header: 69 bytes ---------------------->|
```

- The AEAD additional data is 121 bytes: the transfer's 64-byte Merkle root
  followed by header bytes 0–56 (type, DH public key, N, PN, pqEpoch). The
  12-byte nonce is not in the additional data; it is the AEAD nonce, so a
  changed nonce fails the tag check.
- `pqEpoch` is an unsigned 64-bit counter. v3 used a single byte; v4 widened it
  so the sparse-PQ healing epoch cannot wrap.
- The plaintext cell is always 65,405 bytes, so at most **61,912 bytes** are
  caller payload; the remainder is metadata, the Merkle proof, and padding.
- ChaCha20-Poly1305 supplies the 16-byte tag.

## Receipt frame — 65 bytes

```text
 0        1                                                          65
 +--------+-----------------------------------------------------------+
 | type=3 | SHA-512 receipt token (64)                                 |
 +--------+-----------------------------------------------------------+
```

Both per-chunk acknowledgements and the terminal content-hash acknowledgement
use this exact geometry, so a completion is not distinguishable by size.
Chunk tokens bind the transfer Merkle root, original chunk index and leaf hash.
The sender resolves them through its staged chunk index and persists the
per-recipient acknowledgement before updating the live have-set. A terminal
immediate receipt must equal the message's content hash. These frames use the
authenticated concrete message channel and its current identity gate.

## Scheduled control cells — 65,490 bytes

```text
type=4(1) || edge binding(32) || counter(8) || reserved zero(8) ||
PQ epoch(8) || nonce(12) || ciphertext(65,405) || AEAD tag(16)
```

All 69 header bytes are authenticated. The key binds the room's suite, edge,
direction and PQ epoch. After authentication and counter replay rejection,
the plaintext is `subtype(1) || payload length(4, BE) || payload || zero pad`:

| Subtype | Meaning          | Payload                                                                |
| ------- | ---------------- | ---------------------------------------------------------------------- |
| 1       | Dummy            | Empty                                                                  |
| 2       | CANCEL           | Transfer Merkle root (64 B)                                            |
| 3       | Terminal receipt | Transfer Merkle root (64 B), followed by the same root as token (64 B) |
| 4       | Chunk receipts   | Transfer Merkle root (64 B), followed by 1–64 chunk tokens (64 B each) |

Subtype 4's authenticated payload length determines the token count; partial
tokens, empty batches and batches over 64 tokens are rejected. Only tokens for
one transfer root share a batch. A subtype 3 token unequal to its root cannot
complete a send. Each chunk token must resolve to the tracked transfer, root
and a valid original index. The durable owner also binds room, recipient ID
and public key; a stale owner cannot advance live state after a storage await.
A recipient's CANCEL records refusal only for that recipient.

Receipts and CANCELs replace dummy slots in the existing schedule. The pending
outbound control queue is bounded to 4,096 token/control units; dropping a
queued acknowledgement may require a later retransmission. A terminal receipt
supersedes unsent chunk acknowledgements for the same root, preserving the
first available reverse slot for completion even at long cadences. Other roots
and queued CANCEL controls retain their order. Live have-set
membership uses an O(1) `Set` lookup without copying the set per slot. A resumed
producer scans original indices once and emits missing chunks. It also selects
index zero once per attempt to recover a lost terminal receipt: if that index
was already acknowledged, this costs one extra completion probe. Index scanning
and durable token lookups do not imply globally sublinear processing, and fewer
real chunks do not reduce the fixed scheduled cell count.

Subtype 4 is a protocol-v4 wire addition. Earlier clients reject and drop this
unknown subtype and keep using subtype 3 completion. They cannot selectively
resume scheduled chunks; a missing terminal receipt can require whole-transfer
replay. Subtype 3 is never reused for chunk tokens, because earlier clients
treated any subtype 3 receipt for a tracked root as completion. These additions
do not introduce a fallback to an earlier cryptographic protocol version.

## Immediate pause and cancellation — 66 bytes

```text
type=6(1) || kind(1) || transfer Merkle root(64)
```

Kind 0 announces resume support; kind 1 is explicit CANCEL. An immediate
message channel opened with DCEP protocol `p2party-resume-v1` promises that a
bare close may pause the transfer. A supporting receiver echoes kind 0 after
the identity gate opens. The current client treats any bare close as an
interruption, including a close before this echo. CANCEL is accepted once per concrete channel, only under its current
authenticated gate and exact root. Malformed, unknown, stale and cross-root
controls have no effect. This control relies on the authenticated DTLS/SCTP
channel; it has no separate application AEAD envelope.

An explicit cancellation sends kind 1 before closing. A transient failed
attempt closes without CANCEL, allowing a supporting receiver to retain its
partial data for bounded resume. Earlier clients ignore type 6 and retain
their close-as-cancel behavior. At a fresh immediate attempt the new sender
starts a fresh live chunk have-set and rebuilds it from the receiver's paced
receipt replay, so deleted legacy partials cause full resend
instead of trusting stale acknowledgements. The store-free session API does
not implement this WebRTC channel contract.

## Handshake ladder

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

## Sparse post-quantum healing

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

The browser scheduler starts a local exchange only when no real producer,
derive-to-enqueue reservation, message channel or queued receive work remains.
Dummy/control cover alone does not hold it back. A remote exchange blocks new
application admission and drains reservations before the durable transition;
it does not wait for a long scheduled send to finish. A committed new epoch
retires old-key real producers and publishes a cover generation change on the
same runtime. The sender re-derives the remaining transfer under that epoch;
fixed lane timing continues with dummy tails. An unrelated generation notice
cannot authorize reuse of the same runtime without an actual PQ epoch advance.

## Room policy — 32 bytes

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
