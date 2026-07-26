# Wire format

Every byte here is derived from
[`src/utils/constants.ts`](../src/utils/constants.ts), which is the single
source of truth and is byte-matched in `utils.h`. For what these frames do and
do not protect, read the
[protocol-v4 security boundary](protocol-v4-security.md).


## Outer frame types

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

## Chunk frame — 65,490 bytes

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

## Receipt frame — 65 bytes

```text
 0        1                                                          65
 +--------+-----------------------------------------------------------+
 | type=3 | SHA-512 receipt token (64)                                 |
 +--------+-----------------------------------------------------------+
```

Both per-chunk acknowledgements and the terminal content-hash acknowledgement
use this exact geometry, so a completion is not distinguishable by size.

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
