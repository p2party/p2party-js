# p2party protocol-v3 ProVerif scaffold

Status: **not yet a proof**. This directory contains a first symbolic model of
the current no-PIN, pairwise protocol-v3 bootstrap after triple confirmation.
It targets ProVerif 2.04, matching the pinned
[PQXDH analysis artifact](https://github.com/Inria-Prosecco/pqxdh-analysis/tree/a09439cc350629ec430fb486305baa4001abbee1),
and is also intended to parse with ProVerif 2.05. ProVerif and opam were not
installed when this scaffold was written, so no successful parser or solver run
has been recorded.

## What is modeled

- Two principals, both role directions, unbounded concurrent sessions, and a
  Dolev–Yao adversary controlling the public network.
- A pinned Ed25519 identity anchor as an ideal authenticated credential over
  the dedicated static X25519 public key. Ed25519 and X25519 secrets are
  deliberately distinct.
- The implemented interactive secret
  `DH(IK_I, EK_R) || DH(EK_I, IK_R) || DH(EK_I, EK_R)`.
- An ideal ML-KEM encapsulation/decapsulation leg. The active profile accepts
  exactly `suite_mlkem768`; public 512 and 1024 constants exist only so a wrong
  suite can be supplied and rejected. A separate run should use a separate
  fixed constant for either alternative suite—there is no negotiation or
  fallback.
- The suite, role-ordered identities and credentials, ML-KEM key/ciphertext,
  fresh session identifiers, ephemeral keys, ratchet keys, and an opaque
  WebRTC/DTLS channel binding in the root/confirmation transcript.
- The implemented confirmation chain:
  `mac_R`, `mac_I(transcript, mac_R)`,
  `mac_F(transcript, mac_R, mac_I)`. The initiator accepts only after checking
  `mac_F`; the responder accepts after it verifies `mac_I` and sends `mac_F`.

The role-specific HELLO constructors abstract the canonical all-zero unused
CPace/KEM fields. This is a protocol model, not a byte-parser or length model.

## Query profiles

The source uses the same C-preprocessor pattern as the PQXDH artifact.

`PROFILE_BASELINE` removes all compromise/broken-primitive oracles and states:

- root secrecy at initiator and responder acceptance;
- injective directional agreement over the exact transcript, root, ratchet
  keys, and three confirmation proofs;
- exact root/transcript agreement; and
- acceptance reachability guards, to expose vacuous proofs.

`PROFILE_THREAT` enables separate X25519/Ed25519 compromise controls and
attacker-triggered DH/KEM break oracles. Its necessary-condition queries are
intended to explore:

- peer impersonation after pre-accept peer static-key compromise;
- KCI: compromise of the accepting endpoint's own static key is deliberately
  **not** an authentication or secrecy exception;
- static-key forward secrecy; and
- HNDL: a DH break only after an accepted session should not expose its root
  unless the KEM assumption also breaks.

These threat queries intentionally use coarse global broken-assumption events.
A successful result would apply only to this symbolic model and its perfect
primitives.

## Run

Preprocess outside the repository, then invoke ProVerif:

```sh
mkdir -p /tmp/p2party-proverif
cpp -P -traditional-cpp -DPROFILE_BASELINE \
  formal/proverif/p2party-v3-nopin-triple-confirmation.cpp.pv \
  > /tmp/p2party-proverif/baseline.pv
proverif /tmp/p2party-proverif/baseline.pv

cpp -P -traditional-cpp -DPROFILE_THREAT \
  formal/proverif/p2party-v3-nopin-triple-confirmation.cpp.pv \
  > /tmp/p2party-proverif/threat.pv
proverif /tmp/p2party-proverif/threat.pv
```

Do not mark a property proved until the generated file parses, the reachability
queries show honest completion is reachable, the relevant security query
returns true, and any approximations/attack traces have been reviewed manually.

## Explicit limits and non-claims

- The model assumes the peer's Ed25519 anchor is already authenticated/pinned.
  It therefore does **not** solve no-PIN identity substitution by a malicious
  signaling service.
- `hybrid_extract`/`hybrid_expand` are perfect symbolic constructors. This
  model cannot prove that
  `HKDF-Extract(0, 3DH || ML-KEMss)` is a secure robust combiner. That needs an
  explicit computational argument/model (for example CryptoVerif), with the
  real HKDF assumptions and ML-KEM security notion.
- The ideal KEM does not capture ML-KEM implementation bugs, malformed
  encodings, re-encapsulation subtleties, side channels, or active quantum
  authentication. Authentication remains classical.
- The opaque channel binding assumes both honest roles obtained the same
  role-aware `channelInput` and that DTLS fingerprints were verified. The
  browser API, SDP/ICE, DTLS/SCTP, and signaling implementation are out of
  scope.
- CPace/PIN rooms, Double/Triple Ratchet evolution, message AEAD, persistence
  and erasure, sparse PQ healing, cover traffic, room mesh consistency, and L2
  rendezvous are not modeled.
- There is intentionally no query `accept_r ==> accept_i`. A responder can send
  a valid `mac_F` and complete while the final packet is dropped. An established
  RTCDataChannel predates this application handshake and is not a peer-verified
  receipt for `mac_F`; no finite acknowledgement chain creates synchronized
  final delivery or common knowledge on a lossy transport.

The next formal milestone is to get both profiles through ProVerif, inspect all
traces, then separate computational combiner work from a Tamarin model of
confirmation ordering, erasure, and multi-peer state.
