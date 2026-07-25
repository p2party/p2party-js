# References

What p2party is built from, and what it is built on. Every entry links to a
primary source: a standard, a paper, or the implementation itself.

For the full research treatment — including a per-claim novelty assessment and
142 verified citations — see
[Related work and prior art](paper-prior-art-and-related-work.md).

## 1. Cryptographic dependencies

These are compiled into the shipped `libcrypto.wasm` or bundled into the
package. Licences and notices are reproduced in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

| Project                 | Used for                                                           | Link                                                                                       |
| ----------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| libsodium               | X25519, Ed25519, ChaCha20-Poly1305, BLAKE2b, HKDF, Argon2, SHA-512 | [github.com/jedisct1/libsodium](https://github.com/jedisct1/libsodium)                     |
| mlkem-native            | ML-KEM-512/768/1024 (FIPS 203)                                     | [github.com/pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native) |
| Emscripten              | Compiles the C cryptography to the pinned WASM module              | [emscripten.org](https://emscripten.org/)                                                  |
| BIP-39 English wordlist | The 24-word room-capability encoding                               | [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md)       |
| Redux Toolkit           | Browser-root state store                                           | [redux-toolkit.js.org](https://redux-toolkit.js.org/)                                      |

## 2. Standards the wire format implements

| Standard                                   | Where it appears in p2party                               | Link                                                                                                          |
| ------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **FIPS 203** — ML-KEM                      | Room-fixed post-quantum bootstrap and healing epochs      | [csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)                                |
| **RFC 8439** — ChaCha20-Poly1305           | AEAD for every chunk frame                                | [rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439.html)                                     |
| **RFC 5869** — HKDF                        | Root and chain-key derivation                             | [rfc-editor.org/rfc/rfc5869](https://www.rfc-editor.org/rfc/rfc5869.html)                                     |
| **RFC 7748** — X25519                      | Interactive 3DH and the ratchet DH turns                  | [rfc-editor.org/rfc/rfc7748](https://www.rfc-editor.org/rfc/rfc7748.html)                                     |
| **RFC 8032** — Ed25519                     | Long-term identity keys and cross-signatures              | [rfc-editor.org/rfc/rfc8032](https://www.rfc-editor.org/rfc/rfc8032.html)                                     |
| **draft-irtf-cfrg-cpace-21** — CPace       | PIN-room balanced PAKE                                    | [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21)                        |
| **RFC 8831 / 8832** — WebRTC data channels | The transport every peer edge runs over                   | [8831](https://datatracker.ietf.org/doc/html/rfc8831) · [8832](https://datatracker.ietf.org/doc/html/rfc8832) |
| **RFC 8122** — SDP DTLS fingerprints       | Endpoint fingerprints bound into the handshake transcript | [datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc8122)                                         |
| **RFC 9794** — PQ/T hybrid terminology     | How the hybrid security boundary is described             | [rfc-editor.org/rfc/rfc9794](https://www.rfc-editor.org/rfc/rfc9794.html)                                     |

## 3. Papers the design follows

**Ratcheting and the Signal lineage**

- M. Marlinspike, T. Perrin. _The Double Ratchet Algorithm._ Signal, 2016.
  https://signal.org/docs/specifications/doubleratchet/
- M. Marlinspike, T. Perrin. _The X3DH Key Agreement Protocol._ Signal, 2016.
  https://signal.org/docs/specifications/x3dh/
- J. Alwen, S. Coretti, Y. Dodis. _The Double Ratchet: Security Notions,
  Proofs, and Modularization for the Signal Protocol._ EUROCRYPT 2019.
  https://eprint.iacr.org/2018/1037
- K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt, D. Stebila. _A Formal
  Security Analysis of the Signal Messaging Protocol._ EuroS&P 2017; J.
  Cryptology 33(4), 2020. https://eprint.iacr.org/2016/1013

**Post-quantum messaging**

- E. Kret, R. Schmidt. _The PQXDH Key Agreement Protocol._ Signal, 2023.
  https://signal.org/docs/specifications/pqxdh/
- K. Bhargavan, C. Jacomme, F. Kiefer, R. Schmidt. _Formal Verification of the
  PQXDH Post-Quantum Key Agreement Protocol._ USENIX Security 2024.
  https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf
- Y. Dodis, D. Jost, S. Katsumata, T. Prest, R. Schmidt. _The Triple Ratchet: A
  Bandwidth Efficient Hybrid-Secure Signal Protocol._ EUROCRYPT 2025.
  https://eprint.iacr.org/2025/078
- B. Auerbach, Y. Dodis, D. Jost, S. Katsumata, T. Prest, R. Schmidt.
  _Post-Quantum Ratcheting for Signal._ NIST 6th PQC Standardization
  Conference, 2025.
  https://csrc.nist.gov/csrc/media/events/2025/sixth-pqc-standardization-conference/post-quantum%20ratcheting%20for%20signal.pdf
- M. Barbosa et al. _X-Wing: The Hybrid KEM You've Been Looking For._ IACR
  Communications in Cryptology, 2024. https://eprint.iacr.org/2024/039
- F. Linker, R. Sasse, D. Basin. _A Formal Analysis of Apple's iMessage PQ3
  Protocol._ USENIX Security 2025.
  https://www.usenix.org/conference/usenixsecurity25/presentation/linker

p2party's sparse post-quantum healing is directly inspired by Signal's SPQR
design; the two are not the same construction, and p2party's has not been
independently analysed.

- Signal Foundation. _SPQR: Signal Protocol and Post-Quantum Ratchets._ 2025.
  https://signal.org/blog/spqr/ ·
  https://github.com/signalapp/SparsePostQuantumRatchet

**PAKE and channel binding**

- M. Abdalla, B. Haase, J. Hesse. _Security Analysis of CPace._ ASIACRYPT 2021.
  https://eprint.iacr.org/2021/114
- N. Williams. _RFC 5056: On the Use of Channel Bindings to Secure Channels._
  https://www.rfc-editor.org/rfc/rfc5056.html

**Traffic analysis and cover traffic** — the basis for scheduled cover, and for
the honest limits stated in the
[security boundary](protocol-v4-security.md).

- A. Piotrowska, J. Hayes, T. Elahi, S. Meiser, G. Danezis. _The Loopix
  Anonymity System._ USENIX Security 2017. https://arxiv.org/abs/1703.00536
- X. Cai, R. Nithyanand, T. Wang, R. Johnson, I. Goldberg. _A Systematic
  Approach to Developing and Evaluating Website Fingerprinting Defenses
  (Tamaraw)._ ACM CCS 2014. https://doi.org/10.1145/2660267.2660362
- T. Pulls, E. Witwer. _Maybenot: A Framework for Traffic Analysis Defenses._
  WPES @ CCS 2023. https://doi.org/10.1145/3603216.3624953
- S. Sasy, I. Goldberg. _SoK: Metadata-Protecting Communication Systems._
  PoPETs 2024. https://doi.org/10.56553/popets-2024-0030
- M. Weisenseel, C. Döpmann, F. Tschorsch. _The Last Hop Attack: Why Loop Cover
  Traffic over Fixed Cascades Threatens Anonymity._ PoPETs 2025.
  https://doi.org/10.56553/popets-2025-0067
- K. Nikitin et al. _Reducing Metadata Leakage from Encrypted Files and
  Communication with PURBs._ PoPETs 2019.
  https://petsymposium.org/popets/2019/popets-2019-0056.php

## 4. Related open-source systems

Projects solving adjacent problems. Several informed p2party's design; none
share its code.

**Browser E2E ratchets**

- [matrix-org/vodozemac](https://github.com/matrix-org/vodozemac) — Rust/WASM
  Olm and Megolm for Matrix.
- [wireapp/core-crypto](https://github.com/wireapp/core-crypto) — MLS and
  Proteus for Wire, compiled to WASM.
- [PeculiarVentures/2key-ratchet](https://github.com/PeculiarVentures/2key-ratchet)
  — Double Ratchet + X3DH on WebCrypto (archived).
- [PeculiarVentures/pqc-ratchet](https://github.com/PeculiarVentures/pqc-ratchet)
  — post-quantum Double Ratchet, ML-KEM-768 + X25519.
- [LukaJCB/ts-mls](https://github.com/LukaJCB/ts-mls) — TypeScript MLS
  (RFC 9420) with post-quantum ciphersuites.

**Browser peer-to-peer transfer**

- [saljam/webwormhole](https://github.com/saljam/webwormhole) — CPace over
  WebRTC with DTLS-fingerprint binding; the closest prior art to p2party's PIN
  rooms.
- [magic-wormhole](https://github.com/magic-wormhole/magic-wormhole-protocols) —
  SPAKE2 code-phrase transfer; origin of the short-code UX.
- [schlagmichdoch/PairDrop](https://github.com/schlagmichdoch/PairDrop) and
  [kern/filepizza](https://github.com/kern/filepizza) — WebRTC file transfer
  without accounts.
- [js-libp2p](https://libp2p.io/docs/webrtc-browser-connectivity/) — WebRTC
  browser transport with Noise.

**Traffic shaping and obfuscation**

- [Yawning/obfs4](https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt)
  — padding and timing obfuscation for Tor pluggable transports.
- [maybenot](https://github.com/maybenot-io/maybenot) — the framework behind
  the traffic-analysis defence paper above.

## 5. How to cite p2party

p2party has not been published as a paper and has not completed an independent
third-party security audit. Cite the implementation:

```bibtex
@software{p2party,
  title  = {p2party: protocol-v4 end-to-end encryption over a WebRTC room mesh},
  url    = {https://github.com/p2party/p2party-js},
  note   = {Version 0.13.0}
}
```
