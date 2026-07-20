# Crypto hardening — Tier 2 (protocol-v2) design

Date: 2026-07-20
Repo: `p2party-js`
Status: in progress

Wire-format-/semantics-breaking crypto changes. Each requires a WASM rebuild and
a CDN redeploy (`npm run uploadcdn`), and old/new clients cannot interoperate
(hard cutover). The signature and Merkle changes happen BEFORE decryption, so
they cannot be gated by the in-metadata `schemaVersion`; both peers must run the
new build.

## Threat recap

- **Message forgery (CRITICAL):** chunk auth is `Ed25519.verify(ephemeral_pk, sig, sender_identity_pk)` — a bare signature over a 32-byte ephemeral public key. The same identity key also signs the server's 32-byte login challenge with no domain separation. A malicious signaling server sends the victim a "challenge" equal to an ephemeral pubkey it controls, harvests the signature, and injects a single-chunk frame the receiver accepts as authentically from the victim.
- **Merkle malleability (MEDIUM):** `merkle.c` hashes odd nodes with themselves (`H(leaf‖leaf)`) and uses no leaf/node domain separation (CVE-2012-2459 class).
- **NULL-check bug (LOW):** `chacha20poly1305.c` decrypt tests the wrong pointer after a malloc.

## This increment

### 1. NULL-check fix — `chacha20poly1305.c` (safe, no wire change)

After `malloc` of `sender_x25519_pk`, the guard tests `receiver_x25519_pk`; fix it
to test `sender_x25519_pk` so an allocation failure returns cleanly instead of
dereferencing NULL.

### 2. Signature forgery fix — bind chunk auth to a domain-separated transcript

Replace "sign the bare ephemeral pubkey" with "sign a domain-separated transcript"
so a signature harvested from the raw-nonce challenge oracle can never satisfy
chunk verification. **No server change** (the challenge signature format is left
alone; the two signature domains simply become incompatible).

Transcript (117 bytes), signed with the sender identity key:

```
DOMAIN(21) = "p2party-chunk-auth-v1"   ‖ merkle_root(64) ‖ ephemeral_pk(32)
```

- Send (`handleSendMessage.ts` / `allocators.ts`): build the transcript in a WASM
  buffer (domain + merkle root constant per message; ephemeral pk per chunk) and
  `_sign(117, transcript, senderSecretKey, sig)` instead of signing the 32-byte
  ephemeral pubkey.
- Receive (`utils.c` `receive_message`): reconstruct the 117-byte transcript from
  the domain constant, the passed `merkle_root`, and `message[0..32]`, then
  `verify(117, transcript, sender_public_key, &message[32])`.
- Frame layout is byte-identical (still `eph_pk(32) ‖ sig(64) ‖ nonce ‖ ct ‖ tag`);
  only the signed content changes. `DOMAIN` defined once in `utils.h` and mirrored
  in TS. Bump `metadataSchemaVersion` default 1→2 for documentation (the break is
  actually enforced by the pre-decryption verify).

Verification: a mismatch between the TS and C transcripts makes every transfer
fail, which the real-WebRTC E2E (two p2party.com contexts, byte-exact file) catches
immediately; a passing transfer proves send/receive agree on the new auth.

## Deferred to the next increment (specified, not yet built)

- **Merkle domain separation + odd-node promotion** (`merkle.c` node hashing =
  `H(0x01‖left‖right)`, leaf hashing = `H(0x00‖chunk)` in `splitToChunks.ts` +
  `utils.c`; promote a lone odd node instead of `H(leaf‖leaf)`). Lower severity;
  fully E2E-verifiable but touches four files in lockstep — its own careful pass.
- **Forward secrecy** — a genuine redesign (Noise IK/XX or X3DH: both parties
  contribute ephemerals, identity keys only authenticate). Not a bug fix; belongs
  with the PAKE-rooms sub-project.
- **Challenge-signature domain separation** on the server side (defense in depth;
  requires a coordinated `server/` change).

## Testing & done

`bun test` + both typechecks stay green; `npm run dist` rebuilds the WASM; the
combined real-WebRTC E2E (with the parallel negotiation fix integrated) passes
byte-exact; then merge to master. Deploy still needs `npm run uploadcdn`.
