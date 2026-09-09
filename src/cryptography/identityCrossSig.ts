import { sign, verify } from "./ed25519";
import { IDENTITY_CROSS_SIGN_DOMAIN_BYTES } from "../utils/constants";

import type { LibCrypto } from "./libcrypto";

// D2=B / SECURITY-1: the Ed25519 identity key cross-signs the dedicated X25519
// identity pub so relying parties trust the X25519 key transitively from the Ed25519
// identity they already anchor on. The signature MUST be over a domain-separated
// transcript — never the bare X25519 pub — so it cannot be forged via the
// login-challenge signing oracle (`handleChallenge` signs a raw 32-byte
// server-supplied nonce with the same Ed25519 identity secret; the challenge is
// gated to exactly 32 bytes, the size of an X25519 pub). Prefixing
// IDENTITY_CROSS_SIGN_DOMAIN makes the cross-sig transcript disjoint from that
// challenge transcript, so no oracle output is ever a valid cross-signature.
// Uses the same explicit domain-separation convention as the v3 KDF labels.

/** The signed/verified transcript: IDENTITY_CROSS_SIGN_DOMAIN ‖ X25519_pub. */
export const identityCrossSignMessage = (x25519Pub: Uint8Array): Uint8Array => {
  const msg = new Uint8Array(
    IDENTITY_CROSS_SIGN_DOMAIN_BYTES.length + x25519Pub.length,
  );
  msg.set(IDENTITY_CROSS_SIGN_DOMAIN_BYTES, 0);
  msg.set(x25519Pub, IDENTITY_CROSS_SIGN_DOMAIN_BYTES.length);
  return msg;
};

/** Produce the cross-signature over (DOMAIN ‖ x25519Pub) with the Ed25519 secret. */
export const crossSignIdentityX25519 = async (
  x25519Pub: Uint8Array,
  ed25519Secret: Uint8Array,
  module?: LibCrypto,
): Promise<Uint8Array> =>
  sign(identityCrossSignMessage(x25519Pub), ed25519Secret, module);

/** Verify a cross-signature against the peer's pinned Ed25519 identity pub. */
export const verifyIdentityCrossSig = async (
  x25519Pub: Uint8Array,
  crossSig: Uint8Array,
  ed25519Pub: Uint8Array,
  module?: LibCrypto,
): Promise<boolean> =>
  verify(identityCrossSignMessage(x25519Pub), crossSig, ed25519Pub, module);
