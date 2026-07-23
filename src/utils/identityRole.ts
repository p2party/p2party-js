/**
 * Deterministic role for one stable Ed25519 identity edge.
 *
 * Lexical ordering is safe only for the one canonical wire representation:
 * exactly 32 bytes encoded as 64 lowercase hexadecimal characters. Rejecting
 * uppercase/invalid encodings is part of role agreement, not cosmetic input
 * cleanup — otherwise two peers can compare different strings for the same key
 * and both (or neither) decide to open the persistent `main` channel.
 */
export const CANONICAL_ED25519_IDENTITY_RE = /^[0-9a-f]{64}$/;

export const isCanonicalEd25519Identity = (
  publicKey: unknown,
): publicKey is string =>
  typeof publicKey === "string" &&
  CANONICAL_ED25519_IDENTITY_RE.test(publicKey);

export const assertCanonicalEd25519Identity = (
  publicKey: string,
  label = "Ed25519 identity",
): void => {
  if (!isCanonicalEd25519Identity(publicKey))
    throw new Error(`${label} must be 32-byte lowercase hexadecimal`);
};

export const isIdentityInitiator = (
  selfPublicKey: string,
  peerPublicKey: string,
): boolean => {
  assertCanonicalEd25519Identity(selfPublicKey, "Self Ed25519 identity");
  assertCanonicalEd25519Identity(peerPublicKey, "Peer Ed25519 identity");
  if (selfPublicKey === peerPublicKey)
    throw new Error("Cannot assign a protocol role to the same Ed25519 identity");
  return selfPublicKey < peerPublicKey;
};

/**
 * Only the non-opener may accept a remotely-created `main` DataChannel. The
 * designated opener receives `main`; accepting another inbound copy on that
 * side would allow duplicate handshakes to race for one room/peer edge.
 */
export const shouldAcceptIncomingMain = (
  selfPublicKey: string,
  peerPublicKey: string,
): boolean => !isIdentityInitiator(selfPublicKey, peerPublicKey);
