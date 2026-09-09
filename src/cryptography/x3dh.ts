import { x25519Dh } from "./x25519";
import { hkdfExtract, hkdfExpand } from "./hkdf";

import type { LibCrypto } from "./libcrypto";

// Internal HKDF params for the no-PIN handshake (both peers are pure TS; not on
// the wire, so no C SSOT needed).
const THREE_DH_INFO = new TextEncoder().encode("p2party-interactive-3dh-v2");
const THREE_DH_SALT = new Uint8Array(64); // HashLen zeros

/**
 * No-PIN identity-mixed ephemeral DH. Mixes
 *   DH(IK_a, EK_b) || DH(EK_a, IK_b) || DH(EK_a, EK_b)
 * (initiator orientation) then HKDF-SHA512 to a 32-byte root seed. The responder
 * passes amInitiator=false; the three DH calls are re-ordered so both sides
 * concatenate the identical shared values.
 */
export const deriveInteractive3dhSecret = (
  idSelfSec: Uint8Array,
  idPeerPub: Uint8Array,
  ephSelfSec: Uint8Array,
  ephPeerPub: Uint8Array,
  amInitiator: boolean,
  module: LibCrypto,
): Uint8Array => {
  let dh1: Uint8Array;
  let dh2: Uint8Array;
  const dh3 = x25519Dh(ephSelfSec, ephPeerPub, module); // DH(EK_a, EK_b) — symmetric

  if (amInitiator) {
    dh1 = x25519Dh(idSelfSec, ephPeerPub, module); // DH(IK_a, EK_b)
    dh2 = x25519Dh(ephSelfSec, idPeerPub, module); // DH(EK_a, IK_b)
  } else {
    dh1 = x25519Dh(ephSelfSec, idPeerPub, module); // == DH(IK_a, EK_b)
    dh2 = x25519Dh(idSelfSec, ephPeerPub, module); // == DH(EK_a, IK_b)
  }

  const ikm = new Uint8Array(96);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);

  const prk = hkdfExtract(THREE_DH_SALT, ikm, module);
  const secret = hkdfExpand(prk, THREE_DH_INFO, 32, module);

  ikm.fill(0);
  dh1.fill(0);
  dh2.fill(0);
  dh3.fill(0);
  prk.fill(0);

  return secret;
};
