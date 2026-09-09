import {
  HPKE_HKDF_SHA256_KDF_ID,
  HPKE_MLKEM768_X25519_SUITE,
} from "../cryptography/hpkeSuite";
import { MLKEM768_X25519_SUITE } from "../cryptography/hybridKemSuite";
import {
  crypto_aead_xchacha20poly1305_ietf_ABYTES,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
} from "../cryptography/interfaces";

/**
 * Constants-only registry for the complete pair-bootstrap suite selected by
 * RoomPolicyV4 and encoded in PairBootstrapHeaderV1.
 *
 * This is the ID-to-cryptography SSOT. Schema geometry, policy validation,
 * HPKE bootstrap, and established pair flights must project from this object
 * rather than independently assigning meaning to suite ID 1.
 */
export const PAIR_BOOTSTRAP_SUITE_ID_V1 = 1;

export const PAIR_BOOTSTRAP_SUITE_V1 = Object.freeze({
  id: PAIR_BOOTSTRAP_SUITE_ID_V1,
  hybridKem: MLKEM768_X25519_SUITE,
  hpke: HPKE_MLKEM768_X25519_SUITE,
  establishedPairAead: Object.freeze({
    standardName: "XChaCha20-Poly1305-IETF",
    kdfId: HPKE_HKDF_SHA256_KDF_ID,
    keyBytes: crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    nonceBytes: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    tagBytes: crypto_aead_xchacha20poly1305_ietf_ABYTES,
  }),
  routingTagBytes: 32,
} as const);

export const PAIR_BOOTSTRAP_SUITES_BY_ID = Object.freeze({
  [PAIR_BOOTSTRAP_SUITE_ID_V1]: PAIR_BOOTSTRAP_SUITE_V1,
} as const);

export type PairBootstrapSuiteIdV1 = keyof typeof PAIR_BOOTSTRAP_SUITES_BY_ID;

export const getPairBootstrapSuite = (
  suiteId: number,
): typeof PAIR_BOOTSTRAP_SUITE_V1 => {
  const suite = (
    PAIR_BOOTSTRAP_SUITES_BY_ID as Partial<
      Record<number, typeof PAIR_BOOTSTRAP_SUITE_V1>
    >
  )[suiteId];
  if (suite === undefined)
    throw new RangeError(
      `unsupported pair bootstrap suite: ${String(suiteId)}`,
    );
  return suite;
};
