import { describe, expect, test } from "bun:test";

import {
  getPairBootstrapSuite,
  PAIR_BOOTSTRAP_SUITE_ID_V1,
  PAIR_BOOTSTRAP_SUITES_BY_ID,
  PAIR_BOOTSTRAP_SUITE_V1,
} from "../../src/blindRendezvous/pairBootstrapSuite";
import { PAIR_AEAD_TAG_BYTES_V1 } from "../../src/blindRendezvous/pairStepEnvelope";
import {
  PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1,
  RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1,
} from "../../src/blindRendezvous/schemas";

describe("pair bootstrap suite registry", () => {
  test("maps suite ID 1 to the complete frozen cryptographic profile", () => {
    expect(PAIR_BOOTSTRAP_SUITE_ID_V1).toBe(1);
    expect(PAIR_BOOTSTRAP_SUITES_BY_ID[1]).toBe(PAIR_BOOTSTRAP_SUITE_V1);
    expect(getPairBootstrapSuite(1)).toBe(PAIR_BOOTSTRAP_SUITE_V1);
    expect(PAIR_BOOTSTRAP_SUITE_V1).toEqual({
      id: 1,
      hybridKem: {
        standardName: "MLKEM768-X25519",
        specification: "draft-irtf-cfrg-concrete-hybrid-kems-04",
        seedBytes: 32,
        publicKeyBytes: 1_216,
        secretKeyBytes: 32,
        ciphertextBytes: 1_120,
        sharedSecretBytes: 32,
        randomnessBytes: 64,
      },
      hpke: {
        specification: {
          kem: "draft-ietf-hpke-pq-05",
          kemKeyDerivation: "draft-ietf-hpke-hpke-03",
          keySchedule: "RFC 9180",
        },
        kemId: 0x647a,
        kdfId: 0x0001,
        aeadId: 0x0003,
        publicKeyBytes: 1_216,
        secretKeyBytes: 32,
        encapsulatedKeyBytes: 1_120,
        sharedSecretBytes: 32,
        keyBytes: 32,
        nonceBytes: 12,
        tagBytes: 16,
        pskBytes: 32,
        pskIdBytes: 32,
      },
      establishedPairAead: {
        standardName: "XChaCha20-Poly1305-IETF",
        kdfId: 0x0001,
        keyBytes: 32,
        nonceBytes: 24,
        tagBytes: 16,
      },
      routingTagBytes: 32,
    });
    expect(Object.isFrozen(PAIR_BOOTSTRAP_SUITE_V1)).toBe(true);
    expect(Object.isFrozen(PAIR_BOOTSTRAP_SUITE_V1.establishedPairAead)).toBe(
      true,
    );
  });

  test("is the geometry source used by schemas and envelope framing", () => {
    expect(PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1).toBe(
      PAIR_BOOTSTRAP_SUITE_V1.hybridKem.ciphertextBytes,
    );
    expect(RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1).toBe(
      PAIR_BOOTSTRAP_SUITE_V1.hybridKem.publicKeyBytes,
    );
    expect(PAIR_AEAD_TAG_BYTES_V1).toBe(
      PAIR_BOOTSTRAP_SUITE_V1.establishedPairAead.tagBytes,
    );
    expect(() => getPairBootstrapSuite(2)).toThrow(
      "unsupported pair bootstrap suite: 2",
    );
  });
});
