import { describe, expect, test } from "bun:test";

import { newKeyPair } from "../../src/cryptography/ed25519";
import { pairSemanticSlot } from "../../src/blindRendezvous/derivations";
import {
  createOperationValidationContext,
  operationPaddingFor,
  signOperation,
  validateOperation,
  validateOperationStructure,
} from "../../src/blindRendezvous/operation";
import {
  PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1,
  PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1,
  decodePairStepEnvelopeV1,
  encodePairStepEnvelopeV1,
  pairCiphertextAndTagTargetBytesV1,
  pairPlaintextTargetBytesV1,
} from "../../src/blindRendezvous/pairStepEnvelope";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";
import {
  OPERATION_PAYLOAD_CLASS_BYTES,
  PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1,
} from "../../src/blindRendezvous/schemas";

import type {
  PairBootstrapHeaderV1,
  PairStepEnvelopeV1,
} from "../../src/blindRendezvous/pairStepEnvelope";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const routingTag = new Uint8Array(32).fill(0x42);

const bootstrapHeader = (): PairBootstrapHeaderV1 => ({
  version: 1,
  suiteId: 1,
  hybridKemCiphertext: new Uint8Array(
    PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1,
  ).fill(0x31),
});

const validEnvelope = (
  operationPayloadClass: 0 | 1,
  bootstrap: boolean,
): PairStepEnvelopeV1 => ({
  version: 1,
  pairRoutingTag: routingTag,
  bootstrapHeader: bootstrap ? bootstrapHeader() : null,
  nonce: bootstrap ? null : new Uint8Array(24).fill(0x24),
  pairCiphertextAndTag: new Uint8Array(
    pairCiphertextAndTagTargetBytesV1(operationPayloadClass, bootstrap),
  ).fill(0x7c),
});

const capability = new Uint8Array(32).fill(0x53);
const roomPolicy = DEFAULT_BLIND_POLICY_V4_0;
const operationValidationContext = await createOperationValidationContext(
  capability,
  roomPolicy,
  700n,
);
const confirmation = operationValidationContext.roomContextConfirmation;
const author = await newKeyPair();
const fixedPairPayload = encodePairStepEnvelopeV1(validEnvelope(0, false), 0);
const pairSlot = await pairSemanticSlot(routingTag);
const unsignedPairOperation = {
  version: 1 as const,
  roomContextConfirmation: confirmation,
  logicalWindow: 700n,
  expiresAfterWindow: 710n,
  lifetime: "PAIR_CAUSAL" as const,
  authorEpochEd25519Key: author.publicKey,
  authorSequence: 0n,
  previousAuthorOperationId: null,
  kind: "PAIR_STEP" as const,
  semanticSlot: pairSlot,
  dependencies: [],
  operationPayloadClass: 0 as const,
  fixedPayload: fixedPairPayload,
  operationPadding: new Uint8Array(0),
};
describe("PairStepEnvelopeV1 derived class vectors", () => {
  test("derives framing overhead and all three suite-1 targets from the schema", () => {
    expect(PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1).toBe(1_161);
    expect(PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1).toBe(63);

    expect(pairCiphertextAndTagTargetBytesV1(0, true)).toBe(2_935);
    expect(pairPlaintextTargetBytesV1(0, true)).toBe(2_919);
    expect(pairCiphertextAndTagTargetBytesV1(0, false)).toBe(4_033);
    expect(pairPlaintextTargetBytesV1(0, false)).toBe(4_017);
    expect(pairCiphertextAndTagTargetBytesV1(1, false)).toBe(69_569);
    expect(pairPlaintextTargetBytesV1(1, false)).toBe(69_553);

    expect(() => pairCiphertextAndTagTargetBytesV1(1, true)).toThrow(
      "bootstrap header is permitted only in payload class 0",
    );
  });

  test("each permitted form round-trips and consumes its complete operation class", () => {
    const forms = [
      { operationPayloadClass: 0 as const, bootstrap: true },
      { operationPayloadClass: 0 as const, bootstrap: false },
      { operationPayloadClass: 1 as const, bootstrap: false },
    ];

    for (const form of forms) {
      const encoded = encodePairStepEnvelopeV1(
        validEnvelope(form.operationPayloadClass, form.bootstrap),
        form.operationPayloadClass,
      );
      expect(encoded.length).toBe(
        OPERATION_PAYLOAD_CLASS_BYTES[form.operationPayloadClass],
      );
      expect(
        hex(
          encodePairStepEnvelopeV1(
            decodePairStepEnvelopeV1(encoded, form.operationPayloadClass),
            form.operationPayloadClass,
          ),
        ),
      ).toBe(hex(encoded));
    }
  });
});

describe("PairStepEnvelopeV1 rejects alternate framing", () => {
  test("requires the one legal header/nonce state", () => {
    const established = validEnvelope(0, false);
    expect(() =>
      encodePairStepEnvelopeV1({ ...established, nonce: null }, 0),
    ).toThrow("exactly one of bootstrapHeader and nonce");
    expect(() =>
      encodePairStepEnvelopeV1(
        { ...established, bootstrapHeader: bootstrapHeader() },
        0,
      ),
    ).toThrow("exactly one of bootstrapHeader and nonce");
  });

  test("rejects class-1 bootstrap and every short or long ciphertext", () => {
    const classZeroBootstrap = validEnvelope(0, true);
    expect(() => encodePairStepEnvelopeV1(classZeroBootstrap, 1)).toThrow(
      "bootstrap header is permitted only in payload class 0",
    );

    for (const delta of [-1, 1]) {
      const established = validEnvelope(0, false);
      expect(() =>
        encodePairStepEnvelopeV1(
          {
            ...established,
            pairCiphertextAndTag: new Uint8Array(
              established.pairCiphertextAndTag.length + delta,
            ),
          },
          0,
        ),
      ).toThrow("pairCiphertextAndTag must be exactly 4033 bytes");
    }
  });

  test("rejects unsupported versions, suites, and KEM widths", () => {
    const bootstrap = validEnvelope(0, true);
    expect(() =>
      encodePairStepEnvelopeV1(
        { ...bootstrap, version: 2 } as unknown as PairStepEnvelopeV1,
        0,
      ),
    ).toThrow("unsupported envelope version");
    expect(() =>
      encodePairStepEnvelopeV1(
        {
          ...bootstrap,
          bootstrapHeader: {
            ...bootstrapHeader(),
            suiteId: 2,
          },
        } as unknown as PairStepEnvelopeV1,
        0,
      ),
    ).toThrow("unsupported bootstrap suite");
    expect(() =>
      encodePairStepEnvelopeV1(
        {
          ...bootstrap,
          bootstrapHeader: {
            ...bootstrapHeader(),
            hybridKemCiphertext: new Uint8Array(
              PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1 - 1,
            ),
          },
        },
        0,
      ),
    ).toThrow("must be exactly 1120 bytes");
  });

  test("strict decoding rejects a noncanonical optional tag", () => {
    const encoded = encodePairStepEnvelopeV1(validEnvelope(0, false), 0);
    const malformed = Uint8Array.from(encoded);
    // version (1) || pairRoutingTag (32) || bootstrapHeader presence tag
    malformed[33] = 0x02;
    expect(() => decodePairStepEnvelopeV1(malformed, 0)).toThrow(
      "presence tag must be exactly 0x00 or 0x01",
    );
  });
});

describe("PAIR_STEP outer operation validation", () => {
  test("accepts a signed canonical envelope and recomputed routing-tag slot", async () => {
    const operation = await signOperation(
      unsignedPairOperation,
      author.secretKey,
    );
    await expect(
      validateOperation(operation, operationValidationContext),
    ).resolves.toBeUndefined();
  });

  test("rejects a separately signed but incorrect pair semantic slot", async () => {
    const operation = await signOperation(
      {
        ...unsignedPairOperation,
        semanticSlot: new Uint8Array(32).fill(0xff),
      },
      author.secretKey,
    );
    await expect(
      validateOperation(operation, operationValidationContext),
    ).rejects.toThrow("PAIR_STEP semanticSlot does not match pairRoutingTag");
  });

  test("requires empty operation padding and canonical nested framing", async () => {
    const padded = await signOperation(
      {
        ...unsignedPairOperation,
        fixedPayload: fixedPairPayload.subarray(0, fixedPairPayload.length - 1),
        operationPadding: operationPaddingFor(0, fixedPairPayload.length - 1),
      },
      author.secretKey,
    );
    expect(() =>
      validateOperationStructure(padded, operationValidationContext),
    ).toThrow("PAIR_STEP operationPadding must be empty");

    const arbitraryPayload = await signOperation(
      {
        ...unsignedPairOperation,
        fixedPayload: new Uint8Array(OPERATION_PAYLOAD_CLASS_BYTES[0]),
      },
      author.secretKey,
    );
    expect(() =>
      validateOperationStructure(arbitraryPayload, operationValidationContext),
    ).toThrow("PAIR_STEP payload is invalid");
  });
});
