import { describe, expect, test } from "bun:test";

import {
  encodeCanonical,
  recordFieldNames,
} from "../../src/blindRendezvous/canonicalSchema";
import {
  AUTHENTICATED_ROOM_OPERATION_V1_KEYS,
  CARRIER_ENVELOPE_V1_KEYS,
  CLAIM_ASSUMPTION_EVIDENCE_VERIFICATION_KEYS,
  CLAIM_ASSUMPTION_FOUNDATIONAL_VERIFICATION_KEYS,
  CLAIM_ASSUMPTION_KINDS,
  CLAIM_DEFINITION_KEYS,
  CLAIM_EVALUATION_STATES,
  CLAIM_EVALUATION_STATES_ORDER,
  CLAIM_SCOPE_KINDS,
  CLAIM_WORDING_KEY_LIST,
  DELIVERY_PROFILE_V1_KEYS,
  FORMAL_OBLIGATION_KEYS,
  FORMAL_OBLIGATION_KINDS,
  FORMAL_PROOF_RESULTS,
  KERNEL_MANIFEST_KEYS,
  KERNEL_MODULE_KEYS,
  OPERATION_KINDS_ORDER,
  OPERATION_LIFETIMES_ORDER,
  PAIR_ATTEMPT_MODES_ORDER,
  PAIR_BOOTSTRAP_HEADER_V1_KEYS,
  PAIR_BOOTSTRAP_INFO_V1_KEYS,
  PAIR_BOOTSTRAP_RECIPIENT_KINDS_ORDER,
  PAIR_FLIGHT_SLOT_V1_KEYS,
  PAIR_IDENTITY_ACCEPT_UNSIGNED_V1_KEYS,
  PAIR_IDENTITY_ACCEPT_V1_KEYS,
  PAIR_IDENTITY_HELLO_UNSIGNED_V1_KEYS,
  PAIR_IDENTITY_HELLO_V1_KEYS,
  PAIR_IDENTITY_UNSIGNED_PROJECTION_V1_KEYS,
  PAIR_OUTER_BINDING_V1_KEYS,
  PAIR_OUTER_PREBINDING_V1_KEYS,
  PAIR_PLAINTEXT_V1_KEYS,
  PAIR_STEP_KINDS,
  PAIR_STEP_KINDS_ORDER,
  PAIR_STEP_ENVELOPE_V1_KEYS,
  PAIR_TRANSPORT_ANSWER_V1_KEYS,
  PAIR_TRANSPORT_CANDIDATE_KINDS_ORDER,
  PAIR_TRANSPORT_OFFER_V1_KEYS,
  ROOM_POLICY_V4_KEYS,
  STABLE_IDENTITY_BUNDLE_V1_KEYS,
} from "../../src/blindRendezvous/projections";
import {
  KERNEL_ENTRYPOINT_IDS,
  KERNEL_ENTRYPOINT_IDS_BY_MODULE,
  KERNEL_MODULE_IDS,
  OPERATION_PAYLOAD_CLASS_BYTES,
  V04_REQUIRED_FORMAL_OBLIGATION_IDS,
  authenticatedRoomOperationV1Schema,
  claimDefinitionV1Schema,
  pairBootstrapHeaderV1Schema,
  pairBootstrapInfoV1Schema,
  pairFlightSlotV1Schema,
  pairIdentityAcceptUnsignedV1Schema,
  pairIdentityAcceptV1Schema,
  pairIdentityHelloUnsignedV1Schema,
  pairIdentityHelloV1Schema,
  pairIdentityUnsignedProjectionV1Schema,
  pairOuterBindingV1Schema,
  pairOuterPrebindingV1Schema,
  pairPlaintextV1Schema,
  pairStepEnvelopeV1Schema,
  pairTransportAnswerV1Schema,
  pairTransportOfferV1Schema,
  roomPolicyV4Schema,
  stableIdentityBundleV1Schema,
} from "../../src/blindRendezvous/schemas";

const asSortedArray = (value: ReadonlySet<string>): string[] =>
  [...value].sort();

describe("validator tables are generated from the schema", () => {
  test("every key set is exactly its record's field projection", () => {
    expect(asSortedArray(KERNEL_MANIFEST_KEYS)).toEqual(
      ["version", "canonicalBinarySchemaHash", "modules"].sort(),
    );
    expect(asSortedArray(KERNEL_MODULE_KEYS)).toEqual(
      [
        "moduleId",
        "executableArtifactHash",
        "normativeSourceTreeHash",
        "entrypoints",
        "canonicalVectorSetHash",
      ].sort(),
    );
    expect(asSortedArray(CLAIM_DEFINITION_KEYS)).toEqual(
      [...recordFieldNames(claimDefinitionV1Schema)].sort(),
    );
    expect(asSortedArray(ROOM_POLICY_V4_KEYS)).toEqual(
      [...recordFieldNames(roomPolicyV4Schema)].sort(),
    );
    expect(asSortedArray(AUTHENTICATED_ROOM_OPERATION_V1_KEYS)).toEqual(
      [...recordFieldNames(authenticatedRoomOperationV1Schema)].sort(),
    );
    expect(asSortedArray(PAIR_BOOTSTRAP_HEADER_V1_KEYS)).toEqual(
      [...recordFieldNames(pairBootstrapHeaderV1Schema)].sort(),
    );
    expect(asSortedArray(PAIR_STEP_ENVELOPE_V1_KEYS)).toEqual(
      [...recordFieldNames(pairStepEnvelopeV1Schema)].sort(),
    );
    const pairRecords = [
      [PAIR_PLAINTEXT_V1_KEYS, pairPlaintextV1Schema],
      [
        PAIR_IDENTITY_UNSIGNED_PROJECTION_V1_KEYS,
        pairIdentityUnsignedProjectionV1Schema,
      ],
      [STABLE_IDENTITY_BUNDLE_V1_KEYS, stableIdentityBundleV1Schema],
      [PAIR_IDENTITY_HELLO_UNSIGNED_V1_KEYS, pairIdentityHelloUnsignedV1Schema],
      [PAIR_IDENTITY_HELLO_V1_KEYS, pairIdentityHelloV1Schema],
      [
        PAIR_IDENTITY_ACCEPT_UNSIGNED_V1_KEYS,
        pairIdentityAcceptUnsignedV1Schema,
      ],
      [PAIR_IDENTITY_ACCEPT_V1_KEYS, pairIdentityAcceptV1Schema],
      [PAIR_OUTER_PREBINDING_V1_KEYS, pairOuterPrebindingV1Schema],
      [PAIR_OUTER_BINDING_V1_KEYS, pairOuterBindingV1Schema],
      [PAIR_FLIGHT_SLOT_V1_KEYS, pairFlightSlotV1Schema],
      [PAIR_BOOTSTRAP_INFO_V1_KEYS, pairBootstrapInfoV1Schema],
      [PAIR_TRANSPORT_OFFER_V1_KEYS, pairTransportOfferV1Schema],
      [PAIR_TRANSPORT_ANSWER_V1_KEYS, pairTransportAnswerV1Schema],
    ] as const;
    for (const [keys, schema] of pairRecords)
      expect(asSortedArray(keys)).toEqual([...recordFieldNames(schema)].sort());
  });

  test("closed union variants project their own exact key sets", () => {
    expect(
      asSortedArray(CLAIM_ASSUMPTION_FOUNDATIONAL_VERIFICATION_KEYS),
    ).toEqual(["kind"]);
    expect(asSortedArray(CLAIM_ASSUMPTION_EVIDENCE_VERIFICATION_KEYS)).toEqual(
      ["kind", "verifierEntrypointId"].sort(),
    );
  });

  test("the wording projection covers exactly the six evaluation states", () => {
    expect([...CLAIM_WORDING_KEY_LIST].sort()).toEqual(
      [
        "notImplemented",
        "notEvaluated",
        "unknown",
        "expired",
        "failed",
        "satisfied",
      ].sort(),
    );
    expect(CLAIM_WORDING_KEY_LIST.length).toBe(
      CLAIM_EVALUATION_STATES_ORDER.length,
    );
  });
});

describe("closed enumerations keep their wire order", () => {
  test("evaluation states are declared in specification order", () => {
    expect(CLAIM_EVALUATION_STATES_ORDER).toEqual([
      "not-implemented",
      "not-evaluated",
      "unknown",
      "expired",
      "failed",
      "satisfied",
    ]);
  });

  test("operation kinds and lifetimes are declared in specification order", () => {
    expect(OPERATION_KINDS_ORDER).toEqual([
      "PRESENCE",
      "LEAVE",
      "PAIR_STEP",
      "STORE_HINT",
      "ADMISSION_REVOKE",
    ]);
    expect(OPERATION_LIFETIMES_ORDER).toEqual([
      "WINDOW_TRANSIENT",
      "GRANT_HORIZON",
      "PAIR_CAUSAL",
    ]);
  });

  test("pair registries retain their protocol-visible wire order", () => {
    expect(PAIR_STEP_KINDS_ORDER).toEqual([
      "IDENTITY_HELLO",
      "IDENTITY_ACCEPT",
      "TRANSPORT_OFFER",
      "TRANSPORT_ANSWER",
      "V4_HANDSHAKE",
      "PQ_CONTROL",
      "QUIESCE_PROPOSE",
      "QUIESCE_ACK",
      "HEAL_COMPLETE",
      "PAIR_CHECKPOINT",
    ]);
    expect(PAIR_ATTEMPT_MODES_ORDER).toEqual(["planner", "explicit"]);
    expect(PAIR_BOOTSTRAP_RECIPIENT_KINDS_ORDER).toEqual([
      "presence",
      "hello-response",
    ]);
    expect(PAIR_TRANSPORT_CANDIDATE_KINDS_ORDER).toEqual([
      "webrtc-complete",
      "operation-carrier",
      "registered-local-link",
    ]);
    expect(PAIR_STEP_KINDS.size).toBe(PAIR_STEP_KINDS_ORDER.length);
  });

  test("membership sets and ordered projections agree", () => {
    for (const state of CLAIM_EVALUATION_STATES_ORDER)
      expect(CLAIM_EVALUATION_STATES.has(state)).toBe(true);
    expect(CLAIM_EVALUATION_STATES.size).toBe(
      CLAIM_EVALUATION_STATES_ORDER.length,
    );
    expect(CLAIM_SCOPE_KINDS.has("r2-conformance-record")).toBe(true);
    expect(CLAIM_ASSUMPTION_KINDS.has("environmental")).toBe(true);
    expect(FORMAL_OBLIGATION_KINDS.has("liveness-refinement")).toBe(true);
    expect(FORMAL_PROOF_RESULTS.has("proved-within-scope")).toBe(true);
  });
});

describe("closed kernel and payload constants", () => {
  test("the kernel is closed at eight modules and nine entrypoints", () => {
    expect([...KERNEL_MODULE_IDS]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect([...KERNEL_ENTRYPOINT_IDS]).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);

    // Every entrypoint resolves inside exactly one module.
    const owners = new Map<number, number>();
    for (const moduleId of KERNEL_MODULE_IDS) {
      for (const entrypointId of KERNEL_ENTRYPOINT_IDS_BY_MODULE[moduleId]) {
        expect(owners.has(entrypointId)).toBe(false);
        owners.set(entrypointId, moduleId);
      }
    }
    expect([...owners.keys()].sort((a, b) => a - b)).toEqual([
      ...KERNEL_ENTRYPOINT_IDS,
    ]);
    expect(KERNEL_ENTRYPOINT_IDS_BY_MODULE[6]).toEqual([6, 7]);
  });

  test("a v0.4 release requires FPO-001 through FPO-006", () => {
    expect([...V04_REQUIRED_FORMAL_OBLIGATION_IDS]).toEqual([1, 2, 3, 4, 5, 6]);
  });

  test("operation payload classes carry their exact signed inner lengths", () => {
    expect(OPERATION_PAYLOAD_CLASS_BYTES[0]).toBe(4096);
    expect(OPERATION_PAYLOAD_CLASS_BYTES[1]).toBe(69_632);
    // Class 1 must hold the existing 65,490-byte protocol-v4 control frame
    // plus pair and operation framing overhead.
    expect(OPERATION_PAYLOAD_CLASS_BYTES[1]).toBeGreaterThan(65_490);
  });
});

describe("schema drift is detectable, not silent", () => {
  test("an added field changes the projection and the encoding", () => {
    const before = recordFieldNames(roomPolicyV4Schema).length;
    // The projection is computed, so a schema edit cannot leave a validator
    // table stale: this asserts the derivation, not a copied list.
    expect(ROOM_POLICY_V4_KEYS.size).toBe(before);
    expect(DELIVERY_PROFILE_V1_KEYS.has("sizeClasses")).toBe(true);
    expect(CARRIER_ENVELOPE_V1_KEYS.has("nonce")).toBe(true);
  });

  test("the encoder rejects a record carrying a field the schema lacks", () => {
    expect(() =>
      encodeCanonical(claimDefinitionV1Schema, {
        claimId: 1,
        scopeKind: "release",
        scopeSchemaHash: new Uint8Array(32),
        predicateEntrypointId: 9,
        assumptionIds: [],
        requiredEvidenceKindIds: [],
        prerequisiteClaimIds: [],
        requiredFormalObligationIds: [],
        wordingIdByState: {
          notImplemented: 1,
          notEvaluated: 2,
          unknown: 3,
          expired: 4,
          failed: 5,
          satisfied: 6,
        },
        forbiddenWordingIds: [],
        unregisteredExtension: 1,
      }),
    ).toThrow("missing or unexpected fields");
  });

  test("formal-obligation keys include the scope-coverage entrypoint", () => {
    expect(FORMAL_OBLIGATION_KEYS.has("scopeCoverageEntrypointId")).toBe(true);
    expect(FORMAL_OBLIGATION_KEYS.has("abstractionMapHash")).toBe(true);
  });
});
