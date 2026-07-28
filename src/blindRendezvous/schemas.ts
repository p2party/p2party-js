/**
 * Canonical descriptors for the blind-rendezvous wire objects.
 *
 * These descriptors are the schema SSOT named in Section 1.4: they own field
 * order, integer widths, enum bytes, collection ordering, and bounds. Every
 * other module derives its encoder, decoder, key table, and bound check from
 * here rather than restating them.
 *
 * Field order below follows the specification's declaration order in Sections
 * 4.0 through 4.5. A TypeScript interface may list the same fields in a
 * different order for readability; interface order is not wire order.
 *
 * Status: PROPOSED, NOT FROZEN. Integer widths are this artifact's proposal
 * for the Phase-0 freeze, not published v0.4 release bytes.
 */

import {
  array,
  bool,
  bytes32,
  bytes64,
  enumOf,
  fixedBytes,
  optional,
  record,
  recordFields,
  text,
  u16,
  u32,
  u64,
  u8,
  union,
  varBytes,
} from "./canonicalSchema";
import { MAX_HANDSHAKE_PAYLOAD_LENGTH } from "../handlers/handshakeFrame";
import { WIRE_CHUNK_FRAME_LEN } from "../utils/constants";
import { PAIR_BOOTSTRAP_SUITE_V1 } from "./pairBootstrapSuite";

import type { FieldDescriptor, TypeDescriptor } from "./canonicalSchema";

/* ------------------------------------------------------------------ *
 * Shared bounds
 * ------------------------------------------------------------------ */

/** Section 4.4 operation payload classes: exact signed inner byte counts. */
export const OPERATION_PAYLOAD_CLASS_BYTES: Readonly<Record<0 | 1, number>> =
  Object.freeze({ 0: 4096, 1: 69632 });

export const MAX_OPERATION_PAYLOAD_BYTES = OPERATION_PAYLOAD_CLASS_BYTES[1];

/** Absolute profile bound for one carried signed room operation. */
export const MAX_CARRIED_ROOM_OPERATION_BYTES_V1 = 1 << 20;

/** Section 4.11 suite-1 bootstrap KEM ciphertext width. */
export const PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1 =
  PAIR_BOOTSTRAP_SUITE_V1.hybridKem.ciphertextBytes;

/** Sections 4.9/4.11 suite-1 ML-KEM-768 + X25519 public-key width. */
export const RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1 =
  PAIR_BOOTSTRAP_SUITE_V1.hybridKem.publicKeyBytes;

/** Section 4.11: every currently defined pair step has zero or one dependency. */
export const MAX_PAIR_DEPENDENCIES_V1 = 1;

/**
 * The largest unique pair-padding suffix.
 *
 * An established class-1 plaintext is minimal only when its empty-padding
 * encoding is at least 4,018 bytes. Its target is 69,553 bytes, so the largest
 * possible canonical suffix is 69,553 - 4,018 = 65,535 bytes.
 */
export const MAX_PAIR_PADDING_BYTES_V1 = 0xffff;

/** Section 4.12 permits one through three transport candidates. */
export const MAX_PAIR_TRANSPORT_CANDIDATES_V1 = 3;

export const MAX_PAIR_WEBRTC_SDP_BYTES_V1 = 32_768;
export const MAX_PAIR_LOCAL_CANDIDATE_BYTES_V1 = 2_048;

/** Section 4.2 bounds one encrypted store hint to 255 exact routes. */
export const MAX_STORE_HINT_ROUTES_V1 = 0xff;

/** Section 4.8 bounds each frontend-owned canonical identity set. */
export const MAX_FRONTEND_ROOM_CONTROL_SET_ENTRIES_V1 = 0xffff;

/**
 * Leaves one 16-bit collection slot for the canonical quota+1 physical proof.
 */
export const MAX_OPERATIONS_PER_AUTHOR_WINDOW_V1 = 0xfffe;

/** Section 4.0 closes the kernel at 8 modules and 9 entrypoints. */
export const KERNEL_MODULE_IDS = [1, 2, 3, 4, 5, 6, 7, 8] as const;
export const KERNEL_ENTRYPOINT_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const;

/**
 * Section 4.0: modules 1..5 own entrypoints 1..5; module 6 owns the delivery
 * scheduler (6) and `R2Conforms` (7); module 7 owns the eventual pair-control
 * transition (8); module 8 owns claim evaluation (9).
 */
export const KERNEL_ENTRYPOINT_IDS_BY_MODULE: Readonly<
  Record<(typeof KERNEL_MODULE_IDS)[number], readonly number[]>
> = Object.freeze({
  1: [1],
  2: [2],
  3: [3],
  4: [4],
  5: [5],
  6: [6, 7],
  7: [8],
  8: [9],
});

/** Section 4.0: a v0.4 release must carry FPO-001 through FPO-006. */
export const V04_REQUIRED_FORMAL_OBLIGATION_IDS = [1, 2, 3, 4, 5, 6] as const;

const MAX_REGISTRY_ENTRIES = 0xffff;

/* ------------------------------------------------------------------ *
 * Section 4.1 — room policy and delivery profile
 * ------------------------------------------------------------------ */

export const roomProtocolLimitsV1Schema = record("RoomProtocolLimitsV1", [
  { name: "logicalWindowMs", type: u64 },
  { name: "maxClockSkewWindows", type: u32 },
  { name: "operationRetentionWindows", type: u32 },
  { name: "pairControlRetentionWindows", type: u32 },
  { name: "receiverKeyOverlapWindows", type: u32 },
  { name: "maxFutureLogicalWindows", type: u32 },
  { name: "maxDependenciesPerOperation", type: u16 },
  { name: "maxOperationsPerAuthorWindow", type: u16 },
]);

export const admissionFloorV4Schema = union("AdmissionFloorV4", "mode", [
  {
    tag: "capability",
    type: record("AdmissionFloorCapability", [
      {
        name: "mode",
        type: enumOf("AdmissionFloorCapabilityMode", ["capability"]),
      },
    ]),
  },
  {
    tag: "authority-grant",
    type: record("AdmissionFloorAuthorityGrant", [
      {
        name: "mode",
        type: enumOf("AdmissionFloorAuthorityGrantMode", ["authority-grant"]),
      },
      { name: "authorityEd25519PublicKey", type: bytes32 },
      { name: "maxAuthorityCredentialLifetimeWindows", type: u32 },
    ]),
  },
]);

export const roomPolicyV4Schema = record("RoomPolicyV4", [
  { name: "version", type: u8 },
  // Exact encodeRoomPolicyV1(...) bytes; the v1 codec remains their SSOT.
  { name: "sessionPolicyV1", type: bytes32 },
  { name: "roomCryptoSuite", type: u8 },
  { name: "operationCodec", type: u8 },
  { name: "pairBootstrapSuite", type: u8 },
  { name: "protocolLimits", type: roomProtocolLimitsV1Schema },
  { name: "admissionFloor", type: admissionFloorV4Schema },
  { name: "maxRoomMembers", type: u16 },
]);

export const appendScheduleRoleV1Schema = enumOf("AppendScheduleRoleV1", [
  "safety-control",
  "identity-bootstrap",
  "state-replication",
]);

export const appendScheduleEntryV1Schema = record("AppendScheduleEntryV1", [
  { name: "offsetMs", type: u64 },
  { name: "role", type: appendScheduleRoleV1Schema },
]);

export const deliverySizeClassV1Schema = record("DeliverySizeClassV1", [
  { name: "id", type: u8 },
  { name: "fixedCarrierObjectBytes", type: u32 },
  { name: "operationPayloadClass", type: u8 },
  { name: "appendSchedule", type: array(appendScheduleEntryV1Schema, 0xffff) },
  { name: "publicChunksPerWindow", type: u32 },
]);

export const deliveryProfileV1Schema = record("DeliveryProfileV1", [
  { name: "version", type: u8 },
  { name: "carrierEnvelopeCodec", type: u8 },
  { name: "publicStoreProtocol", type: u8 },
  { name: "carrierAeadSuite", type: u8 },
  { name: "admissionScheme", type: u8 },
  { name: "deliveryWindowMs", type: u64 },
  { name: "carrierRetentionWindows", type: u32 },
  { name: "maxFutureIngressWindows", type: u32 },
  { name: "roomSlotsPerClient", type: u16 },
  { name: "cohortAllocationsPerWindow", type: u32 },
  { name: "publicChunkObjectCount", type: u32 },
  { name: "maxScheduleSkewMs", type: u64 },
  { name: "tokenIssueOffsetMs", type: u64 },
  { name: "tokenIssueResponseBudgetMs", type: u64 },
  { name: "allocationRequestOffsetMs", type: u64 },
  { name: "allocationResponseBudgetMs", type: u64 },
  { name: "chunkFinalizationOffsetMs", type: u64 },
  // Section 4.1 pins this to the literal 1; validation rejects any other value.
  { name: "publicReadLagWindows", type: u8 },
  { name: "publicReadOffsetMs", type: u64 },
  { name: "maxConsecutiveMissedAppendOpportunities", type: u16 },
  { name: "sizeClasses", type: array(deliverySizeClassV1Schema, 0xff) },
  { name: "minMeasuredSharedCohort", type: u32 },
  { name: "maxAssuranceEvidenceAgeMs", type: u64 },
]);

/* ------------------------------------------------------------------ *
 * Section 4.4 — canonical authenticated room operation
 * ------------------------------------------------------------------ */

export const operationKindV1Schema = enumOf("OperationKindV1", [
  "PRESENCE",
  "LEAVE",
  "PAIR_STEP",
  "STORE_HINT",
  "ADMISSION_REVOKE",
]);

export const operationLifetimeV1Schema = enumOf("OperationLifetimeV1", [
  "WINDOW_TRANSIENT",
  "GRANT_HORIZON",
  "PAIR_CAUSAL",
]);

/**
 * Every field of `AuthenticatedRoomOperationV1` preceding `authorSignature`.
 * The signature transcript is exactly this prefix, so it is declared once and
 * reused rather than restated in the signed and unsigned forms.
 */
const authenticatedRoomOperationFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "roomContextConfirmation", type: bytes32 },
  { name: "logicalWindow", type: u64 },
  { name: "expiresAfterWindow", type: u64 },
  { name: "lifetime", type: operationLifetimeV1Schema },
  { name: "authorEpochEd25519Key", type: bytes32 },
  { name: "authorSequence", type: u64 },
  { name: "previousAuthorOperationId", type: optional(bytes32) },
  { name: "kind", type: operationKindV1Schema },
  { name: "semanticSlot", type: bytes32 },
  { name: "dependencies", type: array(bytes32, 0xffff) },
  { name: "operationPayloadClass", type: u8 },
  { name: "fixedPayload", type: varBytes(MAX_OPERATION_PAYLOAD_BYTES) },
  { name: "operationPadding", type: varBytes(MAX_OPERATION_PAYLOAD_BYTES) },
];

export const authenticatedRoomOperationUnsignedV1Schema = record(
  "AuthenticatedRoomOperationUnsignedV1",
  authenticatedRoomOperationFields,
);

export const authenticatedRoomOperationV1Schema = record(
  "AuthenticatedRoomOperationV1",
  [
    ...authenticatedRoomOperationFields,
    { name: "authorSignature", type: bytes64 },
  ],
);

/* ------------------------------------------------------------------ *
 * Section 4.11 — room-visible pair envelope
 * ------------------------------------------------------------------ */

export const pairBootstrapHeaderV1Schema = record("PairBootstrapHeaderV1", [
  { name: "version", type: u8 },
  { name: "suiteId", type: u8 },
  {
    name: "hybridKemCiphertext",
    type: fixedBytes(PAIR_BOOTSTRAP_KEM_CIPHERTEXT_BYTES_V1),
  },
]);

export const pairStepEnvelopeV1Schema = record("PairStepEnvelopeV1", [
  { name: "version", type: u8 },
  { name: "pairRoutingTag", type: bytes32 },
  { name: "bootstrapHeader", type: optional(pairBootstrapHeaderV1Schema) },
  { name: "nonce", type: optional(fixedBytes(24)) },
  // The exact class-dependent length is derived and enforced by the pair
  // envelope validator. This descriptor supplies only the absolute wire bound.
  {
    name: "pairCiphertextAndTag",
    type: varBytes(MAX_OPERATION_PAYLOAD_BYTES),
  },
]);

/* ------------------------------------------------------------------ *
 * Section 4.5 — carrier-separated envelope
 * ------------------------------------------------------------------ */

export const carrierEnvelopeV1Schema = record("CarrierEnvelopeV1", [
  { name: "version", type: u8 },
  { name: "deliveryProfileHash", type: bytes32 },
  { name: "ingressWindow", type: u64 },
  { name: "sizeClass", type: u8 },
  { name: "carrierContextId", type: bytes32 },
  { name: "nonce", type: fixedBytes(24) },
  { name: "ciphertextAndTag", type: varBytes(1 << 20) },
]);

export const carrierPlaintextV1Schema = record("CarrierPlaintextV1", [
  {
    name: "operationBytes",
    type: varBytes(MAX_CARRIED_ROOM_OPERATION_BYTES_V1),
  },
  { name: "carrierPadding", type: varBytes(1 << 20) },
]);

/* ------------------------------------------------------------------ *
 * Section 4.7 — core reduction projections
 * ------------------------------------------------------------------ */

/** The sorted duplicate-free operation-ID projection hashed by
 * `operationsDigest` and by the R2 required-operation digest. */
export const operationIdSetSchema = array(bytes32, MAX_REGISTRY_ENTRIES);

/* ------------------------------------------------------------------ *
 * Section 4.0 — executable kernel, claim, and formal registries
 * ------------------------------------------------------------------ */

export const kernelEntrypointV1Schema = record("KernelEntrypointV1", [
  { name: "entrypointId", type: u16 },
  { name: "inputSchemaHash", type: bytes32 },
  { name: "outputSchemaHash", type: bytes32 },
  { name: "normativeSourceHash", type: bytes32 },
]);

export const executableRendezvousKernelModuleV1Schema = record(
  "ExecutableRendezvousKernelModuleV1",
  [
    { name: "moduleId", type: u16 },
    { name: "executableArtifactHash", type: bytes32 },
    { name: "normativeSourceTreeHash", type: bytes32 },
    {
      name: "entrypoints",
      type: array(kernelEntrypointV1Schema, KERNEL_ENTRYPOINT_IDS.length),
    },
    { name: "canonicalVectorSetHash", type: bytes32 },
  ],
);

export const executableRendezvousKernelManifestV1Schema = record(
  "ExecutableRendezvousKernelManifestV1",
  [
    { name: "version", type: u8 },
    { name: "canonicalBinarySchemaHash", type: bytes32 },
    {
      name: "modules",
      type: array(
        executableRendezvousKernelModuleV1Schema,
        KERNEL_MODULE_IDS.length,
      ),
    },
  ],
);

export const blindRendezvousImplementationBuildManifestV1Schema = record(
  "BlindRendezvousImplementationBuildManifestV1",
  [
    { name: "version", type: u8 },
    { name: "releaseRegistryHash", type: bytes32 },
    { name: "implementationArtifactSetDigest", type: bytes32 },
    {
      name: "executableModuleArtifactHashes",
      type: array(bytes32, KERNEL_MODULE_IDS.length, "sequence"),
    },
    { name: "productionSchedulerArtifactHash", type: bytes32 },
    { name: "canonicalTraceSetDigest", type: bytes32 },
  ],
);

export const claimEvaluationStateV1Schema = enumOf("ClaimEvaluationStateV1", [
  "not-implemented",
  "not-evaluated",
  "unknown",
  "expired",
  "failed",
  "satisfied",
]);

export const claimScopeKindV1Schema = enumOf("ClaimScopeKindV1", [
  "release",
  "deployment",
  "room",
  "carrier-instance",
  "edge",
  "r2-conformance-record",
]);

export const claimAssumptionKindV1Schema = enumOf("ClaimAssumptionKindV1", [
  "cryptographic",
  "protocol",
  "deployment",
  "environmental",
]);

export const claimAssumptionVerificationV1Schema = union(
  "ClaimAssumptionVerificationV1",
  "kind",
  [
    {
      tag: "declared-foundational",
      type: record("ClaimAssumptionVerificationFoundational", [
        {
          name: "kind",
          type: enumOf("ClaimAssumptionVerificationFoundationalKind", [
            "declared-foundational",
          ]),
        },
      ]),
    },
    {
      tag: "evidence-verified",
      type: record("ClaimAssumptionVerificationEvidence", [
        {
          name: "kind",
          type: enumOf("ClaimAssumptionVerificationEvidenceKind", [
            "evidence-verified",
          ]),
        },
        { name: "verifierEntrypointId", type: u16 },
      ]),
    },
  ],
);

export const claimAssumptionV1Schema = record("ClaimAssumptionV1", [
  { name: "assumptionId", type: u16 },
  { name: "kind", type: claimAssumptionKindV1Schema },
  { name: "canonicalStatement", type: text() },
  { name: "verification", type: claimAssumptionVerificationV1Schema },
]);

export const claimEvidenceKindV1Schema = record("ClaimEvidenceKindV1", [
  { name: "evidenceKindId", type: u16 },
  { name: "canonicalSchemaHash", type: bytes32 },
  { name: "verifierEntrypointId", type: u16 },
]);

export const claimWordingByStateV1Schema = record("ClaimWordingByStateV1", [
  { name: "notImplemented", type: u16 },
  { name: "notEvaluated", type: u16 },
  { name: "unknown", type: u16 },
  { name: "expired", type: u16 },
  { name: "failed", type: u16 },
  { name: "satisfied", type: u16 },
]);

export const claimDefinitionV1Schema = record("ClaimDefinitionV1", [
  { name: "claimId", type: u16 },
  { name: "scopeKind", type: claimScopeKindV1Schema },
  { name: "scopeSchemaHash", type: bytes32 },
  { name: "predicateEntrypointId", type: u16 },
  { name: "assumptionIds", type: array(u16, MAX_REGISTRY_ENTRIES) },
  { name: "requiredEvidenceKindIds", type: array(u16, MAX_REGISTRY_ENTRIES) },
  { name: "prerequisiteClaimIds", type: array(u16, MAX_REGISTRY_ENTRIES) },
  {
    name: "requiredFormalObligationIds",
    type: array(u16, MAX_REGISTRY_ENTRIES),
  },
  { name: "wordingIdByState", type: claimWordingByStateV1Schema },
  { name: "forbiddenWordingIds", type: array(u16, MAX_REGISTRY_ENTRIES) },
]);

export const claimRegistryV1Schema = record("ClaimRegistryV1", [
  { name: "version", type: u8 },
  {
    name: "assumptions",
    type: array(claimAssumptionV1Schema, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "evidenceKinds",
    type: array(claimEvidenceKindV1Schema, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "claims",
    type: array(claimDefinitionV1Schema, MAX_REGISTRY_ENTRIES),
  },
  { name: "wordingCatalogHash", type: bytes32 },
]);

export const claimWordingEntryV1Schema = record("ClaimWordingEntryV1", [
  { name: "claimId", type: u16 },
  { name: "wordingId", type: u16 },
  { name: "state", type: claimEvaluationStateV1Schema },
  { name: "canonicalText", type: text() },
]);

export const claimReasonEntryV1Schema = record("ClaimReasonEntryV1", [
  { name: "reasonId", type: u16 },
  { name: "canonicalText", type: text() },
]);

export const claimWordingCatalogV1Schema = record("ClaimWordingCatalogV1", [
  { name: "version", type: u8 },
  {
    name: "wording",
    type: array(claimWordingEntryV1Schema, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "reasons",
    type: array(claimReasonEntryV1Schema, MAX_REGISTRY_ENTRIES),
  },
]);

export const claimEvidenceBindingV1Schema = record("ClaimEvidenceBindingV1", [
  { name: "evidenceKindId", type: u16 },
  { name: "evidenceId", type: bytes32 },
]);

export const claimPrerequisiteBindingV1Schema = record(
  "ClaimPrerequisiteBindingV1",
  [
    { name: "claimId", type: u16 },
    { name: "evaluationDigest", type: bytes32 },
  ],
);

export const claimFormalResultBindingV1Schema = record(
  "ClaimFormalResultBindingV1",
  [
    { name: "obligationId", type: u16 },
    { name: "resultDigest", type: bytes32 },
  ],
);

export const claimAssumptionBindingV1Schema = union(
  "ClaimAssumptionBindingV1",
  "kind",
  [
    {
      tag: "declared-foundational",
      type: record("ClaimAssumptionBindingFoundational", [
        { name: "assumptionId", type: u16 },
        {
          name: "kind",
          type: enumOf("ClaimAssumptionBindingFoundationalKind", [
            "declared-foundational",
          ]),
        },
      ]),
    },
    {
      tag: "evidence-verified",
      type: record("ClaimAssumptionBindingEvidence", [
        { name: "assumptionId", type: u16 },
        {
          name: "kind",
          type: enumOf("ClaimAssumptionBindingEvidenceKind", [
            "evidence-verified",
          ]),
        },
        { name: "evidenceId", type: bytes32 },
      ]),
    },
  ],
);

export const claimEvaluationDatasetV1Schema = record(
  "ClaimEvaluationDatasetV1",
  [
    { name: "version", type: u8 },
    { name: "releaseRegistryHash", type: bytes32 },
    { name: "claimRegistryHash", type: bytes32 },
    { name: "claimId", type: u16 },
    { name: "canonicalScope", type: varBytes(1 << 20) },
    {
      name: "assumptionBindings",
      type: array(claimAssumptionBindingV1Schema, MAX_REGISTRY_ENTRIES),
    },
    {
      name: "evidenceBindings",
      type: array(claimEvidenceBindingV1Schema, MAX_REGISTRY_ENTRIES),
    },
    {
      name: "prerequisiteBindings",
      type: array(claimPrerequisiteBindingV1Schema, MAX_REGISTRY_ENTRIES),
    },
    {
      name: "formalResultBindings",
      type: array(claimFormalResultBindingV1Schema, MAX_REGISTRY_ENTRIES),
    },
    { name: "evidenceSaturated", type: bool },
    { name: "firstSaturatedEvidenceId", type: optional(bytes32) },
  ],
);

export const claimEvaluationInputV1Schema = record("ClaimEvaluationInputV1", [
  { name: "releaseRegistryHash", type: bytes32 },
  { name: "claimRegistryHash", type: bytes32 },
  { name: "claimId", type: u16 },
  { name: "scopeDigest", type: bytes32 },
  { name: "evaluatedAtMs", type: u64 },
  { name: "evaluationClockUncertaintyMs", type: u64 },
  { name: "implementationPresent", type: bool },
  { name: "evaluationDatasetDigest", type: bytes32 },
]);

export const claimEvaluationV1Schema = record("ClaimEvaluationV1", [
  { name: "version", type: u8 },
  { name: "input", type: claimEvaluationInputV1Schema },
  { name: "state", type: claimEvaluationStateV1Schema },
  { name: "validThroughMs", type: optional(u64) },
  { name: "reasonIds", type: array(u16, MAX_REGISTRY_ENTRIES) },
  { name: "selectedWordingId", type: u16 },
]);

export const formalObligationKindV1Schema = enumOf("FormalObligationKindV1", [
  "algebraic",
  "safety",
  "liveness-refinement",
  "computational-game",
]);

export const formalObligationV1Schema = record("FormalObligationV1", [
  { name: "obligationId", type: u16 },
  { name: "kind", type: formalObligationKindV1Schema },
  { name: "modelSourceHash", type: bytes32 },
  { name: "propertySourceHash", type: bytes32 },
  { name: "abstractionMapHash", type: bytes32 },
  { name: "toolchainLockHash", type: bytes32 },
  { name: "proofScopeSchemaHash", type: bytes32 },
  { name: "scopeCoverageEntrypointId", type: u16 },
  { name: "assumptionIds", type: array(u16, MAX_REGISTRY_ENTRIES) },
]);

export const formalObligationRegistryV1Schema = record(
  "FormalObligationRegistryV1",
  [
    { name: "version", type: u8 },
    {
      name: "obligations",
      type: array(formalObligationV1Schema, MAX_REGISTRY_ENTRIES),
    },
  ],
);

export const formalProofScopeArtifactV1Schema = record(
  "FormalProofScopeArtifactV1",
  [
    { name: "version", type: u8 },
    { name: "obligationId", type: u16 },
    { name: "canonicalScope", type: varBytes(1 << 20) },
  ],
);

export const formalProofResultKindV1Schema = enumOf("FormalProofResultKindV1", [
  "proved-within-scope",
  "counterexample",
  "inconclusive",
]);

export const formalProofResultV1Schema = record("FormalProofResultV1", [
  { name: "version", type: u8 },
  { name: "releaseRegistryHash", type: bytes32 },
  { name: "formalObligationRegistryHash", type: bytes32 },
  { name: "obligationId", type: u16 },
  { name: "modelSourceHash", type: bytes32 },
  { name: "propertySourceHash", type: bytes32 },
  { name: "assumptionSetHash", type: bytes32 },
  { name: "abstractionMapHash", type: bytes32 },
  { name: "toolchainLockHash", type: bytes32 },
  { name: "proofScopeDigest", type: bytes32 },
  { name: "implementationArtifactSetDigest", type: bytes32 },
  { name: "canonicalTraceSetDigest", type: bytes32 },
  { name: "schedulerWorkloadDigest", type: bytes32 },
  { name: "result", type: formalProofResultKindV1Schema },
  { name: "proofArtifactDigest", type: bytes32 },
  { name: "counterexampleTraceDigest", type: optional(bytes32) },
]);

/** The resolved assumption sequence hashed by `FormalAssumptionSetHash`. */
export const resolvedAssumptionSetSchema: TypeDescriptor = array(
  claimAssumptionV1Schema,
  MAX_REGISTRY_ENTRIES,
);

/** The normalized source-tree projection hashed by `KernelSourceTreeHash`. */
export const kernelSourceTreeEntrySchema = record("KernelSourceTreeEntryV1", [
  { name: "normalizedRelativePath", type: text() },
  { name: "fileDigest", type: bytes32 },
]);

export const kernelSourceTreeSchema = array(
  kernelSourceTreeEntrySchema,
  MAX_REGISTRY_ENTRIES,
);

/** The per-entrypoint projection hashed by `KernelModuleSemanticsHash`. */
export const kernelModuleSemanticsEntrySchema = record(
  "KernelModuleSemanticsEntryV1",
  [
    { name: "entrypointId", type: u16 },
    { name: "inputSchemaHash", type: bytes32 },
    { name: "outputSchemaHash", type: bytes32 },
    { name: "normativeSourceHash", type: bytes32 },
  ],
);

export const kernelModuleSemanticsSchema = array(
  kernelModuleSemanticsEntrySchema,
  KERNEL_ENTRYPOINT_IDS.length,
);

/* ------------------------------------------------------------------ *
 * Section 4.3 — public windows, buckets, chunks, and checkpoints
 * ------------------------------------------------------------------ */

/** No room-derived value appears here: every room in a profile shares it. */
export const publicBucketV1Schema = record("PublicBucketV1", [
  { name: "deliveryProfileHash", type: bytes32 },
  { name: "ingressWindow", type: u64 },
  { name: "sizeClass", type: u8 },
]);

export const publicChunkBodyV1Schema = record("PublicChunkBodyV1", [
  { name: "version", type: u8 },
  { name: "bucket", type: publicBucketV1Schema },
  { name: "chunkIndex", type: u64 },
  { name: "previousChunkHash", type: bytes32 },
  {
    name: "fixedObjects",
    // Sequence order is the object index within the chunk, so it is
    // positional and must not be reordered into sorted order.
    type: array(varBytes(1 << 20), 0xffff, "sequence"),
  },
]);

export const publicChunkV1Schema = record("PublicChunkV1", [
  ...recordFields(publicChunkBodyV1Schema),
  { name: "storeSignature", type: bytes64 },
]);

export const publicStoreCheckpointBodyV1Schema = record(
  "PublicStoreCheckpointBodyV1",
  [
    { name: "version", type: u8 },
    { name: "storeId", type: bytes32 },
    { name: "descriptorHash", type: bytes32 },
    { name: "deliveryProfileHash", type: bytes32 },
    { name: "ingressWindow", type: u64 },
    { name: "chainStartIngressWindow", type: u64 },
    { name: "previousCheckpointHash", type: bytes32 },
    { name: "finalizedChunkCount", type: u32 },
    { name: "finalizedChunkRoot", type: bytes32 },
  ],
);

export const publicStoreCheckpointV1Schema = record("PublicStoreCheckpointV1", [
  ...recordFields(publicStoreCheckpointBodyV1Schema),
  { name: "storeSignature", type: bytes64 },
]);

export const publicCheckpointChunkLeafV1Schema = record(
  "PublicCheckpointChunkLeafV1",
  [
    { name: "sizeClass", type: u8 },
    { name: "chunkIndex", type: u64 },
    { name: "publicChunkHash", type: bytes32 },
  ],
);

export const publicCheckpointChunkInclusionProofV1Schema = record(
  "PublicCheckpointChunkInclusionProofV1",
  [
    { name: "version", type: u8 },
    { name: "checkpointHash", type: bytes32 },
    { name: "leaf", type: publicCheckpointChunkLeafV1Schema },
    { name: "leafIndex", type: u32 },
    // The audit path is ordered from the leaf upward; sorting it would
    // destroy the path.
    { name: "siblingHashes", type: array(bytes32, 0xff, "sequence") },
  ],
);

/* ------------------------------------------------------------------ *
 * Section 4.2 — store identity and routes
 * ------------------------------------------------------------------ */

export const storeCheckpointChainStartV1Schema = record(
  "StoreCheckpointChainStartV1",
  [
    { name: "deliveryProfileHash", type: bytes32 },
    { name: "chainStartIngressWindow", type: u64 },
  ],
);

const storeDescriptorFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "storeIdentityEd25519Key", type: bytes32 },
  // Canonical RSASSA-PSS SPKI for the scheme-1 Privacy Pass issuer.
  { name: "allocationIssuerPublicKeyDer", type: varBytes(4096) },
  { name: "descriptorGeneration", type: u64 },
  { name: "compatibilityHash", type: bytes32 },
  {
    name: "supportedDeliveryProfileHashes",
    type: array(bytes32, 0xff),
  },
  // Exactly one entry per supported profile, in the same bytewise order.
  {
    name: "checkpointChainStarts",
    type: array(storeCheckpointChainStartV1Schema, 0xff),
  },
  { name: "notBeforeUnixMs", type: u64 },
  { name: "notAfterUnixMs", type: u64 },
];

export const storeDescriptorUnsignedV1Schema = record(
  "StoreDescriptorUnsignedV1",
  storeDescriptorFields,
);

export const storeDescriptorV1Schema = record("StoreDescriptorV1", [
  ...storeDescriptorFields,
  { name: "descriptorSignature", type: bytes64 },
]);

const storeRouteFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "storeId", type: bytes32 },
  { name: "descriptorHash", type: bytes32 },
  { name: "routeFamily", type: u16 },
  { name: "opaqueLocator", type: varBytes(2048) },
  { name: "routePublicParameters", type: varBytes(2048) },
  { name: "notBeforeUnixMs", type: u64 },
  { name: "notAfterUnixMs", type: u64 },
];

export const storeRouteUnsignedV1Schema = record(
  "StoreRouteUnsignedV1",
  storeRouteFields,
);

export const storeRouteV1Schema = record("StoreRouteV1", [
  ...storeRouteFields,
  { name: "routeSignature", type: bytes64 },
]);

/* ------------------------------------------------------------------ *
 * Sections 4.8/4.9 — admission, presence, leave, and store hints
 * ------------------------------------------------------------------ */

export const canonicalBytes32SetV1Schema = array(
  bytes32,
  MAX_FRONTEND_ROOM_CONTROL_SET_ENTRIES_V1,
);

export const frontendRoomControlsV1Schema = record("FrontendRoomControlsV1", [
  { name: "version", type: u8 },
  { name: "policyGeneration", type: u64 },
  { name: "onlyConnectWithKnownPeers", type: bool },
  { name: "allowedStableIdentityKeys", type: canonicalBytes32SetV1Schema },
  { name: "deniedStableIdentityKeys", type: canonicalBytes32SetV1Schema },
  {
    name: "deniedRoomIdentityCommitments",
    type: canonicalBytes32SetV1Schema,
  },
]);

export const bootstrapAdmissionDecisionLeaseV1Schema = record(
  "BootstrapAdmissionDecisionLeaseV1",
  [
    { name: "version", type: u8 },
    { name: "roomContextId", type: bytes32 },
    { name: "stableEd25519PublicKey", type: bytes32 },
    { name: "stableIdentityCommitment", type: bytes32 },
    { name: "grantId", type: optional(bytes32) },
    { name: "grantGeneration", type: optional(u64) },
    { name: "localPolicyGeneration", type: u64 },
    { name: "authorityAdmissionStateDigest", type: optional(bytes32) },
    { name: "admittedPresenceOperationId", type: bytes32 },
    { name: "admittedIdentityOperationId", type: bytes32 },
    { name: "decidedAtLogicalWindow", type: u64 },
    { name: "validThroughLogicalWindow", type: u64 },
  ],
);

const admissionGrantFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "roomContextId", type: bytes32 },
  { name: "stableEd25519PublicKey", type: bytes32 },
  { name: "generation", type: u64 },
  { name: "issuedAtLogicalWindow", type: u64 },
  { name: "notBeforeLogicalWindow", type: u64 },
  { name: "notAfterLogicalWindow", type: u64 },
];

export const admissionGrantUnsignedV1Schema = record(
  "AdmissionGrantUnsignedV1",
  admissionGrantFields,
);

export const admissionGrantV1Schema = record("AdmissionGrantV1", [
  ...admissionGrantFields,
  { name: "authoritySignature", type: bytes64 },
]);

/* ------------------------------------------------------------------ *
 * Sections 4.11–4.13 — pair plaintext, identity, and transport bodies
 * ------------------------------------------------------------------ */

export const pairStepKindV1Schema = enumOf("PairStepKindV1", [
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

export const pairAttemptModeV1Schema = enumOf("PairAttemptModeV1", [
  "planner",
  "explicit",
]);

export const pairAttemptLeaseV1Schema = record("PairAttemptLeaseV1", [
  { name: "version", type: u8 },
  { name: "helloOperationId", type: bytes32 },
  { name: "pairEdgeId", type: bytes32 },
  {
    name: "endpointPresenceOperationIds",
    type: array(bytes32, 2, "sequence"),
  },
  { name: "attemptMode", type: pairAttemptModeV1Schema },
  { name: "helloLogicalWindow", type: u64 },
  { name: "validThroughLogicalWindow", type: u64 },
]);

export const pairBootstrapRecipientKindV1Schema = enumOf(
  "PairBootstrapRecipientKindV1",
  ["presence", "hello-response"],
);

export const pairTransportCandidateKindV1Schema = enumOf(
  "PairTransportCandidateKindV1",
  ["webrtc-complete", "operation-carrier", "registered-local-link"],
);

export const stableIdentityBundleV1Schema = record("StableIdentityBundleV1", [
  { name: "ed25519PublicKey", type: bytes32 },
  { name: "x25519PublicKey", type: bytes32 },
  { name: "x25519CrossSignature", type: bytes64 },
]);

const pairIdentityHelloFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "attemptMode", type: pairAttemptModeV1Schema },
  { name: "senderIdentity", type: stableIdentityBundleV1Schema },
  { name: "senderPresenceCommitment", type: bytes32 },
  { name: "senderAdmissionGrant", type: optional(admissionGrantV1Schema) },
  {
    name: "responseHybridKemPublicKey",
    type: fixedBytes(RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1),
  },
];

export const pairIdentityHelloUnsignedV1Schema = record(
  "PairIdentityHelloUnsignedV1",
  pairIdentityHelloFields,
);

export const pairIdentityHelloV1Schema = record("PairIdentityHelloV1", [
  ...pairIdentityHelloFields,
  { name: "identityTranscriptSignature", type: bytes64 },
]);

const pairIdentityAcceptFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "responderIdentity", type: stableIdentityBundleV1Schema },
  { name: "responderPresenceCommitment", type: bytes32 },
  { name: "responderAdmissionGrant", type: optional(admissionGrantV1Schema) },
];

export const pairIdentityAcceptUnsignedV1Schema = record(
  "PairIdentityAcceptUnsignedV1",
  pairIdentityAcceptFields,
);

export const pairIdentityAcceptV1Schema = record("PairIdentityAcceptV1", [
  ...pairIdentityAcceptFields,
  { name: "identityTranscriptSignature", type: bytes64 },
]);

const stableEdgeAttemptClaimFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "stableEdgeId", type: bytes32 },
  { name: "pairEdgeId", type: bytes32 },
  { name: "confirmedPairTranscriptId", type: bytes32 },
  { name: "claimantStableEd25519PublicKey", type: bytes32 },
  { name: "claimNotBeforeLogicalWindow", type: u64 },
  { name: "claimNotAfterLogicalWindow", type: u64 },
];

export const stableEdgeAttemptClaimUnsignedV1Schema = record(
  "StableEdgeAttemptClaimUnsignedV1",
  stableEdgeAttemptClaimFields,
);

export const stableEdgeAttemptClaimV1Schema = record(
  "StableEdgeAttemptClaimV1",
  [
    ...stableEdgeAttemptClaimFields,
    { name: "claimantSignature", type: bytes64 },
  ],
);

const pairTransportWebrtcCandidateV1Schema = record(
  "PairTransportWebrtcCandidateV1",
  [
    { name: "version", type: u8 },
    { name: "kind", type: pairTransportCandidateKindV1Schema },
    {
      name: "exactSdpUtf8",
      type: varBytes(MAX_PAIR_WEBRTC_SDP_BYTES_V1),
    },
  ],
);

const pairTransportOperationCarrierCandidateV1Schema = record(
  "PairTransportOperationCarrierCandidateV1",
  [
    { name: "version", type: u8 },
    { name: "kind", type: pairTransportCandidateKindV1Schema },
  ],
);

const pairTransportRegisteredLocalCandidateV1Schema = record(
  "PairTransportRegisteredLocalCandidateV1",
  [
    { name: "version", type: u8 },
    { name: "kind", type: pairTransportCandidateKindV1Schema },
    { name: "adapterProtocolId", type: u16 },
    {
      name: "fixedCanonicalCandidate",
      type: varBytes(MAX_PAIR_LOCAL_CANDIDATE_BYTES_V1),
    },
  ],
);

export const pairTransportCandidateV1Schema = union(
  "PairTransportCandidateV1",
  "kind",
  [
    {
      tag: "webrtc-complete",
      type: pairTransportWebrtcCandidateV1Schema,
    },
    {
      tag: "operation-carrier",
      type: pairTransportOperationCarrierCandidateV1Schema,
    },
    {
      tag: "registered-local-link",
      type: pairTransportRegisteredLocalCandidateV1Schema,
    },
  ],
);

export const pairTransportOfferV1Schema = record("PairTransportOfferV1", [
  { name: "version", type: u8 },
  { name: "initiatorStableEdgeClaim", type: stableEdgeAttemptClaimV1Schema },
  {
    name: "candidates",
    type: array(
      pairTransportCandidateV1Schema,
      MAX_PAIR_TRANSPORT_CANDIDATES_V1,
      "sequence",
    ),
  },
]);

export const pairTransportAnswerV1Schema = record("PairTransportAnswerV1", [
  { name: "version", type: u8 },
  { name: "responderStableEdgeClaim", type: stableEdgeAttemptClaimV1Schema },
  { name: "selectedOfferCandidateId", type: bytes32 },
  { name: "answer", type: pairTransportCandidateV1Schema },
]);

export const quiesceProposeV1Schema = record("QuiesceProposeV1", [
  { name: "version", type: u8 },
  { name: "pqEpoch", type: u64 },
]);

export const quiesceAckV1Schema = record("QuiesceAckV1", [
  { name: "version", type: u8 },
  { name: "pqEpoch", type: u64 },
]);

export const healCompleteV1Schema = record("HealCompleteV1", [
  { name: "version", type: u8 },
  { name: "newPqEpoch", type: u64 },
]);

export const pairCheckpointV1Schema = record("PairCheckpointV1", [
  { name: "version", type: u8 },
  { name: "pqEpoch", type: u64 },
]);

const pairStepBodyVariant = (
  name: string,
  value: TypeDescriptor,
): TypeDescriptor =>
  record(name, [
    { name: "kind", type: pairStepKindV1Schema },
    { name: "value", type: value },
  ]);

export const pairStepBodyV1Schema = union("PairStepBodyV1", "kind", [
  {
    tag: "IDENTITY_HELLO",
    type: pairStepBodyVariant(
      "PairStepIdentityHelloBodyV1",
      pairIdentityHelloV1Schema,
    ),
  },
  {
    tag: "IDENTITY_ACCEPT",
    type: pairStepBodyVariant(
      "PairStepIdentityAcceptBodyV1",
      pairIdentityAcceptV1Schema,
    ),
  },
  {
    tag: "TRANSPORT_OFFER",
    type: pairStepBodyVariant(
      "PairStepTransportOfferBodyV1",
      pairTransportOfferV1Schema,
    ),
  },
  {
    tag: "TRANSPORT_ANSWER",
    type: pairStepBodyVariant(
      "PairStepTransportAnswerBodyV1",
      pairTransportAnswerV1Schema,
    ),
  },
  {
    tag: "V4_HANDSHAKE",
    type: pairStepBodyVariant(
      "PairStepV4HandshakeBodyV1",
      varBytes(MAX_HANDSHAKE_PAYLOAD_LENGTH),
    ),
  },
  {
    tag: "PQ_CONTROL",
    type: pairStepBodyVariant(
      "PairStepPqControlBodyV1",
      fixedBytes(WIRE_CHUNK_FRAME_LEN),
    ),
  },
  {
    tag: "QUIESCE_PROPOSE",
    type: pairStepBodyVariant(
      "PairStepQuiesceProposeBodyV1",
      quiesceProposeV1Schema,
    ),
  },
  {
    tag: "QUIESCE_ACK",
    type: pairStepBodyVariant("PairStepQuiesceAckBodyV1", quiesceAckV1Schema),
  },
  {
    tag: "HEAL_COMPLETE",
    type: pairStepBodyVariant(
      "PairStepHealCompleteBodyV1",
      healCompleteV1Schema,
    ),
  },
  {
    tag: "PAIR_CHECKPOINT",
    type: pairStepBodyVariant(
      "PairStepCheckpointBodyV1",
      pairCheckpointV1Schema,
    ),
  },
]);

const pairPlaintextFields = (
  body: TypeDescriptor,
): readonly FieldDescriptor[] => [
  { name: "version", type: u8 },
  { name: "kind", type: pairStepKindV1Schema },
  { name: "pairEdgeId", type: bytes32 },
  {
    name: "endpointPresenceOperationIds",
    type: array(bytes32, 2, "sequence"),
  },
  { name: "direction", type: u8 },
  { name: "pairSequence", type: u64 },
  { name: "previousPairOperationId", type: optional(bytes32) },
  {
    name: "pairDependencies",
    type: array(bytes32, MAX_PAIR_DEPENDENCIES_V1),
  },
  { name: "body", type: body },
  { name: "pairPadding", type: varBytes(MAX_PAIR_PADDING_BYTES_V1) },
];

export const pairPlaintextV1Schema = record(
  "PairPlaintextV1",
  pairPlaintextFields(pairStepBodyV1Schema),
);

const pairIdentityUnsignedBodyV1Schema = union(
  "PairIdentityUnsignedBodyV1",
  "kind",
  [
    {
      tag: "IDENTITY_HELLO",
      type: pairStepBodyVariant(
        "PairIdentityUnsignedHelloBodyV1",
        pairIdentityHelloUnsignedV1Schema,
      ),
    },
    {
      tag: "IDENTITY_ACCEPT",
      type: pairStepBodyVariant(
        "PairIdentityUnsignedAcceptBodyV1",
        pairIdentityAcceptUnsignedV1Schema,
      ),
    },
  ],
);

export const pairIdentityUnsignedProjectionV1Schema = record(
  "PairIdentityUnsignedProjectionV1",
  pairPlaintextFields(pairIdentityUnsignedBodyV1Schema),
);

export const pairOuterPrebindingV1Schema = record("PairOuterPrebindingV1", [
  { name: "version", type: u8 },
  { name: "roomContextConfirmation", type: bytes32 },
  { name: "policyHash", type: bytes32 },
  { name: "logicalWindow", type: u64 },
  { name: "expiresAfterWindow", type: u64 },
  { name: "lifetime", type: operationLifetimeV1Schema },
  { name: "authorEpochEd25519Key", type: bytes32 },
  { name: "authorSequence", type: u64 },
  { name: "previousAuthorOperationId", type: optional(bytes32) },
  { name: "kind", type: operationKindV1Schema },
  {
    name: "dependencies",
    type: array(bytes32, MAX_PAIR_DEPENDENCIES_V1),
  },
  { name: "operationPayloadClass", type: u8 },
  { name: "bootstrapHeaderHash", type: bytes32 },
  { name: "nonce", type: optional(fixedBytes(24)) },
]);

export const pairOuterBindingV1Schema = record("PairOuterBindingV1", [
  { name: "prebinding", type: pairOuterPrebindingV1Schema },
  { name: "pairRoutingTag", type: bytes32 },
  { name: "semanticSlot", type: bytes32 },
]);

export const pairFlightSlotV1Schema = record("PairFlightSlotV1", [
  { name: "kind", type: pairStepKindV1Schema },
  { name: "direction", type: u8 },
  { name: "pairSequence", type: u64 },
]);

const pairBootstrapPresenceRecipientV1Schema = record(
  "PairBootstrapPresenceRecipientV1",
  [
    { name: "kind", type: pairBootstrapRecipientKindV1Schema },
    { name: "presenceOperationId", type: bytes32 },
  ],
);

const pairBootstrapHelloResponseRecipientV1Schema = record(
  "PairBootstrapHelloResponseRecipientV1",
  [
    { name: "kind", type: pairBootstrapRecipientKindV1Schema },
    { name: "helloOperationId", type: bytes32 },
  ],
);

export const pairBootstrapRecipientBindingV1Schema = union(
  "PairBootstrapRecipientBindingV1",
  "kind",
  [
    {
      tag: "presence",
      type: pairBootstrapPresenceRecipientV1Schema,
    },
    {
      tag: "hello-response",
      type: pairBootstrapHelloResponseRecipientV1Schema,
    },
  ],
);

export const pairBootstrapInfoV1Schema = record("PairBootstrapInfoV1", [
  { name: "version", type: u8 },
  { name: "pairBootstrapSuite", type: u8 },
  { name: "roomContextConfirmation", type: bytes32 },
  { name: "policyHash", type: bytes32 },
  { name: "stepKind", type: pairStepKindV1Schema },
  { name: "logicalWindow", type: u64 },
  { name: "expiresAfterWindow", type: u64 },
  { name: "authorEpochEd25519Key", type: bytes32 },
  { name: "authorSequence", type: u64 },
  { name: "previousAuthorOperationId", type: optional(bytes32) },
  { name: "operationPayloadClass", type: u8 },
  { name: "recipientBinding", type: pairBootstrapRecipientBindingV1Schema },
]);

/* ------------------------------------------------------------------ *
 * Section 4.11 — durable accepted pair-slot audit
 * ------------------------------------------------------------------ */

export const pairAcceptedSlotCoordinateV1Schema = record(
  "PairAcceptedSlotCoordinateV1",
  [
    { name: "pairEdgeId", type: bytes32 },
    {
      name: "endpointPresenceOperationIds",
      type: array(bytes32, 2),
    },
    { name: "direction", type: u8 },
    { name: "pairSequence", type: u64 },
  ],
);

export const pairAuthorChainPrefixEvidenceV1Schema = record(
  "PairAuthorChainPrefixEvidenceV1",
  [
    { name: "operationId", type: bytes32 },
    {
      name: "exactOperationBytes",
      type: varBytes(MAX_CARRIED_ROOM_OPERATION_BYTES_V1),
    },
  ],
);

const pairSlotAcceptanceFields: readonly FieldDescriptor[] = [
  { name: "coordinate", type: pairAcceptedSlotCoordinateV1Schema },
  { name: "kind", type: pairStepKindV1Schema },
  { name: "acceptedOperationId", type: bytes32 },
  {
    name: "exactOperationBytes",
    type: varBytes(MAX_CARRIED_ROOM_OPERATION_BYTES_V1),
  },
  { name: "acceptedLogicalWindow", type: u64 },
  { name: "retainThroughLogicalWindow", type: u64 },
  { name: "routingTag", type: bytes32 },
  {
    name: "authorChainPrefix",
    type: array(
      pairAuthorChainPrefixEvidenceV1Schema,
      MAX_OPERATIONS_PER_AUTHOR_WINDOW_V1,
      "sequence",
    ),
  },
  {
    name: "cachedExactResponse",
    type: optional(varBytes(MAX_CARRIED_ROOM_OPERATION_BYTES_V1)),
  },
];

/**
 * Canonical post-authentication input. Its descriptor is shared by the live
 * transition and durable entry so neither path can drift in field order or
 * bounds.
 */
export const pairSlotAcceptanceCandidateV1Schema = record(
  "PairSlotAcceptanceCandidateV1",
  pairSlotAcceptanceFields,
);

export const pairAcceptedSlotEntryV1Schema = record("PairAcceptedSlotEntryV1", [
  { name: "version", type: u8 },
  ...pairSlotAcceptanceFields,
  {
    name: "forkProofOperationIds",
    type: optional(array(bytes32, 2)),
  },
]);

export const pairAcceptedSlotLedgerSnapshotV1Schema = record(
  "PairAcceptedSlotLedgerSnapshotV1",
  [
    { name: "version", type: u8 },
    {
      name: "entries",
      type: array(
        pairAcceptedSlotEntryV1Schema,
        MAX_REGISTRY_ENTRIES,
        "sequence",
      ),
    },
  ],
);

/* ------------------------------------------------------------------ *
 * Section 4.10 — durable pair-open work budget
 * ------------------------------------------------------------------ */

export const pairOpenBudgetCoordinateV1Schema = record(
  "PairOpenBudgetCoordinateV1",
  [
    { name: "localRoomId", type: text(43) },
    { name: "localPresenceOperationId", type: bytes32 },
    { name: "budgetLogicalWindow", type: u64 },
  ],
);

export const pairOpenBudgetChargeV1Schema = record("PairOpenBudgetChargeV1", [
  { name: "localRoomId", type: text(43) },
  { name: "localPresenceOperationId", type: bytes32 },
  { name: "capturedReferenceWindow", type: u64 },
  { name: "completeEnvelopeBytes", type: u32 },
]);

export const pairOpenBudgetSnapshotV1Schema = record(
  "PairOpenBudgetSnapshotV1",
  [
    { name: "version", type: u8 },
    { name: "coordinate", type: pairOpenBudgetCoordinateV1Schema },
    { name: "budgetRevision", type: u64 },
    { name: "reservedTrialCount", type: u32 },
    { name: "reservedEnvelopeBytes", type: u64 },
    { name: "saturated", type: bool },
  ],
);

const admissionRevokeFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "roomContextId", type: bytes32 },
  { name: "stableIdentityCommitment", type: bytes32 },
  { name: "minimumAcceptedGeneration", type: u64 },
  { name: "effectiveLogicalWindow", type: u64 },
  { name: "expiresAfterLogicalWindow", type: u64 },
];

export const admissionRevokeUnsignedV1Schema = record(
  "AdmissionRevokeUnsignedV1",
  admissionRevokeFields,
);

export const admissionRevokeV1Schema = record("AdmissionRevokeV1", [
  ...admissionRevokeFields,
  { name: "authoritySignature", type: bytes64 },
]);

export const presenceCoreV1Schema = record("PresenceCoreV1", [
  { name: "version", type: u8 },
  { name: "stableIdentityCommitment", type: bytes32 },
  {
    name: "rendezvousHybridKemPublicKey",
    type: fixedBytes(RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1),
  },
  { name: "receiverKeyValidThroughLogicalWindow", type: u64 },
  { name: "presenceNonce", type: bytes32 },
  { name: "validThroughLogicalWindow", type: u64 },
]);

const presencePermitFields: readonly FieldDescriptor[] = [
  { name: "version", type: u8 },
  { name: "roomContextId", type: bytes32 },
  { name: "presenceProofTranscriptHash", type: bytes32 },
  { name: "permitSerial", type: bytes32 },
  { name: "generation", type: u64 },
  { name: "issuedAtLogicalWindow", type: u64 },
  { name: "notBeforeLogicalWindow", type: u64 },
  { name: "notAfterLogicalWindow", type: u64 },
];

export const presencePermitUnsignedV1Schema = record(
  "PresencePermitUnsignedV1",
  presencePermitFields,
);

export const presencePermitV1Schema = record("PresencePermitV1", [
  ...presencePermitFields,
  { name: "authoritySignature", type: bytes64 },
]);

export const presenceV1Schema = record("PresenceV1", [
  { name: "core", type: presenceCoreV1Schema },
  { name: "stableOwnershipSignature", type: bytes64 },
  { name: "authorityPermit", type: optional(presencePermitV1Schema) },
]);

/**
 * Canonical input to `PresenceProofTranscriptHash`.
 *
 * The declaration order is protocol-visible. Keeping it in the schema SSOT
 * prevents an implementation from silently reordering the outer bindings.
 */
export const presenceProofTranscriptV1Schema = record(
  "PresenceProofTranscriptV1",
  [
    { name: "roomContextId", type: bytes32 },
    { name: "policyHash", type: bytes32 },
    { name: "logicalWindow", type: u64 },
    { name: "authorEpochEd25519Key", type: bytes32 },
    { name: "core", type: presenceCoreV1Schema },
  ],
);

export const leaveV1Schema = record("LeaveV1", [
  { name: "version", type: u8 },
  { name: "presenceOperationId", type: bytes32 },
  { name: "effectiveLogicalWindow", type: u64 },
]);

export const storeHintOperationV1Schema = record("StoreHintOperationV1", [
  { name: "version", type: u8 },
  { name: "descriptor", type: storeDescriptorV1Schema },
  // RouteId, not route bytes, is the semantic order key. The payload
  // validator derives and checks that order after this sequence decode.
  {
    name: "routes",
    type: array(storeRouteV1Schema, MAX_STORE_HINT_ROUTES_V1, "sequence"),
  },
  { name: "hintExpiresAfterLogicalWindow", type: u64 },
]);

/* ------------------------------------------------------------------ *
 * Section 4.7 — canonical core-reduction output
 * ------------------------------------------------------------------ */

export const corePresenceFactV1Schema = record("CorePresenceFactV1", [
  { name: "presenceOperationId", type: bytes32 },
  { name: "authorEpochEd25519Key", type: bytes32 },
  { name: "logicalWindow", type: u64 },
  { name: "presence", type: presenceV1Schema },
]);

/*
 * Field order follows the canonical identifying tuple, not the interface's
 * prose order. This makes the generic sorted-unique array codec the comparator
 * SSOT for store facts.
 */
export const coreStoreFactV1Schema = record("CoreStoreFactV1", [
  { name: "storeId", type: bytes32 },
  { name: "descriptorGeneration", type: u64 },
  { name: "descriptorHash", type: bytes32 },
  { name: "sourceOperationId", type: bytes32 },
  { name: "descriptor", type: storeDescriptorV1Schema },
  {
    name: "routes",
    type: array(storeRouteV1Schema, MAX_STORE_HINT_ROUTES_V1, "sequence"),
  },
  { name: "hintValidThroughLogicalWindow", type: u64 },
]);

export const coreRevocationFloorV1Schema = record("CoreRevocationFloorV1", [
  { name: "stableIdentityCommitment", type: bytes32 },
  { name: "minimumAcceptedGeneration", type: u64 },
  { name: "effectiveLogicalWindow", type: u64 },
  { name: "validThroughLogicalWindow", type: u64 },
  { name: "revokeOperationId", type: bytes32 },
]);

const coreAuthorFaultV1Schema = record("CoreAuthorFaultV1", [
  {
    name: "kind",
    type: enumOf("CoreAuthorFaultKindV1", ["author-fork-or-overquota"]),
  },
  { name: "authorEpochEd25519Key", type: bytes32 },
  { name: "logicalWindow", type: u64 },
  { name: "proofOperationIds", type: array(bytes32, MAX_REGISTRY_ENTRIES) },
]);

const corePresenceOrLeaveFaultV1Schema = record("CorePresenceOrLeaveFaultV1", [
  {
    name: "kind",
    type: enumOf("CorePresenceOrLeaveFaultKindV1", ["presence-or-leave-fork"]),
  },
  { name: "semanticSlot", type: bytes32 },
  { name: "proofOperationIds", type: array(bytes32, 2) },
]);

const coreStoreGenerationFaultV1Schema = record("CoreStoreGenerationFaultV1", [
  {
    name: "kind",
    type: enumOf("CoreStoreGenerationFaultKindV1", ["store-generation-fork"]),
  },
  { name: "storeId", type: bytes32 },
  { name: "descriptorGeneration", type: u64 },
  { name: "descriptorHashes", type: array(bytes32, 2) },
]);

/**
 * Variant order is the canonical fault order and therefore protocol-visible.
 * Reducer sorting derives its order from this descriptor.
 */
export const coreFaultV1Schema = union("CoreFaultV1", "kind", [
  {
    tag: "author-fork-or-overquota",
    type: coreAuthorFaultV1Schema,
  },
  {
    tag: "presence-or-leave-fork",
    type: corePresenceOrLeaveFaultV1Schema,
  },
  {
    tag: "store-generation-fork",
    type: coreStoreGenerationFaultV1Schema,
  },
]);

export const roomCapacityStateV1Schema = enumOf("RoomCapacityStateV1", [
  "within-policy",
  "overcapacity",
]);

export const coreRoomStateV1Schema = record("CoreRoomStateV1", [
  { name: "version", type: u8 },
  { name: "referenceWindow", type: u64 },
  { name: "roomCapacityState", type: roomCapacityStateV1Schema },
  {
    name: "activeOperationIds",
    type: array(bytes32, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "observedPresences",
    type: array(corePresenceFactV1Schema, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "effectiveLeaveOperationIds",
    type: array(bytes32, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "storeCatalogFacts",
    type: array(coreStoreFactV1Schema, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "revocationFloors",
    type: array(coreRevocationFloorV1Schema, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "activePairOuterOperationIds",
    type: array(bytes32, MAX_REGISTRY_ENTRIES),
  },
  {
    name: "faults",
    type: array(coreFaultV1Schema, MAX_REGISTRY_ENTRIES),
  },
  { name: "operationsDigest", type: bytes32 },
]);
