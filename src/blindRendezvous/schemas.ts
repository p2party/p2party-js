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

import type { FieldDescriptor, TypeDescriptor } from "./canonicalSchema";

/* ------------------------------------------------------------------ *
 * Shared bounds
 * ------------------------------------------------------------------ */

/** Section 4.4 operation payload classes: exact signed inner byte counts. */
export const OPERATION_PAYLOAD_CLASS_BYTES: Readonly<Record<0 | 1, number>> =
  Object.freeze({ 0: 4096, 1: 69632 });

export const MAX_OPERATION_PAYLOAD_BYTES = OPERATION_PAYLOAD_CLASS_BYTES[1];

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
  { name: "operationBytes", type: varBytes(1 << 20) },
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
