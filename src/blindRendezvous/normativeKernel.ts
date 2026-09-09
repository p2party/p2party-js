/**
 * Blind-rendezvous registry shape validators, intentionally absent from the
 * package's public barrel.
 *
 * This module validates the logical shape of the kernel manifest, claim
 * registry, claim evaluations, and formal-obligation records so separate tools
 * cannot accept different registry shapes. It deliberately evaluates no claim
 * and exposes no positive-wording authorizer.
 *
 * Every field table and closed enumeration below is now imported from
 * `projections.ts`, which derives them from the canonical binary schema. The
 * schema is the SSOT for bytes, widths, ordering, and bounds; this module owns
 * only the cross-record reference, ordering, and acyclicity rules that a
 * per-value encoding cannot express.
 *
 * The schema itself is still PROPOSED, not frozen: acquiring real protocol
 * hashes additionally requires the Phase-0 freeze, deterministic vectors, and
 * the module-8 resolver/evaluator.
 */

import {
  CLAIM_ASSUMPTION_EVIDENCE_VERIFICATION_KEYS,
  CLAIM_ASSUMPTION_FOUNDATIONAL_VERIFICATION_KEYS,
  CLAIM_ASSUMPTION_KEYS,
  CLAIM_ASSUMPTION_KINDS,
  CLAIM_DEFINITION_KEYS,
  CLAIM_EVALUATION_INPUT_KEYS,
  CLAIM_EVALUATION_KEYS,
  CLAIM_EVALUATION_STATES,
  CLAIM_EVIDENCE_KIND_KEYS,
  CLAIM_REGISTRY_KEYS,
  CLAIM_SCOPE_KINDS,
  CLAIM_WORDING_KEYS,
  CLAIM_WORDING_KEY_LIST,
  FORMAL_OBLIGATION_KEYS,
  FORMAL_OBLIGATION_KINDS,
  FORMAL_PROOF_RESULTS,
  FORMAL_REGISTRY_KEYS,
  FORMAL_RESULT_KEYS,
  KERNEL_ENTRYPOINT_KEYS,
  KERNEL_MANIFEST_KEYS,
  KERNEL_MODULE_KEYS,
} from "./projections";
import {
  KERNEL_ENTRYPOINT_IDS,
  KERNEL_ENTRYPOINT_IDS_BY_MODULE,
  KERNEL_MODULE_IDS,
  V04_REQUIRED_FORMAL_OBLIGATION_IDS,
} from "./schemas";

export type Bytes32 = Uint8Array;
export type Uint16 = number;

export type KernelModuleIdV1 =
  | 1 // validate-operation-set
  | 2 // core-reduce
  | 3 // admit
  | 4 // derive-assurance
  | 5 // derive-l3-required-work
  | 6 // delivery-scheduler-and-r2-conforms
  | 7 // eventual-pair-control-transition
  | 8; // evaluate-claim

export type KernelEntrypointIdV1 =
  | 1 // validate-operation-set
  | 2 // core-reduce
  | 3 // admit
  | 4 // derive-assurance
  | 5 // derive-l3-required-work
  | 6 // delivery-scheduler
  | 7 // r2-conforms
  | 8 // eventual-pair-control-transition
  | 9; // evaluate-claim

export interface KernelEntrypointV1 {
  entrypointId: KernelEntrypointIdV1;
  inputSchemaHash: Bytes32;
  outputSchemaHash: Bytes32;
  normativeSourceHash: Bytes32;
}

export interface ExecutableRendezvousKernelModuleV1 {
  moduleId: KernelModuleIdV1;
  entrypoints: readonly KernelEntrypointV1[];
  executableArtifactHash: Bytes32;
  normativeSourceTreeHash: Bytes32;
  canonicalVectorSetHash: Bytes32;
}

export interface ExecutableRendezvousKernelManifestV1 {
  version: 1;
  canonicalBinarySchemaHash: Bytes32;
  modules: readonly ExecutableRendezvousKernelModuleV1[];
}

export interface BlindRendezvousImplementationBuildManifestV1 {
  version: 1;
  releaseRegistryHash: Bytes32;
  implementationArtifactSetDigest: Bytes32;
  executableModuleArtifactHashes: readonly Bytes32[];
  productionSchedulerArtifactHash: Bytes32;
  canonicalTraceSetDigest: Bytes32;
}

export type ClaimEvaluationStateV1 =
  | "not-implemented"
  | "not-evaluated"
  | "unknown"
  | "expired"
  | "failed"
  | "satisfied";

export type ClaimScopeKindV1 =
  | "release"
  | "deployment"
  | "room"
  | "carrier-instance"
  | "edge"
  | "r2-conformance-record";

export interface ClaimAssumptionV1 {
  assumptionId: Uint16;
  kind: "cryptographic" | "protocol" | "deployment" | "environmental";
  canonicalStatement: string;
  verification:
    | { kind: "declared-foundational" }
    | {
        kind: "evidence-verified";
        verifierEntrypointId: KernelEntrypointIdV1;
      };
}

export interface ClaimEvidenceKindV1 {
  evidenceKindId: Uint16;
  canonicalSchemaHash: Bytes32;
  verifierEntrypointId: KernelEntrypointIdV1;
}

export interface ClaimWordingByStateV1 {
  notImplemented: Uint16;
  notEvaluated: Uint16;
  unknown: Uint16;
  expired: Uint16;
  failed: Uint16;
  satisfied: Uint16;
}

export interface ClaimDefinitionV1 {
  claimId: Uint16;
  scopeKind: ClaimScopeKindV1;
  scopeSchemaHash: Bytes32;
  predicateEntrypointId: KernelEntrypointIdV1;
  assumptionIds: readonly Uint16[];
  requiredEvidenceKindIds: readonly Uint16[];
  prerequisiteClaimIds: readonly Uint16[];
  requiredFormalObligationIds: readonly Uint16[];
  wordingIdByState: ClaimWordingByStateV1;
  forbiddenWordingIds: readonly Uint16[];
}

export interface ClaimRegistryV1 {
  version: 1;
  assumptions: readonly ClaimAssumptionV1[];
  evidenceKinds: readonly ClaimEvidenceKindV1[];
  claims: readonly ClaimDefinitionV1[];
  wordingCatalogHash: Bytes32;
}

export interface ClaimWordingCatalogV1 {
  version: 1;
  wording: readonly {
    claimId: Uint16;
    wordingId: Uint16;
    state: ClaimEvaluationStateV1;
    canonicalText: string;
  }[];
  reasons: readonly {
    reasonId: Uint16;
    canonicalText: string;
  }[];
}

export interface ClaimEvidenceBindingV1 {
  evidenceKindId: Uint16;
  evidenceId: Bytes32;
}

export interface ClaimPrerequisiteBindingV1 {
  claimId: Uint16;
  evaluationDigest: Bytes32;
}

export interface ClaimFormalResultBindingV1 {
  obligationId: Uint16;
  resultDigest: Bytes32;
}

export type ClaimAssumptionBindingV1 =
  | {
      assumptionId: Uint16;
      kind: "declared-foundational";
    }
  | {
      assumptionId: Uint16;
      kind: "evidence-verified";
      evidenceId: Bytes32;
    };

export interface ClaimEvaluationDatasetV1 {
  version: 1;
  releaseRegistryHash: Bytes32;
  claimRegistryHash: Bytes32;
  claimId: Uint16;
  canonicalScope: Uint8Array;
  assumptionBindings: readonly ClaimAssumptionBindingV1[];
  evidenceBindings: readonly ClaimEvidenceBindingV1[];
  prerequisiteBindings: readonly ClaimPrerequisiteBindingV1[];
  formalResultBindings: readonly ClaimFormalResultBindingV1[];
  evidenceSaturated: boolean;
  firstSaturatedEvidenceId: Bytes32 | null;
}

export interface ClaimEvaluationInputV1 {
  releaseRegistryHash: Bytes32;
  claimRegistryHash: Bytes32;
  claimId: Uint16;
  scopeDigest: Bytes32;
  evaluatedAtMs: bigint;
  evaluationClockUncertaintyMs: bigint;
  implementationPresent: boolean;
  evaluationDatasetDigest: Bytes32;
}

export interface ClaimEvaluationV1 {
  version: 1;
  input: ClaimEvaluationInputV1;
  state: ClaimEvaluationStateV1;
  reasonIds: readonly Uint16[];
  selectedWordingId: Uint16;
  validThroughMs: bigint | null;
}

export interface CurrentClaimEvaluationRegistryRootsV1 {
  releaseRegistryHash: Bytes32;
  claimRegistryHash: Bytes32;
}

export type FormalObligationKindV1 =
  "algebraic" | "safety" | "liveness-refinement" | "computational-game";

export interface FormalObligationV1 {
  obligationId: Uint16;
  kind: FormalObligationKindV1;
  modelSourceHash: Bytes32;
  propertySourceHash: Bytes32;
  abstractionMapHash: Bytes32;
  toolchainLockHash: Bytes32;
  proofScopeSchemaHash: Bytes32;
  scopeCoverageEntrypointId: KernelEntrypointIdV1;
  assumptionIds: readonly Uint16[];
}

export interface FormalObligationRegistryV1 {
  version: 1;
  obligations: readonly FormalObligationV1[];
}

export interface FormalProofScopeArtifactV1 {
  version: 1;
  obligationId: Uint16;
  canonicalScope: Uint8Array;
}

export interface FormalProofResultV1 {
  version: 1;
  releaseRegistryHash: Bytes32;
  formalObligationRegistryHash: Bytes32;
  obligationId: Uint16;
  modelSourceHash: Bytes32;
  propertySourceHash: Bytes32;
  assumptionSetHash: Bytes32;
  abstractionMapHash: Bytes32;
  toolchainLockHash: Bytes32;
  proofScopeDigest: Bytes32;
  implementationArtifactSetDigest: Bytes32;
  canonicalTraceSetDigest: Bytes32;
  schedulerWorkloadDigest: Bytes32;
  result: "proved-within-scope" | "counterexample" | "inconclusive";
  proofArtifactDigest: Bytes32;
  counterexampleTraceDigest: Bytes32 | null;
}

export interface FormalProofValidationContextV1 {
  releaseRegistryHash: Bytes32;
  formalObligationRegistryHash: Bytes32;
  expectedAssumptionSetHash: Bytes32;
}

const KERNEL_MODULE_ID_SET = new Set<number>(KERNEL_MODULE_IDS);
const KERNEL_ENTRYPOINT_ID_SET = new Set<number>(KERNEL_ENTRYPOINT_IDS);

const MAX_REGISTRY_ENTRIES = 0xffff;
const MAX_CANONICAL_STATEMENT_BYTES = 4096;
const textEncoder = new TextEncoder();

function fail(message: string): never {
  throw new Error(`normativeKernel: ${message}`);
}

function assertPlainExactRecord(
  name: string,
  value: unknown,
  keys: ReadonlySet<string>,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    fail(`${name} must be a plain record`);

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    fail(`${name} must be a plain record`);

  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.size ||
    ownKeys.some((key) => typeof key !== "string" || !keys.has(key))
  )
    fail(`${name} has missing or unexpected fields`);

  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      fail(`${name}.${key} must be an enumerable data property`);
  }
}

function assertArray(
  name: string,
  value: unknown,
): asserts value is readonly unknown[] {
  if (!Array.isArray(value)) fail(`${name} must be an array`);
  if (value.length > MAX_REGISTRY_ENTRIES)
    fail(`${name} exceeds the registry entry bound`);

  if (Object.getPrototypeOf(value) !== Array.prototype)
    fail(`${name} must be a plain array`);
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== value.length + 1 ||
    ownKeys[ownKeys.length - 1] !== "length"
  )
    fail(`${name} has unexpected array fields`);
  for (let index = 0; index < value.length; index++) {
    if (ownKeys[index] !== String(index))
      fail(`${name} must be dense and canonically indexed`);
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      fail(`${name}[${index}] must be an enumerable data property`);
  }
}

function assertUint16(name: string, value: unknown): asserts value is Uint16 {
  if (
    !Number.isInteger(value) ||
    (value as number) < 0 ||
    (value as number) > 0xffff
  )
    fail(`${name} must be an unsigned 16-bit integer`);
}

function assertKernelModuleId(
  name: string,
  value: unknown,
): asserts value is KernelModuleIdV1 {
  if (!Number.isInteger(value) || !KERNEL_MODULE_ID_SET.has(value as number))
    fail(`${name} is not a registered kernel module`);
}

function assertKernelEntrypointId(
  name: string,
  value: unknown,
): asserts value is KernelEntrypointIdV1 {
  if (
    !Number.isInteger(value) ||
    !KERNEL_ENTRYPOINT_ID_SET.has(value as number)
  )
    fail(`${name} is not a registered kernel entrypoint`);
}

function assertBytes32(name: string, value: unknown): asserts value is Bytes32 {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32)
    fail(`${name} must be exactly 32 bytes`);
}

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return 0;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  compareBytes(left, right) === 0;

function assertSortedUniqueUint16(
  name: string,
  value: unknown,
): asserts value is readonly Uint16[] {
  assertArray(name, value);
  let previous = -1;
  for (let i = 0; i < value.length; i++) {
    assertUint16(`${name}[${i}]`, value[i]);
    if ((value[i] as number) <= previous)
      fail(`${name} must be strictly sorted and duplicate-free`);
    previous = value[i] as number;
  }
}

function assertCanonicalStatement(
  name: string,
  value: unknown,
): asserts value is string {
  if (typeof value !== "string" || value.length === 0)
    fail(`${name} must be a non-empty string`);
  if (value.normalize("NFC") !== value) fail(`${name} must use Unicode NFC`);
  if (textEncoder.encode(value).byteLength > MAX_CANONICAL_STATEMENT_BYTES)
    fail(`${name} exceeds the canonical statement byte bound`);
}

function assertBoolean(name: string, value: unknown): asserts value is boolean {
  if (typeof value !== "boolean") fail(`${name} must be a boolean`);
}

function assertNonNegativeBigint(
  name: string,
  value: unknown,
): asserts value is bigint {
  if (typeof value !== "bigint" || value < 0n)
    fail(`${name} must be a non-negative bigint`);
}

function assertKernelModule(
  value: unknown,
  index: number,
): asserts value is ExecutableRendezvousKernelModuleV1 {
  const name = `manifest.modules[${index}]`;
  assertPlainExactRecord(name, value, KERNEL_MODULE_KEYS);
  assertKernelModuleId(`${name}.moduleId`, value.moduleId);
  assertArray(`${name}.entrypoints`, value.entrypoints);
  const expectedEntrypoints = KERNEL_ENTRYPOINT_IDS_BY_MODULE[value.moduleId];
  if (value.entrypoints.length !== expectedEntrypoints.length)
    fail(`${name}.entrypoints does not match the closed module interface`);
  for (let i = 0; i < value.entrypoints.length; i++) {
    const entrypointName = `${name}.entrypoints[${i}]`;
    const entrypoint = value.entrypoints[i];
    assertPlainExactRecord(entrypointName, entrypoint, KERNEL_ENTRYPOINT_KEYS);
    assertKernelEntrypointId(
      `${entrypointName}.entrypointId`,
      entrypoint.entrypointId,
    );
    if (entrypoint.entrypointId !== expectedEntrypoints[i])
      fail(`${name}.entrypoints does not match the closed module interface`);
    assertBytes32(
      `${entrypointName}.inputSchemaHash`,
      entrypoint.inputSchemaHash,
    );
    assertBytes32(
      `${entrypointName}.outputSchemaHash`,
      entrypoint.outputSchemaHash,
    );
    assertBytes32(
      `${entrypointName}.normativeSourceHash`,
      entrypoint.normativeSourceHash,
    );
  }
  assertBytes32(`${name}.executableArtifactHash`, value.executableArtifactHash);
  assertBytes32(
    `${name}.normativeSourceTreeHash`,
    value.normativeSourceTreeHash,
  );
  assertBytes32(`${name}.canonicalVectorSetHash`, value.canonicalVectorSetHash);
}

export const validateExecutableRendezvousKernelManifestV1 = (
  manifest: ExecutableRendezvousKernelManifestV1,
): void => {
  assertPlainExactRecord("manifest", manifest, KERNEL_MANIFEST_KEYS);
  if (manifest.version !== 1) fail("manifest has an unsupported version");
  assertBytes32(
    "manifest.canonicalBinarySchemaHash",
    manifest.canonicalBinarySchemaHash,
  );
  assertArray("manifest.modules", manifest.modules);
  if (manifest.modules.length !== KERNEL_MODULE_IDS.length)
    fail("manifest must contain every kernel module exactly once");

  for (let i = 0; i < manifest.modules.length; i++) {
    assertKernelModule(manifest.modules[i], i);
    if (manifest.modules[i].moduleId !== KERNEL_MODULE_IDS[i])
      fail("manifest modules must be complete and sorted by moduleId");
  }
};

const validateClaimWording = (
  wording: ClaimWordingByStateV1,
  claimName: string,
): void => {
  assertPlainExactRecord(
    `${claimName}.wordingIdByState`,
    wording,
    CLAIM_WORDING_KEYS,
  );
  for (const key of CLAIM_WORDING_KEY_LIST)
    assertUint16(`${claimName}.wordingIdByState.${key}`, wording[key]);
};

const validateClaimAssumption = (
  assumption: ClaimAssumptionV1,
  index: number,
): void => {
  const name = `claimRegistry.assumptions[${index}]`;
  assertPlainExactRecord(name, assumption, CLAIM_ASSUMPTION_KEYS);
  assertUint16(`${name}.assumptionId`, assumption.assumptionId);
  if (!CLAIM_ASSUMPTION_KINDS.has(assumption.kind))
    fail(`${name}.kind is unsupported`);
  assertCanonicalStatement(
    `${name}.canonicalStatement`,
    assumption.canonicalStatement,
  );
  const verification = assumption.verification;
  if (
    verification === null ||
    typeof verification !== "object" ||
    Array.isArray(verification)
  )
    fail(`${name}.verification must be a plain record`);
  if (verification.kind === "declared-foundational") {
    assertPlainExactRecord(
      `${name}.verification`,
      verification,
      CLAIM_ASSUMPTION_FOUNDATIONAL_VERIFICATION_KEYS,
    );
  } else if (verification.kind === "evidence-verified") {
    assertPlainExactRecord(
      `${name}.verification`,
      verification,
      CLAIM_ASSUMPTION_EVIDENCE_VERIFICATION_KEYS,
    );
    assertKernelEntrypointId(
      `${name}.verification.verifierEntrypointId`,
      verification.verifierEntrypointId,
    );
  } else {
    fail(`${name}.verification.kind is unsupported`);
  }
};

const validateClaimEvidenceKind = (
  evidenceKind: ClaimEvidenceKindV1,
  index: number,
): void => {
  const name = `claimRegistry.evidenceKinds[${index}]`;
  assertPlainExactRecord(name, evidenceKind, CLAIM_EVIDENCE_KIND_KEYS);
  assertUint16(`${name}.evidenceKindId`, evidenceKind.evidenceKindId);
  assertBytes32(
    `${name}.canonicalSchemaHash`,
    evidenceKind.canonicalSchemaHash,
  );
  assertKernelEntrypointId(
    `${name}.verifierEntrypointId`,
    evidenceKind.verifierEntrypointId,
  );
};

const validateClaimDefinition = (
  claim: ClaimDefinitionV1,
  index: number,
): void => {
  const name = `claimRegistry.claims[${index}]`;
  assertPlainExactRecord(name, claim, CLAIM_DEFINITION_KEYS);
  assertUint16(`${name}.claimId`, claim.claimId);
  if (!CLAIM_SCOPE_KINDS.has(claim.scopeKind))
    fail(`${name}.scopeKind is unsupported`);
  assertBytes32(`${name}.scopeSchemaHash`, claim.scopeSchemaHash);
  assertKernelEntrypointId(
    `${name}.predicateEntrypointId`,
    claim.predicateEntrypointId,
  );
  assertSortedUniqueUint16(`${name}.assumptionIds`, claim.assumptionIds);
  assertSortedUniqueUint16(
    `${name}.requiredEvidenceKindIds`,
    claim.requiredEvidenceKindIds,
  );
  assertSortedUniqueUint16(
    `${name}.prerequisiteClaimIds`,
    claim.prerequisiteClaimIds,
  );
  assertSortedUniqueUint16(
    `${name}.requiredFormalObligationIds`,
    claim.requiredFormalObligationIds,
  );
  validateClaimWording(claim.wordingIdByState, name);
  assertSortedUniqueUint16(
    `${name}.forbiddenWordingIds`,
    claim.forbiddenWordingIds,
  );
  if (claim.prerequisiteClaimIds.includes(claim.claimId))
    fail(`${name} cannot depend on itself`);
  if (claim.forbiddenWordingIds.includes(claim.wordingIdByState.satisfied))
    fail(`${name} forbids its own satisfied wording`);
  if (
    [
      claim.wordingIdByState.notImplemented,
      claim.wordingIdByState.notEvaluated,
      claim.wordingIdByState.unknown,
      claim.wordingIdByState.expired,
      claim.wordingIdByState.failed,
    ].includes(claim.wordingIdByState.satisfied)
  )
    fail(`${name} reuses its satisfied wording for a non-positive state`);
};

const assertReferencesResolve = (
  name: string,
  ids: readonly Uint16[],
  allowed: ReadonlySet<number>,
): void => {
  for (const id of ids) {
    if (!allowed.has(id)) fail(`${name} references unknown id ${id}`);
  }
};

const assertAcyclicClaimPrerequisites = (
  claims: readonly ClaimDefinitionV1[],
): void => {
  const byId = new Map(claims.map((claim) => [claim.claimId, claim]));
  const visiting = new Set<number>();
  const visited = new Set<number>();

  const visit = (claimId: number): void => {
    if (visited.has(claimId)) return;
    if (visiting.has(claimId)) fail("claim prerequisite graph must be acyclic");
    visiting.add(claimId);
    const claim = byId.get(claimId);
    if (claim === undefined) fail(`claim ${claimId} is missing`);
    for (const prerequisite of claim.prerequisiteClaimIds) visit(prerequisite);
    visiting.delete(claimId);
    visited.add(claimId);
  };

  for (const claim of claims) visit(claim.claimId);
};

export const validateClaimRegistryV1 = (registry: ClaimRegistryV1): void => {
  assertPlainExactRecord("claimRegistry", registry, CLAIM_REGISTRY_KEYS);
  if (registry.version !== 1) fail("claimRegistry has an unsupported version");
  assertArray("claimRegistry.assumptions", registry.assumptions);
  assertArray("claimRegistry.evidenceKinds", registry.evidenceKinds);
  assertArray("claimRegistry.claims", registry.claims);
  assertBytes32(
    "claimRegistry.wordingCatalogHash",
    registry.wordingCatalogHash,
  );

  for (let i = 0; i < registry.assumptions.length; i++) {
    validateClaimAssumption(registry.assumptions[i], i);
    if (
      i > 0 &&
      registry.assumptions[i - 1].assumptionId >=
        registry.assumptions[i].assumptionId
    )
      fail("claimRegistry assumptions must be sorted and duplicate-free");
  }
  for (let i = 0; i < registry.evidenceKinds.length; i++) {
    validateClaimEvidenceKind(registry.evidenceKinds[i], i);
    if (
      i > 0 &&
      registry.evidenceKinds[i - 1].evidenceKindId >=
        registry.evidenceKinds[i].evidenceKindId
    )
      fail("claimRegistry evidence kinds must be sorted and duplicate-free");
  }
  for (let i = 0; i < registry.claims.length; i++) {
    validateClaimDefinition(registry.claims[i], i);
    if (i > 0 && registry.claims[i - 1].claimId >= registry.claims[i].claimId)
      fail("claimRegistry claims must be sorted and duplicate-free");
  }

  const assumptionIds = new Set(
    registry.assumptions.map((assumption) => assumption.assumptionId),
  );
  const evidenceKindIds = new Set(
    registry.evidenceKinds.map((kind) => kind.evidenceKindId),
  );
  const claimIds = new Set(registry.claims.map((claim) => claim.claimId));

  for (const claim of registry.claims) {
    assertReferencesResolve(
      `claim ${claim.claimId} assumptions`,
      claim.assumptionIds,
      assumptionIds,
    );
    assertReferencesResolve(
      `claim ${claim.claimId} evidence kinds`,
      claim.requiredEvidenceKindIds,
      evidenceKindIds,
    );
    assertReferencesResolve(
      `claim ${claim.claimId} prerequisites`,
      claim.prerequisiteClaimIds,
      claimIds,
    );
  }
  assertAcyclicClaimPrerequisites(registry.claims);
};

const validateFormalObligation = (
  obligation: FormalObligationV1,
  index: number,
): void => {
  const name = `formalRegistry.obligations[${index}]`;
  assertPlainExactRecord(name, obligation, FORMAL_OBLIGATION_KEYS);
  assertUint16(`${name}.obligationId`, obligation.obligationId);
  if (!FORMAL_OBLIGATION_KINDS.has(obligation.kind))
    fail(`${name}.kind is unsupported`);
  assertBytes32(`${name}.modelSourceHash`, obligation.modelSourceHash);
  assertBytes32(`${name}.propertySourceHash`, obligation.propertySourceHash);
  assertBytes32(`${name}.abstractionMapHash`, obligation.abstractionMapHash);
  assertBytes32(`${name}.toolchainLockHash`, obligation.toolchainLockHash);
  assertBytes32(
    `${name}.proofScopeSchemaHash`,
    obligation.proofScopeSchemaHash,
  );
  assertKernelEntrypointId(
    `${name}.scopeCoverageEntrypointId`,
    obligation.scopeCoverageEntrypointId,
  );
  assertSortedUniqueUint16(`${name}.assumptionIds`, obligation.assumptionIds);
};

export const validateFormalObligationRegistryV1 = (
  registry: FormalObligationRegistryV1,
): void => {
  assertPlainExactRecord("formalRegistry", registry, FORMAL_REGISTRY_KEYS);
  if (registry.version !== 1) fail("formalRegistry has an unsupported version");
  assertArray("formalRegistry.obligations", registry.obligations);

  for (let i = 0; i < registry.obligations.length; i++) {
    validateFormalObligation(registry.obligations[i], i);
    if (
      i > 0 &&
      registry.obligations[i - 1].obligationId >=
        registry.obligations[i].obligationId
    )
      fail("formalRegistry obligations must be sorted and duplicate-free");
  }
};

export const validateNormativeRegistriesV1 = (
  manifest: ExecutableRendezvousKernelManifestV1,
  claimRegistry: ClaimRegistryV1,
  formalRegistry: FormalObligationRegistryV1,
): void => {
  // Structural closure only. Without the frozen canonical encoder this
  // scaffold cannot derive or authenticate any registry or release hash.
  validateExecutableRendezvousKernelManifestV1(manifest);
  validateClaimRegistryV1(claimRegistry);
  validateFormalObligationRegistryV1(formalRegistry);

  const assumptionIds = new Set(
    claimRegistry.assumptions.map((assumption) => assumption.assumptionId),
  );
  const obligationIds = new Set(
    formalRegistry.obligations.map((obligation) => obligation.obligationId),
  );

  for (const obligation of formalRegistry.obligations) {
    assertReferencesResolve(
      `formal obligation ${obligation.obligationId} assumptions`,
      obligation.assumptionIds,
      assumptionIds,
    );
  }
  for (const claim of claimRegistry.claims) {
    assertReferencesResolve(
      `claim ${claim.claimId} formal obligations`,
      claim.requiredFormalObligationIds,
      obligationIds,
    );
  }
};

/**
 * Checks the v0.4 structural publication set. This is not cryptographic
 * release conformance until a caller verifies canonically derived roots.
 */
export const validateV04ReleaseConformanceShapeV1 = (
  manifest: ExecutableRendezvousKernelManifestV1,
  claimRegistry: ClaimRegistryV1,
  formalRegistry: FormalObligationRegistryV1,
): void => {
  validateNormativeRegistriesV1(manifest, claimRegistry, formalRegistry);
  const obligationIds = new Set(
    formalRegistry.obligations.map((obligation) => obligation.obligationId),
  );
  for (const requiredId of V04_REQUIRED_FORMAL_OBLIGATION_IDS) {
    if (!obligationIds.has(requiredId))
      fail(`v0.4 release is missing formal obligation ${requiredId}`);
  }
};

const wordingIdForState = (
  wording: ClaimWordingByStateV1,
  state: ClaimEvaluationStateV1,
): Uint16 => {
  if (state === "not-implemented") return wording.notImplemented;
  if (state === "not-evaluated") return wording.notEvaluated;
  if (state === "unknown") return wording.unknown;
  if (state === "expired") return wording.expired;
  if (state === "failed") return wording.failed;
  return wording.satisfied;
};

/**
 * Validates artifact shape and its binding to caller-supplied current roots.
 * It deliberately does not verify evidence, run the predicate, or authorize
 * claim wording.
 */
export const validateClaimEvaluationShapeV1 = (
  evaluation: ClaimEvaluationV1,
  definition: ClaimDefinitionV1,
  currentRoots: CurrentClaimEvaluationRegistryRootsV1,
): void => {
  assertPlainExactRecord("claimEvaluation", evaluation, CLAIM_EVALUATION_KEYS);
  if (evaluation.version !== 1)
    fail("claimEvaluation has an unsupported version");
  assertPlainExactRecord(
    "claimEvaluation.input",
    evaluation.input,
    CLAIM_EVALUATION_INPUT_KEYS,
  );
  assertBytes32(
    "claimEvaluation.input.releaseRegistryHash",
    evaluation.input.releaseRegistryHash,
  );
  assertBytes32(
    "claimEvaluation.input.claimRegistryHash",
    evaluation.input.claimRegistryHash,
  );
  assertBytes32(
    "currentRoots.releaseRegistryHash",
    currentRoots.releaseRegistryHash,
  );
  assertBytes32(
    "currentRoots.claimRegistryHash",
    currentRoots.claimRegistryHash,
  );
  if (
    !bytesEqual(
      evaluation.input.releaseRegistryHash,
      currentRoots.releaseRegistryHash,
    )
  )
    fail("claimEvaluation does not bind the current release registry");
  if (
    !bytesEqual(
      evaluation.input.claimRegistryHash,
      currentRoots.claimRegistryHash,
    )
  )
    fail("claimEvaluation does not bind the current claim registry");
  assertUint16("claimEvaluation.input.claimId", evaluation.input.claimId);
  if (evaluation.input.claimId !== definition.claimId)
    fail("claimEvaluation uses the wrong claim definition");
  assertBytes32(
    "claimEvaluation.input.scopeDigest",
    evaluation.input.scopeDigest,
  );
  assertNonNegativeBigint(
    "claimEvaluation.input.evaluatedAtMs",
    evaluation.input.evaluatedAtMs,
  );
  assertNonNegativeBigint(
    "claimEvaluation.input.evaluationClockUncertaintyMs",
    evaluation.input.evaluationClockUncertaintyMs,
  );
  if (
    evaluation.input.evaluationClockUncertaintyMs >
    evaluation.input.evaluatedAtMs
  )
    fail("claimEvaluation uncertainty underflows the evaluation interval");
  assertBoolean(
    "claimEvaluation.input.implementationPresent",
    evaluation.input.implementationPresent,
  );
  assertBytes32(
    "claimEvaluation.input.evaluationDatasetDigest",
    evaluation.input.evaluationDatasetDigest,
  );

  if (!CLAIM_EVALUATION_STATES.has(evaluation.state))
    fail("claimEvaluation state is unsupported");
  assertSortedUniqueUint16("claimEvaluation.reasonIds", evaluation.reasonIds);
  assertUint16(
    "claimEvaluation.selectedWordingId",
    evaluation.selectedWordingId,
  );
  if (evaluation.validThroughMs !== null)
    assertNonNegativeBigint(
      "claimEvaluation.validThroughMs",
      evaluation.validThroughMs,
    );

  if (
    evaluation.selectedWordingId !==
    wordingIdForState(definition.wordingIdByState, evaluation.state)
  )
    fail("claimEvaluation selected the wrong wording for its state");
  if (definition.forbiddenWordingIds.includes(evaluation.selectedWordingId))
    fail("claimEvaluation selected forbidden wording");
  if (
    evaluation.input.implementationPresent !==
    (evaluation.state !== "not-implemented")
  )
    fail(
      "claimEvaluation implementation presence and not-implemented state must agree",
    );
  if (evaluation.state === "satisfied" && evaluation.reasonIds.length !== 0)
    fail("a satisfied claimEvaluation cannot contain failure reasons");
  if (evaluation.state !== "satisfied" && evaluation.reasonIds.length === 0)
    fail("a non-satisfied claimEvaluation must contain a reason");
  if (
    evaluation.state === "satisfied" &&
    (evaluation.validThroughMs === null ||
      evaluation.validThroughMs <= evaluation.input.evaluatedAtMs)
  )
    fail(
      "a satisfied claimEvaluation requires a future valid-through timestamp",
    );
};

export const validateFormalProofResultV1 = (
  result: FormalProofResultV1,
  obligation: FormalObligationV1,
  validationContext: FormalProofValidationContextV1,
): void => {
  assertPlainExactRecord("formalProofResult", result, FORMAL_RESULT_KEYS);
  if (result.version !== 1)
    fail("formalProofResult has an unsupported version");
  assertBytes32(
    "formalProofResult.releaseRegistryHash",
    result.releaseRegistryHash,
  );
  assertBytes32(
    "formalProofResult.formalObligationRegistryHash",
    result.formalObligationRegistryHash,
  );
  assertBytes32(
    "validationContext.releaseRegistryHash",
    validationContext.releaseRegistryHash,
  );
  assertBytes32(
    "validationContext.formalObligationRegistryHash",
    validationContext.formalObligationRegistryHash,
  );
  assertBytes32(
    "validationContext.expectedAssumptionSetHash",
    validationContext.expectedAssumptionSetHash,
  );
  if (
    !bytesEqual(
      result.releaseRegistryHash,
      validationContext.releaseRegistryHash,
    )
  )
    fail("formalProofResult does not bind the current release registry");
  if (
    !bytesEqual(
      result.formalObligationRegistryHash,
      validationContext.formalObligationRegistryHash,
    )
  )
    fail(
      "formalProofResult does not bind the current formal-obligation registry",
    );
  assertUint16("formalProofResult.obligationId", result.obligationId);
  if (result.obligationId !== obligation.obligationId)
    fail("formalProofResult uses the wrong obligation");

  const boundHashes = [
    ["modelSourceHash", obligation.modelSourceHash],
    ["propertySourceHash", obligation.propertySourceHash],
    ["abstractionMapHash", obligation.abstractionMapHash],
    ["toolchainLockHash", obligation.toolchainLockHash],
  ] as const;
  for (const [field, expected] of boundHashes) {
    const value = result[field];
    assertBytes32(`formalProofResult.${field}`, value);
    if (!bytesEqual(value, expected))
      fail(`formalProofResult.${field} does not bind the obligation`);
  }
  assertBytes32(
    "formalProofResult.assumptionSetHash",
    result.assumptionSetHash,
  );
  if (
    !bytesEqual(
      result.assumptionSetHash,
      validationContext.expectedAssumptionSetHash,
    )
  )
    fail("formalProofResult does not bind the derived assumption set");
  assertBytes32("formalProofResult.proofScopeDigest", result.proofScopeDigest);
  assertBytes32(
    "formalProofResult.implementationArtifactSetDigest",
    result.implementationArtifactSetDigest,
  );
  assertBytes32(
    "formalProofResult.canonicalTraceSetDigest",
    result.canonicalTraceSetDigest,
  );
  assertBytes32(
    "formalProofResult.schedulerWorkloadDigest",
    result.schedulerWorkloadDigest,
  );
  if (!FORMAL_PROOF_RESULTS.has(result.result))
    fail("formalProofResult result is unsupported");
  assertBytes32(
    "formalProofResult.proofArtifactDigest",
    result.proofArtifactDigest,
  );
  if (result.counterexampleTraceDigest !== null)
    assertBytes32(
      "formalProofResult.counterexampleTraceDigest",
      result.counterexampleTraceDigest,
    );
  if (
    (result.result === "counterexample") !==
    (result.counterexampleTraceDigest !== null)
  )
    fail("formalProofResult counterexample state and trace must agree");
};
