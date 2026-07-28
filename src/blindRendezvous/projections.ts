/**
 * Generated projections of the canonical binary schema.
 *
 * REQ-024 and AC-047 make this indirection mandatory rather than stylistic:
 * types, codecs, fixtures, protocol tables, and UI claim keys are projections
 * of the schema, never a second hand-maintained authority. A validator that
 * kept its own key list would silently disagree with the wire format the day
 * one field is added.
 *
 * Everything here is derived by `recordFieldNames`/`enumValues` at module load
 * from `schemas.ts`. There is nothing to keep in sync by hand, which is the
 * point: `tests/blindRendezvous/projections.test.ts` proves the derivation
 * covers every validator table and every specified field.
 */

import {
  enumValues,
  recordFieldNames,
  recordFieldType,
  unionVariantType,
} from "./canonicalSchema";
import {
  authenticatedRoomOperationV1Schema,
  carrierEnvelopeV1Schema,
  claimAssumptionKindV1Schema,
  claimAssumptionV1Schema,
  claimDefinitionV1Schema,
  claimEvaluationInputV1Schema,
  claimEvaluationStateV1Schema,
  claimEvaluationV1Schema,
  claimEvidenceKindV1Schema,
  claimRegistryV1Schema,
  claimScopeKindV1Schema,
  claimWordingByStateV1Schema,
  deliveryProfileV1Schema,
  executableRendezvousKernelManifestV1Schema,
  executableRendezvousKernelModuleV1Schema,
  formalObligationKindV1Schema,
  formalObligationRegistryV1Schema,
  formalObligationV1Schema,
  formalProofResultKindV1Schema,
  formalProofResultV1Schema,
  kernelEntrypointV1Schema,
  operationKindV1Schema,
  operationLifetimeV1Schema,
  pairBootstrapHeaderV1Schema,
  pairStepEnvelopeV1Schema,
  roomPolicyV4Schema,
} from "./schemas";

import type { TypeDescriptor } from "./canonicalSchema";

const keySet = (descriptor: TypeDescriptor): ReadonlySet<string> =>
  new Set(recordFieldNames(descriptor));

const variantKeySet = (
  descriptor: TypeDescriptor,
  tag: string,
): ReadonlySet<string> => keySet(unionVariantType(descriptor, tag));

const claimAssumptionVerification = recordFieldType(
  claimAssumptionV1Schema,
  "verification",
);

/* Section 4.0 — executable kernel */

export const KERNEL_MANIFEST_KEYS = keySet(
  executableRendezvousKernelManifestV1Schema,
);
export const KERNEL_MODULE_KEYS = keySet(
  executableRendezvousKernelModuleV1Schema,
);
export const KERNEL_ENTRYPOINT_KEYS = keySet(kernelEntrypointV1Schema);

/* Section 4.0 — claim registry */

export const CLAIM_REGISTRY_KEYS = keySet(claimRegistryV1Schema);
export const CLAIM_ASSUMPTION_KEYS = keySet(claimAssumptionV1Schema);
export const CLAIM_EVIDENCE_KIND_KEYS = keySet(claimEvidenceKindV1Schema);
export const CLAIM_DEFINITION_KEYS = keySet(claimDefinitionV1Schema);
export const CLAIM_WORDING_KEY_LIST = recordFieldNames(
  claimWordingByStateV1Schema,
);
export const CLAIM_WORDING_KEYS = keySet(claimWordingByStateV1Schema);
export const CLAIM_EVALUATION_KEYS = keySet(claimEvaluationV1Schema);
export const CLAIM_EVALUATION_INPUT_KEYS = keySet(claimEvaluationInputV1Schema);

export const CLAIM_ASSUMPTION_FOUNDATIONAL_VERIFICATION_KEYS = variantKeySet(
  claimAssumptionVerification,
  "declared-foundational",
);

export const CLAIM_ASSUMPTION_EVIDENCE_VERIFICATION_KEYS = variantKeySet(
  claimAssumptionVerification,
  "evidence-verified",
);

/* Section 4.0 — formal obligations */

export const FORMAL_REGISTRY_KEYS = keySet(formalObligationRegistryV1Schema);
export const FORMAL_OBLIGATION_KEYS = keySet(formalObligationV1Schema);
export const FORMAL_RESULT_KEYS = keySet(formalProofResultV1Schema);

/* Sections 4.1, 4.4, 4.5 — protocol objects */

export const ROOM_POLICY_V4_KEYS = keySet(roomPolicyV4Schema);
export const DELIVERY_PROFILE_V1_KEYS = keySet(deliveryProfileV1Schema);
export const AUTHENTICATED_ROOM_OPERATION_V1_KEYS = keySet(
  authenticatedRoomOperationV1Schema,
);
export const PAIR_BOOTSTRAP_HEADER_V1_KEYS = keySet(
  pairBootstrapHeaderV1Schema,
);
export const PAIR_STEP_ENVELOPE_V1_KEYS = keySet(pairStepEnvelopeV1Schema);
export const CARRIER_ENVELOPE_V1_KEYS = keySet(carrierEnvelopeV1Schema);

/* Closed enumerations.
 *
 * `*_ORDER` preserves wire-byte order, which is protocol-visible and may not be
 * rearranged. `*_SET` is the membership projection validators use; deriving
 * both from one descriptor keeps a validator from accepting a member the codec
 * cannot encode. */

const ordered = <T extends string>(descriptor: TypeDescriptor): readonly T[] =>
  enumValues(descriptor) as readonly T[];

export const CLAIM_EVALUATION_STATES_ORDER = ordered(
  claimEvaluationStateV1Schema,
);
export const CLAIM_SCOPE_KINDS_ORDER = ordered(claimScopeKindV1Schema);
export const CLAIM_ASSUMPTION_KINDS_ORDER = ordered(
  claimAssumptionKindV1Schema,
);
export const FORMAL_OBLIGATION_KINDS_ORDER = ordered(
  formalObligationKindV1Schema,
);
export const FORMAL_PROOF_RESULTS_ORDER = ordered(
  formalProofResultKindV1Schema,
);
export const OPERATION_KINDS_ORDER = ordered(operationKindV1Schema);
export const OPERATION_LIFETIMES_ORDER = ordered(operationLifetimeV1Schema);

export const CLAIM_EVALUATION_STATES: ReadonlySet<string> = new Set(
  CLAIM_EVALUATION_STATES_ORDER,
);
export const CLAIM_SCOPE_KINDS: ReadonlySet<string> = new Set(
  CLAIM_SCOPE_KINDS_ORDER,
);
export const CLAIM_ASSUMPTION_KINDS: ReadonlySet<string> = new Set(
  CLAIM_ASSUMPTION_KINDS_ORDER,
);
export const FORMAL_OBLIGATION_KINDS: ReadonlySet<string> = new Set(
  FORMAL_OBLIGATION_KINDS_ORDER,
);
export const FORMAL_PROOF_RESULTS: ReadonlySet<string> = new Set(
  FORMAL_PROOF_RESULTS_ORDER,
);
export const OPERATION_KINDS: ReadonlySet<string> = new Set(
  OPERATION_KINDS_ORDER,
);
export const OPERATION_LIFETIMES: ReadonlySet<string> = new Set(
  OPERATION_LIFETIMES_ORDER,
);
