/**
 * Prototype delivery profile: the fixed per-window traffic geometry shared by
 * every client and both store servers in the server-blind rendezvous
 * prototype (design doc §4.2).
 *
 * `PROTOTYPE_DELIVERY_PROFILE_V0` is the one constant everything downstream
 * — the store server, the client adapter, and the scheduler — reads. Pinning
 * it here, next to the validator that checks it against the specification's
 * §4.3 arithmetic, means a profile that ships is a profile that has already
 * been proven geometrically self-consistent; nothing downstream re-derives or
 * re-checks that arithmetic.
 *
 * `withDeliveryWindowMs` exists because the prototype runs its local-stack
 * demo at a faster cadence than the spec's production numbers; scaling every
 * offset by the same ratio and re-validating is the only way to change the
 * window length without silently breaking one of the ordering inequalities.
 */

import { encodeCarrierEnvelope } from "../carrierEnvelope";

import type { CarrierEnvelopeV1 } from "../carrierEnvelope";
import type { PublicProfileGeometry } from "../publicWindow";

export interface AppendScheduleEntryV1 {
  readonly offsetMs: bigint;
  readonly role: "identity-bootstrap" | "safety-control" | "state-replication";
}

export interface DeliverySizeClassV1 {
  readonly id: number;
  readonly fixedCarrierObjectBytes: number;
  readonly operationPayloadClass: 0 | 1;
  readonly appendSchedule: readonly AppendScheduleEntryV1[];
  readonly publicChunksPerWindow: number;
}

export interface DeliveryProfileV1 {
  version: 1;
  carrierEnvelopeCodec: 1;
  publicStoreProtocol: 1;
  carrierAeadSuite: 1;
  admissionScheme: number;
  deliveryWindowMs: bigint;
  carrierRetentionWindows: number;
  maxFutureIngressWindows: number;
  roomSlotsPerClient: number;
  cohortAllocationsPerWindow: number;
  publicChunkObjectCount: number;
  maxScheduleSkewMs: bigint;
  tokenIssueOffsetMs: bigint;
  tokenIssueResponseBudgetMs: bigint;
  allocationRequestOffsetMs: bigint;
  allocationResponseBudgetMs: bigint;
  chunkFinalizationOffsetMs: bigint;
  publicReadLagWindows: 1;
  publicReadOffsetMs: bigint;
  maxConsecutiveMissedAppendOpportunities: number;
  sizeClasses: readonly DeliverySizeClassV1[];
  minMeasuredSharedCohort: number;
  maxAssuranceEvidenceAgeMs: bigint;
}

export const PROTOTYPE_STORE_PROTOCOL = "prototype-v0";
export const PROTOTYPE_ROUTE_PREFIX = "/p2party/prototype-v0";
export const PROTOTYPE_DESCRIPTOR_PATH =
  "/.well-known/p2party-store/prototype-v0";
export const PROTOTYPE_MEDIA_TYPE = (name: string): string =>
  `application/p2party-${name}-prototype-v0`;

/**
 * The prototype's pinned delivery profile (design doc §4.2).
 *
 * Two size classes, one per `operationPayloadClass`: class 0 carries
 * identity-bootstrap traffic alongside the safety-control and
 * state-replication roles every class must schedule, and class 1 carries the
 * larger state-replication-heavy payloads. `publicChunksPerWindow` in each
 * class is the minimum satisfying `scheduledObjects <= chunkCapacity` —
 * see the third test in `profile.test.ts`, which recomputes it independently
 * rather than trusting the literal.
 */
export const PROTOTYPE_DELIVERY_PROFILE_V0: DeliveryProfileV1 = Object.freeze({
  version: 1,
  carrierEnvelopeCodec: 1,
  publicStoreProtocol: 1,
  carrierAeadSuite: 1,
  admissionScheme: 1,
  deliveryWindowMs: 4_000n,
  carrierRetentionWindows: 160_000,
  maxFutureIngressWindows: 2,
  roomSlotsPerClient: 1,
  cohortAllocationsPerWindow: 8,
  publicChunkObjectCount: 8,
  maxScheduleSkewMs: 200n,
  tokenIssueOffsetMs: 100n,
  tokenIssueResponseBudgetMs: 300n,
  allocationRequestOffsetMs: 700n,
  allocationResponseBudgetMs: 300n,
  chunkFinalizationOffsetMs: 2_800n,
  publicReadLagWindows: 1,
  publicReadOffsetMs: 600n,
  maxConsecutiveMissedAppendOpportunities: 3,
  sizeClasses: [
    {
      id: 0,
      fixedCarrierObjectBytes: 8192,
      operationPayloadClass: 0,
      appendSchedule: [
        { offsetMs: 1_300n, role: "identity-bootstrap" },
        { offsetMs: 1_700n, role: "safety-control" },
        { offsetMs: 2_100n, role: "state-replication" },
      ],
      publicChunksPerWindow: 3,
    },
    {
      id: 1,
      fixedCarrierObjectBytes: 73_728,
      operationPayloadClass: 1,
      appendSchedule: [
        { offsetMs: 1_500n, role: "safety-control" },
        { offsetMs: 1_900n, role: "state-replication" },
      ],
      publicChunksPerWindow: 2,
    },
  ],
  minMeasuredSharedCohort: 2,
  maxAssuranceEvidenceAgeMs: 3_600_000n,
} as const) as DeliveryProfileV1;

export class ProfileGeometryError extends Error {
  override readonly name = "ProfileGeometryError";

  constructor(message: string) {
    super(`prototypeProfile: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new ProfileGeometryError(message);
};

const APPEND_SCHEDULE_ROLES = new Set<AppendScheduleEntryV1["role"]>([
  "identity-bootstrap",
  "safety-control",
  "state-replication",
]);

/** Checked `number` multiplication; the geometry fields it multiplies are
 * u16/u32 wire values, so overflow here means a corrupt profile, not a
 * legitimate count. */
const checkedMultiply = (left: number, right: number): number => {
  const product = left * right;
  if (!Number.isSafeInteger(product))
    fail("checked multiplication overflowed while sizing a size class");
  return product;
};

const roleCount = (
  appendSchedule: readonly AppendScheduleEntryV1[],
  role: AppendScheduleEntryV1["role"],
): number => appendSchedule.filter((entry) => entry.role === role).length;

/**
 * Every inequality from spec lines 5777-5825 ("For every size class, the
 * profile is valid only if: ..."), plus the preamble at 5770-5774 pinning
 * `sizeClasses` to exactly one class per `operationPayloadClass`. Throws
 * `ProfileGeometryError` on the first violation found; a caller that wants
 * every violation must fix and re-run.
 */
export const validateDeliveryProfileGeometry = (
  profile: DeliveryProfileV1,
): void => {
  const {
    deliveryWindowMs,
    maxScheduleSkewMs,
    tokenIssueOffsetMs,
    tokenIssueResponseBudgetMs,
    allocationRequestOffsetMs,
    allocationResponseBudgetMs,
    chunkFinalizationOffsetMs,
    publicReadLagWindows,
    publicReadOffsetMs,
    maxConsecutiveMissedAppendOpportunities,
    maxAssuranceEvidenceAgeMs,
    sizeClasses,
    cohortAllocationsPerWindow,
    roomSlotsPerClient,
    publicChunkObjectCount,
  } = profile;

  // Preamble (5770-5774): codec v1 fixes the class set to one class per
  // payload class, so CarrierSizeClassForPayloadClass is a total function.
  const payloadClasses = sizeClasses
    .map((sizeClass) => sizeClass.operationPayloadClass)
    .slice()
    .sort((left, right) => left - right);
  if (
    sizeClasses.length !== 2 ||
    payloadClasses[0] !== 0 ||
    payloadClasses[1] !== 1
  )
    fail(
      "sizeClasses must contain exactly two classes with operationPayloadClass values [0, 1]",
    );

  // 5793: 0 <= tokenIssueOffsetMs < deliveryWindowMs
  if (tokenIssueOffsetMs < 0n || tokenIssueOffsetMs >= deliveryWindowMs)
    fail("tokenIssueOffsetMs must fall within [0, deliveryWindowMs)");
  // 5794: 0 <= tokenIssueResponseBudgetMs
  if (tokenIssueResponseBudgetMs < 0n)
    fail("tokenIssueResponseBudgetMs must not be negative");
  // 5795-5798: the token-issue round trip plus skew precedes the allocation request
  if (
    tokenIssueOffsetMs + tokenIssueResponseBudgetMs + maxScheduleSkewMs >=
    allocationRequestOffsetMs
  )
    fail(
      "tokenIssueOffsetMs + tokenIssueResponseBudgetMs + maxScheduleSkewMs must be less than allocationRequestOffsetMs",
    );
  // 5799: 0 <= allocationRequestOffsetMs < deliveryWindowMs
  if (
    allocationRequestOffsetMs < 0n ||
    allocationRequestOffsetMs >= deliveryWindowMs
  )
    fail("allocationRequestOffsetMs must fall within [0, deliveryWindowMs)");
  // 5800: 0 <= allocationResponseBudgetMs
  if (allocationResponseBudgetMs < 0n)
    fail("allocationResponseBudgetMs must not be negative");
  // 5801-5804: the allocation round trip plus skew fits inside the delivery window
  if (
    allocationRequestOffsetMs +
      allocationResponseBudgetMs +
      maxScheduleSkewMs >=
    deliveryWindowMs
  )
    fail(
      "allocationRequestOffsetMs + allocationResponseBudgetMs + maxScheduleSkewMs must be less than deliveryWindowMs",
    );
  // 5812: 0 < chunkFinalizationOffsetMs < deliveryWindowMs
  if (
    chunkFinalizationOffsetMs <= 0n ||
    chunkFinalizationOffsetMs >= deliveryWindowMs
  )
    fail("chunkFinalizationOffsetMs must fall within (0, deliveryWindowMs)");
  // 5813-5814: finalization plus skew precedes the next window's public read
  if (
    chunkFinalizationOffsetMs + maxScheduleSkewMs >=
    deliveryWindowMs + publicReadOffsetMs
  )
    fail(
      "chunkFinalizationOffsetMs + maxScheduleSkewMs must be less than deliveryWindowMs + publicReadOffsetMs",
    );
  // 5815: 0 <= publicReadOffsetMs < deliveryWindowMs
  if (publicReadOffsetMs < 0n || publicReadOffsetMs >= deliveryWindowMs)
    fail("publicReadOffsetMs must fall within [0, deliveryWindowMs)");
  // 5816: publicReadLagWindows == 1
  if (publicReadLagWindows !== 1)
    fail("publicReadLagWindows must be exactly 1");
  // 5819: maxConsecutiveMissedAppendOpportunities is a non-negative safe integer
  if (
    !Number.isSafeInteger(maxConsecutiveMissedAppendOpportunities) ||
    maxConsecutiveMissedAppendOpportunities < 0
  )
    fail(
      "maxConsecutiveMissedAppendOpportunities must be a non-negative safe integer",
    );
  // 5820: 0 < maxAssuranceEvidenceAgeMs
  if (maxAssuranceEvidenceAgeMs <= 0n)
    fail("maxAssuranceEvidenceAgeMs must be positive");

  for (const sizeClass of sizeClasses) {
    const { id, appendSchedule, operationPayloadClass, publicChunksPerWindow } =
      sizeClass;

    // 5809, 5817-5818: every offset is non-negative, offsets are strictly
    // increasing (sorted and unique), and every role is the closed enum.
    for (let index = 0; index < appendSchedule.length; index++) {
      const entry = appendSchedule[index];
      if (entry.offsetMs < 0n)
        fail(
          `size class ${String(id)}: every appendSchedule.offsetMs must be non-negative`,
        );
      if (!APPEND_SCHEDULE_ROLES.has(entry.role))
        fail(
          `size class ${String(id)}: appendSchedule role must be a closed value`,
        );
      if (index > 0 && appendSchedule[index - 1].offsetMs >= entry.offsetMs)
        fail(
          `size class ${String(id)}: appendSchedule must be sorted by strictly increasing offsetMs`,
        );
    }

    // 5822-5824: required roles. An empty schedule fails here (both counts
    // are 0), so the offset-dependent checks below may assume a non-empty,
    // sorted appendSchedule.
    if (
      operationPayloadClass === 0 &&
      roleCount(appendSchedule, "identity-bootstrap") < 1
    )
      fail(
        `size class ${String(id)}: operationPayloadClass 0 requires at least one identity-bootstrap append`,
      );
    if (roleCount(appendSchedule, "safety-control") < 1)
      fail(
        `size class ${String(id)}: requires at least one safety-control append`,
      );
    if (roleCount(appendSchedule, "state-replication") < 1)
      fail(
        `size class ${String(id)}: requires at least one state-replication append`,
      );

    // 5781-5791: scheduledObjects <= chunkCapacity, and publicChunksPerWindow
    // is the minimum integer satisfying that inequality.
    const scheduledObjects = checkedMultiply(
      checkedMultiply(cohortAllocationsPerWindow, roomSlotsPerClient),
      appendSchedule.length,
    );
    const chunkCapacity = checkedMultiply(
      publicChunksPerWindow,
      publicChunkObjectCount,
    );
    if (scheduledObjects > chunkCapacity)
      fail(
        `size class ${String(id)}: publicChunksPerWindow is too small for scheduledObjects`,
      );
    const minimalChunksPerWindow = Math.ceil(
      scheduledObjects / publicChunkObjectCount,
    );
    if (publicChunksPerWindow !== minimalChunksPerWindow)
      fail(
        `size class ${String(id)}: publicChunksPerWindow must be the minimum integer satisfying scheduledObjects <= chunkCapacity`,
      );

    // 5805-5808: the allocation round trip plus skew precedes this class's
    // earliest append. appendSchedule is sorted above, so its first entry is
    // the minimum.
    const earliestAppendOffsetMs = appendSchedule[0].offsetMs;
    if (
      allocationRequestOffsetMs +
        allocationResponseBudgetMs +
        maxScheduleSkewMs >=
      earliestAppendOffsetMs
    )
      fail(
        `size class ${String(id)}: allocationRequestOffsetMs + allocationResponseBudgetMs + maxScheduleSkewMs must be less than the earliest appendSchedule.offsetMs`,
      );

    // 5810-5811: every append plus skew precedes chunk finalization.
    for (const entry of appendSchedule) {
      if (entry.offsetMs + maxScheduleSkewMs >= chunkFinalizationOffsetMs)
        fail(
          `size class ${String(id)}: every appendSchedule.offsetMs + maxScheduleSkewMs must be less than chunkFinalizationOffsetMs`,
        );
    }
  }
};

/** The size-class geometry a profile fixes, projected for the public-window
 * layer (`publicWindow.ts`), which never needs the full room-facing fields. */
export const profileGeometry = (
  profile: DeliveryProfileV1,
): PublicProfileGeometry => ({
  publicChunkObjectCount: profile.publicChunkObjectCount,
  cohortAllocationsPerWindow: profile.cohortAllocationsPerWindow,
  roomSlotsPerClient: profile.roomSlotsPerClient,
  sizeClasses: profile.sizeClasses.map((sizeClass) => ({
    id: sizeClass.id,
    appendScheduleLength: sizeClass.appendSchedule.length,
    publicChunksPerWindow: sizeClass.publicChunksPerWindow,
  })),
});

/** `CarrierSizeClassForPayloadClass(payloadClass)` (5772-5773): a total
 * function once the profile has passed `validateDeliveryProfileGeometry`. */
export const sizeClassForPayloadClass = (
  profile: DeliveryProfileV1,
  payloadClass: 0 | 1,
): DeliverySizeClassV1 => {
  const found = profile.sizeClasses.find(
    (sizeClass) => sizeClass.operationPayloadClass === payloadClass,
  );
  if (found === undefined)
    fail(`no size class defines operationPayloadClass ${String(payloadClass)}`);
  return found;
};

/**
 * The exact wire length of one carrier object in this size class: the
 * canonical `CarrierEnvelopeV1` encoding of a zeroed envelope whose
 * ciphertext-and-tag body is the class's `fixedCarrierObjectBytes`. Building
 * the envelope literally and delegating to `encodeCarrierEnvelope` means this
 * never drifts from the wire codec, unlike a hand-maintained constant would.
 */
export const carrierObjectWireBytes = (
  profile: DeliveryProfileV1,
  sizeClassId: number,
  profileHash: Uint8Array,
): number => {
  const sizeClass = profile.sizeClasses.find(
    (candidate) => candidate.id === sizeClassId,
  );
  if (sizeClass === undefined)
    fail(`no size class with id ${String(sizeClassId)} in this profile`);

  const envelope: CarrierEnvelopeV1 = {
    version: 1,
    deliveryProfileHash: profileHash,
    ingressWindow: 0n,
    sizeClass: sizeClassId,
    carrierContextId: new Uint8Array(32),
    nonce: new Uint8Array(24),
    ciphertextAndTag: new Uint8Array(sizeClass.fixedCarrierObjectBytes),
  };
  return encodeCarrierEnvelope(envelope).length;
};

/**
 * Scale every schedule offset (and `maxAssuranceEvidenceAgeMs`) by
 * `deliveryWindowMs / profile.deliveryWindowMs` and re-validate.
 *
 * The prototype's local-stack demo runs the profile at a faster cadence than
 * the spec's production numbers; scaling every offset by the same ratio is
 * the only way to change the window length without silently breaking one of
 * the ordering inequalities checked above.
 */
export const withDeliveryWindowMs = (
  profile: DeliveryProfileV1,
  deliveryWindowMs: bigint,
): DeliveryProfileV1 => {
  const previousDeliveryWindowMs = profile.deliveryWindowMs;
  if (previousDeliveryWindowMs <= 0n)
    fail("profile.deliveryWindowMs must be positive to rescale from");
  if (deliveryWindowMs <= 0n) fail("deliveryWindowMs must be positive");

  const scale = (offsetMs: bigint): bigint =>
    (offsetMs * deliveryWindowMs) / previousDeliveryWindowMs;

  const scaled: DeliveryProfileV1 = {
    ...profile,
    deliveryWindowMs,
    maxScheduleSkewMs: scale(profile.maxScheduleSkewMs),
    tokenIssueOffsetMs: scale(profile.tokenIssueOffsetMs),
    tokenIssueResponseBudgetMs: scale(profile.tokenIssueResponseBudgetMs),
    allocationRequestOffsetMs: scale(profile.allocationRequestOffsetMs),
    allocationResponseBudgetMs: scale(profile.allocationResponseBudgetMs),
    chunkFinalizationOffsetMs: scale(profile.chunkFinalizationOffsetMs),
    publicReadOffsetMs: scale(profile.publicReadOffsetMs),
    maxAssuranceEvidenceAgeMs: scale(profile.maxAssuranceEvidenceAgeMs),
    sizeClasses: profile.sizeClasses.map((sizeClass) => ({
      ...sizeClass,
      appendSchedule: sizeClass.appendSchedule.map((entry) => ({
        ...entry,
        offsetMs: scale(entry.offsetMs),
      })),
    })),
  };

  validateDeliveryProfileGeometry(scaled);
  return scaled;
};
