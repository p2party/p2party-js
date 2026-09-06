/**
 * Exact local persistence boundary for retained blind-rendezvous operations.
 *
 * This is a local storage schema, not a wire format and not part of the
 * normative release registry. It preserves the exact canonical operation
 * bytes needed by the existing operation validator and CoreReduce after a
 * restart; it deliberately performs neither of those protocol validations.
 *
 * One immutable content row stores each exact operation once per room. A
 * per-room/window manifest names the complete sorted unique room-wide row set
 * visible at that historical decision boundary and fences its physical
 * count/bytes. This intentionally simple representation makes omission and
 * overcapacity explicit. A later database adapter may change its physical
 * layout without changing this source-internal contract.
 */

import { snapshotByteInput } from "../cryptography/byteInput";
import {
  MAX_CANONICAL_ENCODING_BYTES,
  MAX_U16_COLLECTION_ENTRIES,
  array,
  bytes32,
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
  enumOf,
  optional,
  record,
  u8,
  u32,
  u64,
} from "./canonicalSchema";
import { decodeOperation, deriveOperationId } from "./operation";

const U64_MAX = 0xffffffffffffffffn;

export type RetainedOperationManifestCompletenessV1 =
  "complete" | "incomplete-overcapacity";

/**
 * Canonical local manifest for one room/window historical replay fence.
 *
 * `operationIds` names the complete room-wide unique retained-operation set,
 * not an endpoint subset and not a decoded Core projection. Therefore the
 * byte total charges a shared content row once regardless of how many window
 * manifests reference it.
 */
export interface RetainedOperationWindowManifestV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly referenceWindow: bigint;
  readonly retainThroughLogicalWindow: bigint;
  readonly completeness: RetainedOperationManifestCompletenessV1;
  readonly operationIds: readonly Uint8Array[];
  readonly retainedOperationCount: number;
  readonly retainedOperationBytes: bigint;
  readonly maxRetainedValidOperationsPerRoom: number;
  readonly maxRetainedValidOperationBytesPerRoom: bigint;
  /** The first unique row rejected at the public capacity boundary. */
  readonly firstRejectedOperationId: Uint8Array | null;
}

/**
 * Immutable content-addressed row. Room membership is supplied only by the
 * trusted outer-validation/store transition; this module can prove the
 * OperationId/bytes relation but cannot infer RoomContextId from an operation.
 */
export interface RetainedOperationContentRowV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly operationId: Uint8Array;
  readonly exactOperationBytes: Uint8Array;
}

export interface RetainedOperationWindowLocatorV1 {
  readonly version: 1;
  readonly roomContextId: Uint8Array;
  readonly referenceWindow: bigint;
}

/** Exact absence is replay-unavailable, never an empty complete manifest. */
export type ExactRetainedOperationManifestRowV1 =
  | {
      readonly kind: "absent";
    }
  | {
      readonly kind: "present";
      readonly exactManifestBytes: Uint8Array;
      /** Non-reused adapter revision used to prevent ABA. */
      readonly recordRevision: bigint;
    };

/**
 * Exact rows copied by one future read-only transaction.
 *
 * For a present manifest, `operations` must contain exactly one row for every
 * named ID and no other row. Missing rows are represented by omission and fail
 * validation; an absent manifest must have an empty row list.
 */
export interface RetainedOperationWindowExactCaptureV1 {
  readonly manifest: ExactRetainedOperationManifestRowV1;
  readonly operations: readonly RetainedOperationContentRowV1[];
}

export type ValidatedRetainedOperationWindowCaptureV1 =
  | {
      readonly kind: "unavailable";
    }
  | {
      readonly kind: "available";
      readonly exactManifestRow: Extract<
        ExactRetainedOperationManifestRowV1,
        { readonly kind: "present" }
      >;
      readonly manifest: RetainedOperationWindowManifestV1;
      readonly operations: readonly RetainedOperationContentRowV1[];
    };

export interface InitializeRetainedOperationWindowOptionsV1 {
  readonly roomContextId: Uint8Array;
  readonly referenceWindow: bigint;
  readonly retainThroughLogicalWindow: bigint;
  readonly maxRetainedValidOperationsPerRoom: number;
  readonly maxRetainedValidOperationBytesPerRoom: bigint;
}

export type PreparedRetainedOperationStoreMutationV1 =
  | {
      readonly kind: "initialize-window";
      readonly exactNextManifestBytes: Uint8Array;
    }
  | {
      readonly kind: "insert-operation-and-replace-manifest";
      readonly operation: RetainedOperationContentRowV1;
      readonly exactNextManifestBytes: Uint8Array;
    }
  | {
      readonly kind: "mark-incomplete-overcapacity";
      readonly firstRejectedOperationId: Uint8Array;
      readonly exactNextManifestBytes: Uint8Array;
    };

/**
 * Closed future CAS request. The adapter compares the exact manifest
 * bytes/revision and every expected content row before applying the mutation.
 * Admission mutations additionally require the candidate content key to be
 * absent; finding it without the matching manifest is a conflict/corruption,
 * not an invitation to repair state heuristically.
 */
export interface RetainedOperationStoreCasRequestV1 {
  readonly version: 1;
  readonly locator: RetainedOperationWindowLocatorV1;
  readonly expected: RetainedOperationWindowExactCaptureV1;
  readonly candidateOperationId: Uint8Array | null;
  readonly mutation: PreparedRetainedOperationStoreMutationV1;
}

export type RetainedOperationStoreCasResultV1 =
  | {
      readonly status: "committed";
      readonly exactManifestRow: Extract<
        ExactRetainedOperationManifestRowV1,
        { readonly kind: "present" }
      >;
    }
  | {
      readonly status: "conflict";
      readonly fence: "manifest" | "operation";
    };

/**
 * Source-internal byte-store port for the later IndexedDB adapter.
 *
 * `readExactWindowCapture` must own all returned buffers and resolve only
 * after its read transaction completes. `compareAndSwap` performs no crypto
 * and awaits no promise while its write transaction is live.
 *
 * @internal
 */
export interface RetainedOperationStorePortV1 {
  readExactWindowCapture(
    locator: RetainedOperationWindowLocatorV1,
  ): Promise<RetainedOperationWindowExactCaptureV1>;

  compareAndSwap(
    request: RetainedOperationStoreCasRequestV1,
  ): Promise<RetainedOperationStoreCasResultV1>;
}

export type RetainedOperationAdmissionPlanV1 =
  | {
      readonly kind: "unavailable";
    }
  | {
      readonly kind: "duplicate";
    }
  | {
      readonly kind: "sticky-incomplete-overcapacity";
      readonly firstRejectedOperationId: Uint8Array;
    }
  | {
      readonly kind: "accept-operation";
      readonly request: RetainedOperationStoreCasRequestV1;
    }
  | {
      readonly kind: "mark-incomplete-overcapacity";
      readonly request: RetainedOperationStoreCasRequestV1;
    };

export class RetainedOperationStoreError extends Error {
  override readonly name = "RetainedOperationStoreError";

  constructor(message: string) {
    super(`retainedOperationStore: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new RetainedOperationStoreError(message);
};

/*
 * Deliberately module-local. Registering this descriptor in schemas.ts would
 * incorrectly turn an evolvable storage representation into protocol bytes.
 */
const retainedOperationWindowManifestV1Schema = record(
  "LocalRetainedOperationWindowManifestV1",
  [
    { name: "version", type: u8 },
    { name: "roomContextId", type: bytes32 },
    { name: "referenceWindow", type: u64 },
    { name: "retainThroughLogicalWindow", type: u64 },
    {
      name: "completeness",
      type: enumOf("LocalRetainedOperationManifestCompletenessV1", [
        "complete",
        "incomplete-overcapacity",
      ]),
    },
    {
      name: "operationIds",
      type: array(bytes32, MAX_U16_COLLECTION_ENTRIES, "sorted-unique"),
    },
    { name: "retainedOperationCount", type: u32 },
    { name: "retainedOperationBytes", type: u64 },
    { name: "maxRetainedValidOperationsPerRoom", type: u32 },
    { name: "maxRetainedValidOperationBytesPerRoom", type: u64 },
    { name: "firstRejectedOperationId", type: optional(bytes32) },
  ],
);

const hasExactOwnDataFields = (
  value: unknown,
  expectedFields: readonly string[],
): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedFields.length ||
    keys.some((key) => typeof key !== "string" || !expectedFields.includes(key))
  )
    return false;
  return expectedFields.every((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return (
      descriptor !== undefined && descriptor.enumerable && "value" in descriptor
    );
  });
};

const ownDenseArrayValues = (
  value: unknown,
  label: string,
): readonly unknown[] => {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype)
    return fail(`${label} must be a plain array`);
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys[keys.length - 1] !== "length" ||
    value.length > MAX_U16_COLLECTION_ENTRIES
  )
    return fail(`${label} must be a bounded dense array`);

  const entries: unknown[] = [];
  for (let index = 0; index < value.length; index++) {
    if (keys[index] !== String(index))
      return fail(`${label} must be a bounded dense array`);
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    )
      return fail(`${label} must contain only data elements`);
    entries.push(descriptor.value);
  }
  return entries;
};

const ownBytes = (
  value: unknown,
  label: string,
  exactLength?: number,
): Uint8Array => {
  try {
    const bytes = snapshotByteInput(
      value,
      `retainedOperationStore: ${label}`,
      exactLength === undefined
        ? { maximumLength: MAX_CANONICAL_ENCODING_BYTES }
        : { exactLength },
    );
    if (exactLength === undefined && bytes.length === 0)
      return fail(`${label} must not be empty`);
    return bytes;
  } catch (error) {
    if (error instanceof RetainedOperationStoreError) throw error;
    return fail(error instanceof Error ? error.message : `${label} is invalid`);
  }
};

const requireU64 = (value: unknown, label: string): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return fail(`${label} must be an unsigned 64-bit integer`);
  return value;
};

const requirePositiveManifestCountCap = (value: unknown): number => {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAX_U16_COLLECTION_ENTRIES
  )
    return fail(
      `maxRetainedValidOperationsPerRoom must be within [1, ${String(
        MAX_U16_COLLECTION_ENTRIES,
      )}]`,
    );
  return value;
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const validateManifestSemantics = (
  manifest: RetainedOperationWindowManifestV1,
): void => {
  if (manifest.version !== 1) fail("unsupported manifest version");
  if (manifest.referenceWindow > manifest.retainThroughLogicalWindow)
    fail("manifest retention ends before its reference window");
  requirePositiveManifestCountCap(manifest.maxRetainedValidOperationsPerRoom);
  if (manifest.maxRetainedValidOperationBytesPerRoom <= 0n)
    fail("maxRetainedValidOperationBytesPerRoom must be positive");
  if (manifest.retainedOperationCount !== manifest.operationIds.length)
    fail("manifest operation count does not match its exact ID set");
  if (
    (manifest.retainedOperationCount === 0) !==
    (manifest.retainedOperationBytes === 0n)
  )
    fail("manifest count and byte total disagree about an empty set");

  if (manifest.completeness === "complete") {
    if (manifest.firstRejectedOperationId !== null)
      fail("a complete manifest cannot name a rejected operation");
    if (
      manifest.retainedOperationCount >=
        manifest.maxRetainedValidOperationsPerRoom ||
      manifest.retainedOperationBytes >=
        manifest.maxRetainedValidOperationBytesPerRoom
    )
      fail("a complete manifest is at or beyond a configured capacity");
    return;
  }

  const rejected = manifest.firstRejectedOperationId;
  if (rejected === null)
    fail("an incomplete-overcapacity manifest needs its first rejected ID");
  const rejectedOperationId = rejected;
  if (
    manifest.operationIds.some((operationId) =>
      bytesEqual(operationId, rejectedOperationId),
    )
  )
    fail("the first rejected operation is already retained");
};

/**
 * Encode one strict local manifest. The descriptor is intentionally not
 * exported and the bytes carry no interoperability or protocol provenance.
 */
export const encodeRetainedOperationWindowManifestV1 = (
  value: RetainedOperationWindowManifestV1,
): Uint8Array => {
  try {
    const encoded = encodeCanonical(
      retainedOperationWindowManifestV1Schema,
      value,
    );
    const decoded = decodeCanonicalStrict(
      retainedOperationWindowManifestV1Schema,
      encoded,
    ) as RetainedOperationWindowManifestV1;
    validateManifestSemantics(decoded);
    return encoded;
  } catch (error) {
    if (error instanceof RetainedOperationStoreError) throw error;
    return fail(
      error instanceof Error ? error.message : "manifest encoding failed",
    );
  }
};

/** Decode, own, and semantically validate one exact local manifest. */
export const decodeRetainedOperationWindowManifestV1 = (
  exactBytes: Uint8Array,
): RetainedOperationWindowManifestV1 => {
  const ownedBytes = ownBytes(exactBytes, "exact manifest bytes");
  try {
    const decoded = decodeCanonicalStrict(
      retainedOperationWindowManifestV1Schema,
      ownedBytes,
    ) as RetainedOperationWindowManifestV1;
    validateManifestSemantics(decoded);
    return decoded;
  } catch (error) {
    if (error instanceof RetainedOperationStoreError) throw error;
    return fail(
      error instanceof Error ? error.message : "manifest decoding failed",
    );
  }
};

const ownContentRowShape = (
  value: unknown,
  label: string,
): RetainedOperationContentRowV1 => {
  if (
    !hasExactOwnDataFields(value, [
      "version",
      "roomContextId",
      "operationId",
      "exactOperationBytes",
    ])
  )
    return fail(`${label} must contain exactly the content-row fields`);
  if (value.version !== 1) return fail(`${label} has an unsupported version`);
  return {
    version: 1,
    roomContextId: ownBytes(
      value.roomContextId,
      `${label} room context ID`,
      32,
    ),
    operationId: ownBytes(value.operationId, `${label} operation ID`, 32),
    exactOperationBytes: ownBytes(
      value.exactOperationBytes,
      `${label} exact operation bytes`,
    ),
  };
};

const validateOwnedContentRowAssociation = async (
  row: RetainedOperationContentRowV1,
): Promise<void> => {
  let operation;
  try {
    operation = decodeOperation(row.exactOperationBytes);
  } catch (error) {
    return fail(
      `exact operation bytes are not canonical: ${
        error instanceof Error ? error.message : "decode failed"
      }`,
    );
  }

  let derivedOperationId: Uint8Array;
  try {
    derivedOperationId = await deriveOperationId(operation);
  } catch (error) {
    return fail(
      `operation ID derivation failed: ${
        error instanceof Error ? error.message : "unknown error"
      }`,
    );
  }
  if (!bytesEqual(derivedOperationId, row.operationId))
    fail("operation ID does not address the exact operation bytes");
};

/**
 * Own one content row and prove only its canonical bytes/OperationId
 * association. This is not signature, room, policy, temporal, or Core
 * validation.
 */
export const validateAndCopyRetainedOperationContentRowV1 = async (
  value: unknown,
): Promise<RetainedOperationContentRowV1> => {
  const row = ownContentRowShape(value, "operation row");
  await validateOwnedContentRowAssociation(row);
  return row;
};

const ownManifestRow = (
  value: unknown,
): ExactRetainedOperationManifestRowV1 => {
  if (hasExactOwnDataFields(value, ["kind"]) && value.kind === "absent")
    return { kind: "absent" };
  if (
    !hasExactOwnDataFields(value, [
      "kind",
      "exactManifestBytes",
      "recordRevision",
    ]) ||
    value.kind !== "present"
  )
    return fail("manifest row must be exact present/absent state");
  return {
    kind: "present",
    exactManifestBytes: ownBytes(
      value.exactManifestBytes,
      "exact manifest row bytes",
    ),
    recordRevision: requireU64(value.recordRevision, "manifest recordRevision"),
  };
};

interface OwnedCaptureShape {
  readonly manifestRow: ExactRetainedOperationManifestRowV1;
  readonly manifest: RetainedOperationWindowManifestV1 | null;
  readonly operations: readonly RetainedOperationContentRowV1[];
}

const ownCaptureShape = (value: unknown): OwnedCaptureShape => {
  if (!hasExactOwnDataFields(value, ["manifest", "operations"]))
    return fail("capture must contain exactly manifest and operations");
  const manifestRow = ownManifestRow(value.manifest);
  const operationValues = ownDenseArrayValues(
    value.operations,
    "capture operations",
  );
  const operations = operationValues.map((operation, index) =>
    ownContentRowShape(operation, `capture operation ${String(index)}`),
  );

  for (let index = 1; index < operations.length; index++) {
    const order = compareBytes(
      operations[index - 1].operationId,
      operations[index].operationId,
    );
    if (order >= 0)
      return fail(
        order === 0
          ? "capture operation rows must be duplicate-free"
          : "capture operation rows must be sorted by operation ID",
      );
  }

  if (manifestRow.kind === "absent") {
    if (operations.length !== 0)
      return fail("an absent manifest cannot expose operation rows");
    return { manifestRow, manifest: null, operations };
  }
  const manifest = decodeRetainedOperationWindowManifestV1(
    manifestRow.exactManifestBytes,
  );
  return { manifestRow, manifest, operations };
};

/**
 * Own and correlate a complete future adapter capture.
 *
 * All caller-controlled buffers are copied before the first OperationId hash
 * await. A present capture is rejected for missing, extra, duplicate,
 * misaddressed, cross-room, or mis-accounted rows. An absent manifest becomes
 * explicitly unavailable.
 */
const validateOwnedWindowCapture = async (
  owned: OwnedCaptureShape,
): Promise<ValidatedRetainedOperationWindowCaptureV1> => {
  if (owned.manifestRow.kind === "absent") return { kind: "unavailable" };

  const manifest = owned.manifest;
  if (manifest === null)
    return fail("present manifest row lost its decoded manifest");
  if (manifest.operationIds.length !== owned.operations.length)
    return fail("manifest and capture operation-row counts differ");

  let retainedBytes = 0n;
  for (let index = 0; index < owned.operations.length; index++) {
    const row = owned.operations[index];
    if (!bytesEqual(row.roomContextId, manifest.roomContextId))
      return fail("captured operation row belongs to another room");
    if (!bytesEqual(row.operationId, manifest.operationIds[index]))
      return fail("captured operation rows do not match the manifest ID set");
    retainedBytes += BigInt(row.exactOperationBytes.length);
    if (retainedBytes > U64_MAX)
      return fail("captured operation byte total overflowed u64");
  }
  if (
    manifest.retainedOperationCount !== owned.operations.length ||
    manifest.retainedOperationBytes !== retainedBytes
  )
    return fail("manifest retained-operation resource totals are not exact");

  // The entire untrusted capture was synchronously owned above.
  for (const row of owned.operations)
    await validateOwnedContentRowAssociation(row);

  return {
    kind: "available",
    exactManifestRow: owned.manifestRow,
    manifest,
    operations: owned.operations,
  };
};

export const validateAndCopyRetainedOperationWindowExactCaptureV1 = async (
  value: unknown,
): Promise<ValidatedRetainedOperationWindowCaptureV1> =>
  validateOwnedWindowCapture(ownCaptureShape(value));

const copyContentRow = (
  row: RetainedOperationContentRowV1,
): RetainedOperationContentRowV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(row.roomContextId),
  operationId: Uint8Array.from(row.operationId),
  exactOperationBytes: Uint8Array.from(row.exactOperationBytes),
});

const copyExactCapture = (
  capture: Extract<
    ValidatedRetainedOperationWindowCaptureV1,
    { readonly kind: "available" }
  >,
): RetainedOperationWindowExactCaptureV1 => ({
  manifest: {
    kind: "present",
    exactManifestBytes: Uint8Array.from(
      capture.exactManifestRow.exactManifestBytes,
    ),
    recordRevision: capture.exactManifestRow.recordRevision,
  },
  operations: capture.operations.map(copyContentRow),
});

const locatorFromManifest = (
  manifest: RetainedOperationWindowManifestV1,
): RetainedOperationWindowLocatorV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(manifest.roomContextId),
  referenceWindow: manifest.referenceWindow,
});

const sortedIdsWith = (
  operationIds: readonly Uint8Array[],
  operationId: Uint8Array,
): readonly Uint8Array[] => {
  const result = operationIds.map((value) => Uint8Array.from(value));
  let index = 0;
  while (index < result.length && compareBytes(result[index], operationId) < 0)
    index++;
  result.splice(index, 0, Uint8Array.from(operationId));
  return result;
};

const manifestWith = (
  source: RetainedOperationWindowManifestV1,
  overrides: Partial<
    Pick<
      RetainedOperationWindowManifestV1,
      | "completeness"
      | "operationIds"
      | "retainedOperationCount"
      | "retainedOperationBytes"
      | "firstRejectedOperationId"
    >
  >,
): RetainedOperationWindowManifestV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(source.roomContextId),
  referenceWindow: source.referenceWindow,
  retainThroughLogicalWindow: source.retainThroughLogicalWindow,
  completeness: overrides.completeness ?? source.completeness,
  operationIds:
    overrides.operationIds?.map((value) => Uint8Array.from(value)) ??
    source.operationIds.map((value) => Uint8Array.from(value)),
  retainedOperationCount:
    overrides.retainedOperationCount ?? source.retainedOperationCount,
  retainedOperationBytes:
    overrides.retainedOperationBytes ?? source.retainedOperationBytes,
  maxRetainedValidOperationsPerRoom: source.maxRetainedValidOperationsPerRoom,
  maxRetainedValidOperationBytesPerRoom:
    source.maxRetainedValidOperationBytesPerRoom,
  firstRejectedOperationId:
    overrides.firstRejectedOperationId === undefined
      ? source.firstRejectedOperationId === null
        ? null
        : Uint8Array.from(source.firstRejectedOperationId)
      : overrides.firstRejectedOperationId === null
        ? null
        : Uint8Array.from(overrides.firstRejectedOperationId),
});

const admissionRequest = (
  capture: Extract<
    ValidatedRetainedOperationWindowCaptureV1,
    { readonly kind: "available" }
  >,
  candidateOperationId: Uint8Array,
  mutation: PreparedRetainedOperationStoreMutationV1,
): RetainedOperationStoreCasRequestV1 => ({
  version: 1,
  locator: locatorFromManifest(capture.manifest),
  expected: copyExactCapture(capture),
  candidateOperationId: Uint8Array.from(candidateOperationId),
  mutation,
});

/**
 * Explicitly prepare a new empty complete window. This is the only path that
 * turns expected absence into a manifest; replay reads never infer that an
 * absent row means an empty room.
 */
export const prepareRetainedOperationWindowInitializationV1 = (
  value: unknown,
): RetainedOperationStoreCasRequestV1 => {
  if (
    !hasExactOwnDataFields(value, [
      "roomContextId",
      "referenceWindow",
      "retainThroughLogicalWindow",
      "maxRetainedValidOperationsPerRoom",
      "maxRetainedValidOperationBytesPerRoom",
    ])
  )
    return fail("initialization must contain exactly its declared fields");
  const roomContextId = ownBytes(
    value.roomContextId,
    "initial room context ID",
    32,
  );
  const referenceWindow = requireU64(
    value.referenceWindow,
    "initial referenceWindow",
  );
  const retainThroughLogicalWindow = requireU64(
    value.retainThroughLogicalWindow,
    "initial retainThroughLogicalWindow",
  );
  const maxRetainedValidOperationsPerRoom = requirePositiveManifestCountCap(
    value.maxRetainedValidOperationsPerRoom,
  );
  const maxRetainedValidOperationBytesPerRoom = requireU64(
    value.maxRetainedValidOperationBytesPerRoom,
    "initial maxRetainedValidOperationBytesPerRoom",
  );
  if (maxRetainedValidOperationBytesPerRoom === 0n)
    return fail("maxRetainedValidOperationBytesPerRoom must be positive");

  const manifest: RetainedOperationWindowManifestV1 = {
    version: 1,
    roomContextId: Uint8Array.from(roomContextId),
    referenceWindow,
    retainThroughLogicalWindow,
    completeness: "complete",
    operationIds: [],
    retainedOperationCount: 0,
    retainedOperationBytes: 0n,
    maxRetainedValidOperationsPerRoom,
    maxRetainedValidOperationBytesPerRoom,
    firstRejectedOperationId: null,
  };
  const exactNextManifestBytes =
    encodeRetainedOperationWindowManifestV1(manifest);
  return {
    version: 1,
    locator: {
      version: 1,
      roomContextId: Uint8Array.from(roomContextId),
      referenceWindow,
    },
    expected: { manifest: { kind: "absent" }, operations: [] },
    candidateOperationId: null,
    mutation: {
      kind: "initialize-window",
      exactNextManifestBytes,
    },
  };
};

/**
 * Plan one deterministic retained-operation admission.
 *
 * The input capture is fully correlated before a candidate can affect state.
 * Duplicate exact rows have zero resource delta. Once a manifest is
 * incomplete, normal admission never parses a candidate or repairs/replaces
 * the first-rejected witness; only a separate future full reconciliation may
 * create a new complete manifest after capacity changes.
 */
export const planRetainedOperationAdmissionV1 = async (
  captureValue: unknown,
  candidateValue: unknown,
): Promise<RetainedOperationAdmissionPlanV1> => {
  const ownedCapture = ownCaptureShape(captureValue);
  const ownedCandidate =
    ownedCapture.manifest?.completeness === "complete"
      ? ownContentRowShape(candidateValue, "candidate operation row")
      : null;
  const capture = await validateOwnedWindowCapture(ownedCapture);
  if (capture.kind === "unavailable") return { kind: "unavailable" };

  if (capture.manifest.completeness === "incomplete-overcapacity") {
    const firstRejected = capture.manifest.firstRejectedOperationId;
    if (firstRejected === null)
      return fail("incomplete manifest lost its first rejected witness");
    return {
      kind: "sticky-incomplete-overcapacity",
      firstRejectedOperationId: Uint8Array.from(firstRejected),
    };
  }

  const candidate = ownedCandidate;
  if (candidate === null)
    return fail("complete manifest lost its owned candidate operation");
  await validateOwnedContentRowAssociation(candidate);
  if (!bytesEqual(candidate.roomContextId, capture.manifest.roomContextId))
    return fail("candidate operation belongs to another room");

  const existingIndex = capture.manifest.operationIds.findIndex((operationId) =>
    bytesEqual(operationId, candidate.operationId),
  );
  if (existingIndex >= 0) {
    const existing = capture.operations[existingIndex];
    if (
      !bytesEqual(existing.exactOperationBytes, candidate.exactOperationBytes)
    )
      return fail("one operation ID addresses conflicting exact bytes");
    return { kind: "duplicate" };
  }

  const nextCount = capture.manifest.retainedOperationCount + 1;
  const candidateBytes = BigInt(candidate.exactOperationBytes.length);
  const byteOverflow =
    capture.manifest.retainedOperationBytes > U64_MAX - candidateBytes;
  const nextBytes = byteOverflow
    ? U64_MAX
    : capture.manifest.retainedOperationBytes + candidateBytes;
  const reachesCapacity =
    nextCount >= capture.manifest.maxRetainedValidOperationsPerRoom ||
    byteOverflow ||
    nextBytes >= capture.manifest.maxRetainedValidOperationBytesPerRoom;

  if (reachesCapacity) {
    const nextManifest = manifestWith(capture.manifest, {
      completeness: "incomplete-overcapacity",
      firstRejectedOperationId: candidate.operationId,
    });
    const exactNextManifestBytes =
      encodeRetainedOperationWindowManifestV1(nextManifest);
    return {
      kind: "mark-incomplete-overcapacity",
      request: admissionRequest(capture, candidate.operationId, {
        kind: "mark-incomplete-overcapacity",
        firstRejectedOperationId: Uint8Array.from(candidate.operationId),
        exactNextManifestBytes,
      }),
    };
  }

  const nextManifest = manifestWith(capture.manifest, {
    operationIds: sortedIdsWith(
      capture.manifest.operationIds,
      candidate.operationId,
    ),
    retainedOperationCount: nextCount,
    retainedOperationBytes: nextBytes,
  });
  const exactNextManifestBytes =
    encodeRetainedOperationWindowManifestV1(nextManifest);
  return {
    kind: "accept-operation",
    request: admissionRequest(capture, candidate.operationId, {
      kind: "insert-operation-and-replace-manifest",
      operation: copyContentRow(candidate),
      exactNextManifestBytes,
    }),
  };
};
