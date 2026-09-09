/**
 * Canonical retained evidence for one authenticated IDENTITY_HELLO.
 *
 * The bundle is intentionally pair-subject scoped: it binds the exact
 * historical Core selector and the remote/local endpoint PRESENCE operations,
 * including the complete author prefixes that made those operations eligible.
 * It is not a claim that every unrelated roster fact is duplicated here.
 */

import {
  MAX_CANONICAL_ENCODING_BYTES,
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import { snapshotByteInput } from "../cryptography/byteInput";
import { roomContextConfirmation } from "./derivations";
import { decodeOperation, deriveOperationId } from "./operation";
import { decodePresenceV1 } from "./operationPayload";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";
import { identityHelloHistoricalEvidenceBundleV1Schema } from "./schemas";

import type { PairAuthorChainPrefixEvidenceV1 } from "./coreReduce";
import type { RoomPolicyV4 } from "./roomPolicyV4";

const U64_MAX = 0xffffffffffffffffn;

export interface IdentityHelloHistoricalPresenceEvidenceV1 {
  readonly exactPresenceOperationBytes: Uint8Array;
  readonly presenceOperationId: Uint8Array;
  readonly retainThroughLogicalWindow: bigint;
  readonly authorChainPrefix: readonly PairAuthorChainPrefixEvidenceV1[];
}

export interface IdentityHelloHistoricalEvidenceBundleV1 {
  readonly version: 1;
  readonly exactCoreStateBytes: Uint8Array;
  /** Remote HELLO author first, local responder second. */
  readonly endpointPresenceEvidence: readonly [
    IdentityHelloHistoricalPresenceEvidenceV1,
    IdentityHelloHistoricalPresenceEvidenceV1,
  ];
}

export interface ExpectedIdentityHelloHistoricalEvidenceV1 {
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly exactCoreStateBytes: Uint8Array;
  readonly endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array];
}

export class IdentityHelloHistoricalEvidenceError extends Error {
  override readonly name = "IdentityHelloHistoricalEvidenceError";

  constructor(message: string) {
    super(`identityHelloHistoricalEvidence: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new IdentityHelloHistoricalEvidenceError(message);
};

const bytesKey = (value: Uint8Array): string => {
  let result = "";
  for (const byte of value) result += byte.toString(16).padStart(2, "0");
  return result;
};

const checkedAddU64 = (left: bigint, right: bigint): bigint => {
  if (left < 0n || right < 0n || left > U64_MAX - right)
    return fail("retention horizon overflowed u64");
  return left + right;
};

const hasExactOwnDataFields = (
  value: unknown,
  fields: readonly string[],
): value is Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  )
    return false;
  return fields.every((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return (
      descriptor !== undefined && descriptor.enumerable && "value" in descriptor
    );
  });
};

const ownBytes = (
  value: unknown,
  label: string,
  exactLength?: number,
): Uint8Array => {
  try {
    return snapshotByteInput(
      value,
      `identityHelloHistoricalEvidence: ${label}`,
      exactLength === undefined
        ? { maximumLength: MAX_CANONICAL_ENCODING_BYTES }
        : { exactLength },
    );
  } catch (error) {
    return fail(error instanceof Error ? error.message : `${label} is invalid`);
  }
};

const snapshotExpected = (
  value: ExpectedIdentityHelloHistoricalEvidenceV1,
): ExpectedIdentityHelloHistoricalEvidenceV1 => {
  if (
    !hasExactOwnDataFields(value, [
      "roomContextId",
      "roomPolicy",
      "exactCoreStateBytes",
      "endpointPresenceOperationIds",
    ])
  )
    return fail("expected evidence binding must contain exactly its fields");
  const endpoints = value.endpointPresenceOperationIds;
  if (
    !Array.isArray(endpoints) ||
    Object.getPrototypeOf(endpoints) !== Array.prototype ||
    endpoints.length !== 2
  )
    return fail("expected endpoint PRESENCE IDs must be one exact pair");
  const first = Object.getOwnPropertyDescriptor(endpoints, "0");
  const second = Object.getOwnPropertyDescriptor(endpoints, "1");
  if (
    first === undefined ||
    second === undefined ||
    !("value" in first) ||
    !("value" in second)
  )
    return fail("expected endpoint PRESENCE IDs must be dense data elements");

  let roomPolicy: RoomPolicyV4;
  try {
    roomPolicy = decodeRoomPolicyV4(encodeRoomPolicyV4(value.roomPolicy));
  } catch (error) {
    return fail(
      error instanceof Error
        ? error.message
        : "expected room policy is invalid",
    );
  }
  return {
    roomContextId: ownBytes(value.roomContextId, "room context ID", 32),
    roomPolicy,
    exactCoreStateBytes: ownBytes(
      value.exactCoreStateBytes,
      "historical Core state",
    ),
    endpointPresenceOperationIds: [
      ownBytes(first.value, "remote endpoint PRESENCE ID", 32),
      ownBytes(second.value, "local endpoint PRESENCE ID", 32),
    ],
  };
};

const validateStructuralSemantics = (
  value: IdentityHelloHistoricalEvidenceBundleV1,
): void => {
  if (value.version !== 1) fail("unsupported bundle version");
  if (value.exactCoreStateBytes.length === 0)
    fail("exact Core state must not be empty");
  if (value.endpointPresenceEvidence.length !== 2)
    fail("bundle must contain exactly two endpoint PRESENCE entries");

  for (let endpoint = 0; endpoint < 2; endpoint++) {
    const evidence = value.endpointPresenceEvidence[endpoint];
    if (evidence.exactPresenceOperationBytes.length === 0)
      fail(`endpoint ${String(endpoint)} PRESENCE bytes must not be empty`);
    if (evidence.authorChainPrefix.length === 0)
      fail(`endpoint ${String(endpoint)} author prefix must not be empty`);

    const operationIds = new Set<string>();
    for (const member of evidence.authorChainPrefix) {
      if (member.exactOperationBytes.length === 0)
        fail(
          `endpoint ${String(endpoint)} author-prefix bytes must not be empty`,
        );
      const key = bytesKey(member.operationId);
      if (operationIds.has(key))
        fail(`endpoint ${String(endpoint)} author prefix repeats an operation`);
      operationIds.add(key);
    }

    const tail = evidence.authorChainPrefix.at(-1);
    if (
      tail === undefined ||
      !bytesEqual(tail.operationId, evidence.presenceOperationId) ||
      !bytesEqual(
        tail.exactOperationBytes,
        evidence.exactPresenceOperationBytes,
      )
    )
      fail(
        `endpoint ${String(endpoint)} author prefix must end at its exact PRESENCE`,
      );
  }
};

const decodeStructural = (
  exactBytes: Uint8Array,
): IdentityHelloHistoricalEvidenceBundleV1 => {
  let decoded: IdentityHelloHistoricalEvidenceBundleV1;
  try {
    decoded = decodeCanonicalStrict(
      identityHelloHistoricalEvidenceBundleV1Schema,
      exactBytes,
    ) as IdentityHelloHistoricalEvidenceBundleV1;
  } catch (error) {
    return fail(
      error instanceof Error ? error.message : "canonical decode failed",
    );
  }
  validateStructuralSemantics(decoded);
  return decoded;
};

/**
 * Encode and deeply own a bundle assembled from genuine CoreReduce evidence.
 *
 * Cryptographic operation IDs and author-chain continuity are rechecked by
 * `decodeAndVerifyIdentityHelloHistoricalEvidenceBundleV1` at the durable
 * admission boundary.
 */
export const encodeIdentityHelloHistoricalEvidenceBundleV1 = (
  value: IdentityHelloHistoricalEvidenceBundleV1,
): Uint8Array => {
  let encoded: Uint8Array;
  try {
    encoded = encodeCanonical(
      identityHelloHistoricalEvidenceBundleV1Schema,
      value,
    );
  } catch (error) {
    return fail(
      error instanceof Error ? error.message : "canonical encode failed",
    );
  }
  decodeStructural(encoded);
  return encoded;
};

const verifyAuthorPrefix = async (
  evidence: IdentityHelloHistoricalPresenceEvidenceV1,
  expectedRoomContextConfirmation: Uint8Array,
  endpoint: number,
): Promise<void> => {
  let previousOperationId: Uint8Array | null = null;
  let authorKey: Uint8Array | null = null;
  let logicalWindow: bigint | null = null;

  for (let index = 0; index < evidence.authorChainPrefix.length; index++) {
    const member = evidence.authorChainPrefix[index];
    let operation;
    try {
      operation = decodeOperation(member.exactOperationBytes);
    } catch (error) {
      return fail(
        `endpoint ${String(endpoint)} author prefix ${String(index)} is invalid: ${
          error instanceof Error ? error.message : "operation decode failed"
        }`,
      );
    }
    const derivedOperationId = await deriveOperationId(operation);
    if (!bytesEqual(derivedOperationId, member.operationId))
      fail(
        `endpoint ${String(endpoint)} author prefix ${String(index)} has the wrong operation ID`,
      );
    if (
      !bytesEqual(
        operation.roomContextConfirmation,
        expectedRoomContextConfirmation,
      )
    )
      fail(
        `endpoint ${String(endpoint)} author prefix ${String(index)} belongs to another room`,
      );
    if (operation.authorSequence !== BigInt(index))
      fail(
        `endpoint ${String(endpoint)} author prefix is not contiguous from sequence zero`,
      );
    if (
      (previousOperationId === null &&
        operation.previousAuthorOperationId !== null) ||
      (previousOperationId !== null &&
        (operation.previousAuthorOperationId === null ||
          !bytesEqual(
            operation.previousAuthorOperationId,
            previousOperationId,
          )))
    )
      fail(
        `endpoint ${String(endpoint)} author prefix has a broken predecessor link`,
      );
    if (authorKey === null) authorKey = operation.authorEpochEd25519Key;
    else if (!bytesEqual(authorKey, operation.authorEpochEd25519Key))
      fail(`endpoint ${String(endpoint)} author prefix changes author`);
    if (logicalWindow === null) logicalWindow = operation.logicalWindow;
    else if (logicalWindow !== operation.logicalWindow)
      fail(`endpoint ${String(endpoint)} author prefix crosses a window`);
    previousOperationId = member.operationId;
  }
};

/**
 * Canonical-decode and revalidate the complete persisted pair-subject bundle.
 *
 * Exact comparison with the authenticated claim remains mandatory before this
 * call. This verifier then independently checks the selector, endpoint order,
 * operation IDs, contiguous author prefixes, room binding, PRESENCE kind, and
 * exact protocol-derived retention horizons.
 */
export const decodeAndVerifyIdentityHelloHistoricalEvidenceBundleV1 = async (
  exactBytes: Uint8Array,
  expected: ExpectedIdentityHelloHistoricalEvidenceV1,
): Promise<IdentityHelloHistoricalEvidenceBundleV1> => {
  /*
   * Own every caller input before the first await. A port/caller mutation,
   * proxy, accessor, or custom typed-array surface cannot change which room,
   * policy, Core selector, or endpoint tuple is subsequently verified.
   */
  const privateExactBytes = ownBytes(exactBytes, "exact bundle bytes");
  const privateExpected = snapshotExpected(expected);
  const bundle = decodeStructural(privateExactBytes);
  if (
    !bytesEqual(bundle.exactCoreStateBytes, privateExpected.exactCoreStateBytes)
  )
    fail("historical Core selector differs from the authenticated HELLO");

  const expectedConfirmation = await roomContextConfirmation(
    privateExpected.roomContextId,
  );
  for (let endpoint = 0; endpoint < 2; endpoint++) {
    const evidence = bundle.endpointPresenceEvidence[endpoint];
    if (
      !bytesEqual(
        evidence.presenceOperationId,
        privateExpected.endpointPresenceOperationIds[endpoint],
      )
    )
      fail(
        `endpoint ${String(endpoint)} PRESENCE ID is out of order or changed`,
      );

    let presenceOperation;
    try {
      presenceOperation = decodeOperation(evidence.exactPresenceOperationBytes);
    } catch (error) {
      return fail(
        `endpoint ${String(endpoint)} PRESENCE operation is invalid: ${
          error instanceof Error ? error.message : "operation decode failed"
        }`,
      );
    }
    if (presenceOperation.kind !== "PRESENCE")
      fail(`endpoint ${String(endpoint)} evidence is not a PRESENCE operation`);
    if (
      !bytesEqual(
        await deriveOperationId(presenceOperation),
        evidence.presenceOperationId,
      )
    )
      fail(`endpoint ${String(endpoint)} PRESENCE operation ID changed`);
    if (
      !bytesEqual(
        presenceOperation.roomContextConfirmation,
        expectedConfirmation,
      )
    )
      fail(`endpoint ${String(endpoint)} PRESENCE belongs to another room`);

    let presence;
    try {
      presence = decodePresenceV1(presenceOperation.fixedPayload);
    } catch (error) {
      return fail(
        `endpoint ${String(endpoint)} PRESENCE payload is invalid: ${
          error instanceof Error ? error.message : "payload decode failed"
        }`,
      );
    }
    const exactRetention = checkedAddU64(
      checkedAddU64(
        presence.core.receiverKeyValidThroughLogicalWindow,
        BigInt(
          privateExpected.roomPolicy.protocolLimits.receiverKeyOverlapWindows,
        ),
      ),
      BigInt(privateExpected.roomPolicy.protocolLimits.maxClockSkewWindows),
    );
    if (evidence.retainThroughLogicalWindow !== exactRetention)
      fail(`endpoint ${String(endpoint)} retention horizon changed`);

    await verifyAuthorPrefix(evidence, expectedConfirmation, endpoint);
  }
  return bundle;
};
