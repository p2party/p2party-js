/**
 * Closed non-pair operation payload codecs and intrinsic validation.
 *
 * The schema descriptors in `schemas.ts` are the byte SSOT. This module adds
 * only rules that cannot be expressed by field widths alone: room/policy
 * binding, interval containment, semantic-slot derivation, and signatures.
 *
 * A LEAVE's same-author/live-presence dependency is intentionally completed
 * by `CoreReduce`, after the referenced operation is available. Rejecting a
 * missing dependency here would make acceptance depend on carrier arrival
 * order. Stable presence ownership is likewise verified only when a trusted
 * local address-book key or the pair-private stable key is available.
 */

import { verify } from "../cryptography/ed25519";
import {
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import {
  admissionGrantSignedMessage,
  admissionRevokeSemanticSlot,
  admissionRevokeSignedMessage,
  leaveSemanticSlot,
  policyHash,
  presenceOwnershipSignedMessage,
  presencePermitSignedMessage,
  presenceProofTranscriptHash,
  presenceSemanticSlot,
  stableIdentityCommitment,
  storeHintSemanticSlot,
} from "./derivations";
import { storeDescriptorAuthentic, storeId } from "./storeDescriptor";
import {
  admissionGrantV1Schema,
  admissionRevokeV1Schema,
  authenticatedRoomOperationV1Schema,
  corePresenceFactV1Schema,
  leaveV1Schema,
  presenceV1Schema,
  storeHintOperationV1Schema,
} from "./schemas";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";

import type { LibCrypto } from "../cryptography/libcrypto";
import type {
  AuthenticatedRoomOperationV1,
  OperationKindV1,
} from "./operation";
import type { CorePresenceFactV1 } from "./coreReduce";
import type { RoomPolicyV4 } from "./roomPolicyV4";
import type { StoreDescriptorV1, StoreRouteV1 } from "./storeDescriptor";
import type { TypeDescriptor } from "./canonicalSchema";

const U64_MAX = 0xffffffffffffffffn;
const isUnsignedU64 = (value: unknown): value is bigint =>
  typeof value === "bigint" && value >= 0n && value <= U64_MAX;

export interface AdmissionGrantV1 {
  version: 1;
  roomContextId: Uint8Array;
  stableEd25519PublicKey: Uint8Array;
  generation: bigint;
  issuedAtLogicalWindow: bigint;
  notBeforeLogicalWindow: bigint;
  notAfterLogicalWindow: bigint;
  authoritySignature: Uint8Array;
}

export interface AdmissionRevokeV1 {
  version: 1;
  roomContextId: Uint8Array;
  stableIdentityCommitment: Uint8Array;
  minimumAcceptedGeneration: bigint;
  effectiveLogicalWindow: bigint;
  expiresAfterLogicalWindow: bigint;
  authoritySignature: Uint8Array;
}

export interface PresenceCoreV1 {
  version: 1;
  stableIdentityCommitment: Uint8Array;
  rendezvousHybridKemPublicKey: Uint8Array;
  receiverKeyValidThroughLogicalWindow: bigint;
  presenceNonce: Uint8Array;
  validThroughLogicalWindow: bigint;
}

export interface PresencePermitV1 {
  version: 1;
  roomContextId: Uint8Array;
  presenceProofTranscriptHash: Uint8Array;
  permitSerial: Uint8Array;
  generation: bigint;
  issuedAtLogicalWindow: bigint;
  notBeforeLogicalWindow: bigint;
  notAfterLogicalWindow: bigint;
  authoritySignature: Uint8Array;
}

export interface PresenceV1 {
  core: PresenceCoreV1;
  stableOwnershipSignature: Uint8Array;
  authorityPermit: PresencePermitV1 | null;
}

export interface LeaveV1 {
  version: 1;
  presenceOperationId: Uint8Array;
  effectiveLogicalWindow: bigint;
}

export interface StoreHintOperationV1 {
  version: 1;
  descriptor: StoreDescriptorV1;
  routes: readonly StoreRouteV1[];
  hintExpiresAfterLogicalWindow: bigint;
}

export type DecodedNonPairOperationPayloadV1 =
  | { readonly kind: "PRESENCE"; readonly value: PresenceV1 }
  | { readonly kind: "LEAVE"; readonly value: LeaveV1 }
  | { readonly kind: "STORE_HINT"; readonly value: StoreHintOperationV1 }
  | { readonly kind: "ADMISSION_REVOKE"; readonly value: AdmissionRevokeV1 };

export interface NonPairPayloadValidationContext {
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
}

export interface AdmissionGrantValidationContext extends NonPairPayloadValidationContext {
  /** Logical window of the HELLO or ACCEPT carrying this grant. */
  readonly carriedAtLogicalWindow: bigint;
  readonly referenceWindow: bigint;
}

export class OperationPayloadValidationError extends Error {
  override readonly name = "OperationPayloadValidationError";

  constructor(message: string) {
    super(`roomOperation payload: ${message}`);
  }
}

const fail: (message: string) => never = (message) => {
  throw new OperationPayloadValidationError(message);
};

const checkedAdd = (left: bigint, right: bigint): bigint => {
  const sum = left + right;
  if (left < 0n || right < 0n || sum > U64_MAX)
    fail("checked unsigned-64 addition overflowed");
  return sum;
};

const checkedMultiply = (left: bigint, right: bigint): bigint => {
  if (left < 0n || right < 0n)
    fail("checked unsigned-64 multiplication received a negative input");
  if (left !== 0n && right > U64_MAX / left)
    fail("checked unsigned-64 multiplication overflowed");
  return left * right;
};

const decode = <T>(
  name: string,
  descriptor: TypeDescriptor,
  bytes: Uint8Array,
): T => {
  try {
    return decodeCanonicalStrict(descriptor, bytes) as T;
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : "unknown canonical-codec error";
    return fail(`${name} is invalid: ${reason}`);
  }
};

const encode = (descriptor: TypeDescriptor, value: unknown): Uint8Array =>
  encodeCanonical(descriptor, value);

const snapshotCanonical = <T>(
  name: string,
  descriptor: TypeDescriptor,
  value: unknown,
): T => {
  try {
    return decodeCanonicalStrict(
      descriptor,
      encodeCanonical(descriptor, value),
    ) as T;
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : "unknown canonical-codec error";
    return fail(`${name} is invalid: ${reason}`);
  }
};

const snapshotPayloadContext = (
  context: NonPairPayloadValidationContext,
): NonPairPayloadValidationContext => {
  try {
    const roomContextId = Uint8Array.from(context.roomContextId);
    if (roomContextId.length !== 32)
      fail("validation context RoomContextId must be exactly 32 bytes");
    const roomPolicyBytes = encodeRoomPolicyV4(context.roomPolicy);
    return {
      roomContextId,
      roomPolicy: decodeRoomPolicyV4(roomPolicyBytes),
    };
  } catch (error) {
    if (error instanceof OperationPayloadValidationError) throw error;
    const reason =
      error instanceof Error ? error.message : "unknown context snapshot error";
    return fail(`validation context is invalid: ${reason}`);
  }
};

export const encodeAdmissionGrantV1 = (value: AdmissionGrantV1): Uint8Array =>
  encode(admissionGrantV1Schema, value);

export const decodeAdmissionGrantV1 = (bytes: Uint8Array): AdmissionGrantV1 =>
  decode("AdmissionGrantV1", admissionGrantV1Schema, bytes);

export const encodeAdmissionRevokeV1 = (value: AdmissionRevokeV1): Uint8Array =>
  encode(admissionRevokeV1Schema, value);

export const decodeAdmissionRevokeV1 = (bytes: Uint8Array): AdmissionRevokeV1 =>
  decode("AdmissionRevokeV1", admissionRevokeV1Schema, bytes);

export const encodePresenceV1 = (value: PresenceV1): Uint8Array =>
  encode(presenceV1Schema, value);

export const decodePresenceV1 = (bytes: Uint8Array): PresenceV1 =>
  decode("PresenceV1", presenceV1Schema, bytes);

export const encodeLeaveV1 = (value: LeaveV1): Uint8Array =>
  encode(leaveV1Schema, value);

export const decodeLeaveV1 = (bytes: Uint8Array): LeaveV1 =>
  decode("LeaveV1", leaveV1Schema, bytes);

export const encodeStoreHintOperationV1 = (
  value: StoreHintOperationV1,
): Uint8Array => encode(storeHintOperationV1Schema, value);

export const decodeStoreHintOperationV1 = (
  bytes: Uint8Array,
): StoreHintOperationV1 =>
  decode("StoreHintOperationV1", storeHintOperationV1Schema, bytes);

const unsigned = <T extends { readonly authoritySignature: Uint8Array }>(
  value: T,
): Omit<T, "authoritySignature"> => {
  const { authoritySignature: _signature, ...result } = value;
  return result;
};

const requireAuthorityPolicy = (
  roomPolicy: RoomPolicyV4,
): Extract<RoomPolicyV4["admissionFloor"], { mode: "authority-grant" }> => {
  if (roomPolicy.admissionFloor.mode !== "authority-grant")
    return fail("authority credential is forbidden in capability mode");
  return roomPolicy.admissionFloor;
};

/**
 * Validate a pair-private admission grant at the one decision snapshot.
 *
 * This does not apply frontend allow/deny policy or a revocation floor. Those
 * belong to the sole admission kernel after it has captured its trusted
 * snapshot; this function proves only the grant's canonical authority facts.
 */
export const validateAdmissionGrantV1 = async (
  grant: AdmissionGrantV1,
  context: AdmissionGrantValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  // Own every byte/scalar before the first await. Callers may retain and mutate
  // their objects while WebCrypto is pending.
  const privateGrant = snapshotCanonical<AdmissionGrantV1>(
    "AdmissionGrantV1",
    admissionGrantV1Schema,
    grant,
  );
  const privatePayloadContext = snapshotPayloadContext(context);
  const privateContext: AdmissionGrantValidationContext = {
    ...privatePayloadContext,
    carriedAtLogicalWindow: context.carriedAtLogicalWindow,
    referenceWindow: context.referenceWindow,
  };

  if (privateGrant.version !== 1) fail("unsupported AdmissionGrantV1 version");
  if (!bytesEqual(privateGrant.roomContextId, privateContext.roomContextId))
    fail("admission grant names another room context");

  const authority = requireAuthorityPolicy(privateContext.roomPolicy);
  if (
    !isUnsignedU64(privateContext.carriedAtLogicalWindow) ||
    !isUnsignedU64(privateContext.referenceWindow) ||
    privateGrant.issuedAtLogicalWindow >
      privateContext.carriedAtLogicalWindow ||
    privateContext.carriedAtLogicalWindow > privateContext.referenceWindow
  )
    fail("admission grant issuance/carrying interval is invalid");
  if (
    privateGrant.issuedAtLogicalWindow > privateGrant.notBeforeLogicalWindow ||
    privateGrant.notBeforeLogicalWindow > privateContext.referenceWindow ||
    privateContext.referenceWindow > privateGrant.notAfterLogicalWindow
  )
    fail("admission grant is not live at the reference window");
  if (
    privateGrant.notAfterLogicalWindow - privateGrant.issuedAtLogicalWindow >
    BigInt(authority.maxAuthorityCredentialLifetimeWindows)
  )
    fail("admission grant exceeds the authority credential lifetime");

  if (
    !(await verify(
      await admissionGrantSignedMessage(unsigned(privateGrant)),
      Uint8Array.from(privateGrant.authoritySignature),
      Uint8Array.from(authority.authorityEd25519PublicKey),
      module,
    ))
  )
    fail("admission grant authority signature does not verify");
};

interface PresenceProofTranscriptV1 {
  readonly roomContextId: Uint8Array;
  readonly policyHash: Uint8Array;
  readonly logicalWindow: bigint;
  readonly authorEpochEd25519Key: Uint8Array;
  readonly core: PresenceCoreV1;
}

const presenceTranscriptFromFacts = async (
  logicalWindow: bigint,
  authorEpochEd25519Key: Uint8Array,
  presence: PresenceV1,
  context: NonPairPayloadValidationContext,
): Promise<{
  readonly transcript: PresenceProofTranscriptV1;
  readonly transcriptHash: Uint8Array;
}> => {
  const transcript: PresenceProofTranscriptV1 = {
    roomContextId: context.roomContextId,
    policyHash: await policyHash(context.roomPolicy),
    logicalWindow,
    authorEpochEd25519Key,
    core: presence.core,
  };
  return {
    transcript,
    transcriptHash: await presenceProofTranscriptHash(transcript),
  };
};

const validateOwnedPresenceProof = async (
  logicalWindow: bigint,
  authorEpochEd25519Key: Uint8Array,
  presence: PresenceV1,
  stableEd25519PublicKey: Uint8Array,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  const expectedCommitment = await stableIdentityCommitment(
    context.roomContextId,
    stableEd25519PublicKey,
  );
  if (!bytesEqual(presence.core.stableIdentityCommitment, expectedCommitment))
    fail("stable key does not match the presence commitment");
  const { transcriptHash } = await presenceTranscriptFromFacts(
    logicalWindow,
    authorEpochEd25519Key,
    presence,
    context,
  );
  if (
    !(await verify(
      presenceOwnershipSignedMessage(transcriptHash),
      Uint8Array.from(presence.stableOwnershipSignature),
      stableEd25519PublicKey,
      module,
    ))
  )
    fail("stable presence ownership signature does not verify");
};

/**
 * Verify the stable ownership proof once a trusted local lookup or pair flight
 * supplies the exact stable public key. The key is deliberately absent from
 * room-wide presence, so core validation cannot call this function itself.
 */
export const validatePresenceOwnershipV1 = async (
  operation: AuthenticatedRoomOperationV1,
  presence: PresenceV1,
  stableEd25519PublicKey: Uint8Array,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  const privateOperation = snapshotCanonical<AuthenticatedRoomOperationV1>(
    "AuthenticatedRoomOperationV1",
    authenticatedRoomOperationV1Schema,
    operation,
  );
  const privatePresence = snapshotCanonical<PresenceV1>(
    "PresenceV1",
    presenceV1Schema,
    presence,
  );
  const privateStableKey = Uint8Array.from(stableEd25519PublicKey);
  const privateContext = snapshotPayloadContext(context);

  if (privateOperation.kind !== "PRESENCE")
    fail("stable ownership proof requires a PRESENCE operation");
  if (
    !bytesEqual(
      encodePresenceV1(privatePresence),
      privateOperation.fixedPayload,
    )
  )
    fail("stable ownership proof does not match the operation payload");
  await validateOwnedPresenceProof(
    privateOperation.logicalWindow,
    privateOperation.authorEpochEd25519Key,
    privatePresence,
    privateStableKey,
    privateContext,
    module,
  );
};

/**
 * Verify ownership directly from a trusted Core presence fact.
 *
 * Core already authenticated the outer operation and preserved every field
 * used by the ownership transcript. This avoids fabricating an incomplete
 * `AuthenticatedRoomOperationV1` merely to perform a local address-book
 * lookup. The function proves only the signature/commitment relation; the
 * caller must still obtain the fact from a genuine current or retained Core
 * projection before treating it as admission evidence.
 */
export const validateCorePresenceFactOwnershipV1 = async (
  fact: CorePresenceFactV1,
  stableEd25519PublicKey: Uint8Array,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  const privateFact = snapshotCanonical<CorePresenceFactV1>(
    "CorePresenceFactV1",
    corePresenceFactV1Schema,
    fact,
  );
  const privateStableKey = Uint8Array.from(stableEd25519PublicKey);
  const privateContext = snapshotPayloadContext(context);
  if (privateStableKey.length !== 32)
    fail("stableEd25519PublicKey must be exactly 32 bytes");
  await validateOwnedPresenceProof(
    privateFact.logicalWindow,
    privateFact.authorEpochEd25519Key,
    privateFact.presence,
    privateStableKey,
    privateContext,
    module,
  );
};

const validatePresence = async (
  operation: AuthenticatedRoomOperationV1,
  presence: PresenceV1,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  if (presence.core.version !== 1) fail("unsupported PresenceCoreV1 version");
  if (
    operation.logicalWindow > presence.core.validThroughLogicalWindow ||
    presence.core.validThroughLogicalWindow >
      presence.core.receiverKeyValidThroughLogicalWindow ||
    presence.core.receiverKeyValidThroughLogicalWindow >
      operation.expiresAfterWindow
  )
    fail("presence validity interval is not contained by its outer operation");
  checkedAdd(
    checkedAdd(
      presence.core.receiverKeyValidThroughLogicalWindow,
      BigInt(context.roomPolicy.protocolLimits.receiverKeyOverlapWindows),
    ),
    BigInt(context.roomPolicy.protocolLimits.maxClockSkewWindows),
  );

  const { transcriptHash } = await presenceTranscriptFromFacts(
    operation.logicalWindow,
    operation.authorEpochEd25519Key,
    presence,
    context,
  );
  const expectedSlot = await presenceSemanticSlot(
    operation.authorEpochEd25519Key,
    operation.logicalWindow,
    presence.core.presenceNonce,
  );
  if (!bytesEqual(operation.semanticSlot, expectedSlot))
    fail("PRESENCE semanticSlot does not match its core");

  if (context.roomPolicy.admissionFloor.mode === "capability") {
    if (presence.authorityPermit !== null)
      fail("authority permit is forbidden in capability mode");
    return;
  }

  const permit = presence.authorityPermit;
  if (permit === null) fail("authority mode requires a presence permit");
  if (permit.version !== 1) fail("unsupported PresencePermitV1 version");
  if (!bytesEqual(permit.roomContextId, context.roomContextId))
    fail("presence permit names another room context");
  if (!bytesEqual(permit.presenceProofTranscriptHash, transcriptHash))
    fail("presence permit does not bind the exact presence transcript");
  if (
    permit.issuedAtLogicalWindow > permit.notBeforeLogicalWindow ||
    permit.notBeforeLogicalWindow > operation.logicalWindow ||
    presence.core.receiverKeyValidThroughLogicalWindow >
      permit.notAfterLogicalWindow
  )
    fail("presence permit does not cover the complete presence interval");

  const authority = context.roomPolicy.admissionFloor;
  if (
    permit.notAfterLogicalWindow - permit.issuedAtLogicalWindow >
    BigInt(authority.maxAuthorityCredentialLifetimeWindows)
  )
    fail("presence permit exceeds the authority credential lifetime");
  if (
    !(await verify(
      await presencePermitSignedMessage(unsigned(permit)),
      permit.authoritySignature,
      authority.authorityEd25519PublicKey,
      module,
    ))
  )
    fail("presence permit authority signature does not verify");
};

const validateLeave = async (
  operation: AuthenticatedRoomOperationV1,
  leave: LeaveV1,
): Promise<void> => {
  if (leave.version !== 1) fail("unsupported LeaveV1 version");
  if (operation.logicalWindow !== leave.effectiveLogicalWindow)
    fail("LEAVE logicalWindow must equal effectiveLogicalWindow");
  if (
    operation.dependencies.length !== 1 ||
    !bytesEqual(operation.dependencies[0], leave.presenceOperationId)
  )
    fail("LEAVE dependency must equal its referenced presence operation");
  if (
    !bytesEqual(
      operation.semanticSlot,
      await leaveSemanticSlot(
        leave.presenceOperationId,
        leave.effectiveLogicalWindow,
      ),
    )
  )
    fail("LEAVE semanticSlot does not match its payload");
};

const validateStoreHint = async (
  operation: AuthenticatedRoomOperationV1,
  hint: StoreHintOperationV1,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  if (hint.version !== 1) fail("unsupported StoreHintOperationV1 version");
  if (
    operation.logicalWindow > hint.hintExpiresAfterLogicalWindow ||
    hint.hintExpiresAfterLogicalWindow > operation.expiresAfterWindow
  )
    fail(
      "store hint validity interval is not contained by its outer operation",
    );

  /*
   * No non-empty route hint can be accepted until the content-addressed
   * release registry freezes an exact route-family parser. Fail before any
   * store/route signature work so one authenticated author cannot amplify a
   * single operation into hundreds of pointless Ed25519 verifications.
   */
  if (hint.routes.length !== 0)
    fail("STORE_HINT route-family registry is not frozen");

  const logicalWindowMs = context.roomPolicy.protocolLimits.logicalWindowMs;
  const intervalStart = checkedMultiply(
    operation.logicalWindow,
    logicalWindowMs,
  );
  const intervalEndExclusive = checkedMultiply(
    checkedAdd(hint.hintExpiresAfterLogicalWindow, 1n),
    logicalWindowMs,
  );
  if (
    hint.descriptor.notBeforeUnixMs > intervalStart ||
    intervalEndExclusive > hint.descriptor.notAfterUnixMs
  )
    fail("store descriptor lease does not cover the complete hint interval");

  const expectedSlot = await storeHintSemanticSlot(
    await storeId(hint.descriptor.storeIdentityEd25519Key),
    hint.descriptor.descriptorGeneration,
  );
  if (!bytesEqual(operation.semanticSlot, expectedSlot))
    fail("STORE_HINT semanticSlot does not match its descriptor");

  const descriptorAuthentic = await storeDescriptorAuthentic(
    hint.descriptor,
    module,
  );
  if (!descriptorAuthentic.valid)
    fail(
      `store hint descriptor is not authentic: ${descriptorAuthentic.reason}`,
    );
};

const validateAdmissionRevoke = async (
  operation: AuthenticatedRoomOperationV1,
  revoke: AdmissionRevokeV1,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<void> => {
  if (revoke.version !== 1) fail("unsupported AdmissionRevokeV1 version");
  if (!bytesEqual(revoke.roomContextId, context.roomContextId))
    fail("admission revoke names another room context");

  const authority = requireAuthorityPolicy(context.roomPolicy);
  const expectedExpiry = checkedAdd(
    checkedAdd(
      revoke.effectiveLogicalWindow,
      BigInt(context.roomPolicy.protocolLimits.maxFutureLogicalWindows),
    ),
    BigInt(authority.maxAuthorityCredentialLifetimeWindows),
  );
  if (
    operation.logicalWindow !== revoke.effectiveLogicalWindow ||
    revoke.expiresAfterLogicalWindow !== expectedExpiry ||
    operation.expiresAfterWindow !== expectedExpiry
  )
    fail("ADMISSION_REVOKE does not use its exact grant horizon");
  if (
    !bytesEqual(
      operation.semanticSlot,
      await admissionRevokeSemanticSlot(
        revoke.stableIdentityCommitment,
        revoke.minimumAcceptedGeneration,
        revoke.effectiveLogicalWindow,
        revoke.expiresAfterLogicalWindow,
      ),
    )
  )
    fail("ADMISSION_REVOKE semanticSlot does not match its payload");
  if (
    !bytesEqual(
      operation.authorEpochEd25519Key,
      authority.authorityEd25519PublicKey,
    )
  )
    fail("ADMISSION_REVOKE outer author is not the pinned authority");
  if (
    !(await verify(
      await admissionRevokeSignedMessage(unsigned(revoke)),
      revoke.authoritySignature,
      authority.authorityEd25519PublicKey,
      module,
    ))
  )
    fail("admission revoke authority signature does not verify");
};

/**
 * Decode the one payload schema selected by the signed outer kind and prove
 * every self-contained nested rule. No caller-supplied discriminant exists.
 */
const decodeAndValidateNonPairOperationPayloadOwned = async (
  operation: AuthenticatedRoomOperationV1,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<DecodedNonPairOperationPayloadV1> => {
  if (operation.kind === "PAIR_STEP")
    return fail("PAIR_STEP must use the pair-envelope validator");
  const kind: Exclude<OperationKindV1, "PAIR_STEP"> = operation.kind as Exclude<
    OperationKindV1,
    "PAIR_STEP"
  >;
  switch (kind) {
    case "PRESENCE": {
      const value = decodePresenceV1(operation.fixedPayload);
      await validatePresence(operation, value, context, module);
      return { kind, value };
    }
    case "LEAVE": {
      const value = decodeLeaveV1(operation.fixedPayload);
      await validateLeave(operation, value);
      return { kind, value };
    }
    case "STORE_HINT": {
      const value = decodeStoreHintOperationV1(operation.fixedPayload);
      await validateStoreHint(operation, value, context, module);
      return { kind, value };
    }
    case "ADMISSION_REVOKE": {
      const value = decodeAdmissionRevokeV1(operation.fixedPayload);
      await validateAdmissionRevoke(operation, value, context, module);
      return { kind, value };
    }
    default:
      return fail(`unsupported operation kind ${String(kind)}`);
  }
};

export const decodeAndValidateNonPairOperationPayload = async (
  operation: AuthenticatedRoomOperationV1,
  context: NonPairPayloadValidationContext,
  module?: LibCrypto,
): Promise<DecodedNonPairOperationPayloadV1> => {
  const privateOperation = snapshotCanonical<AuthenticatedRoomOperationV1>(
    "AuthenticatedRoomOperationV1",
    authenticatedRoomOperationV1Schema,
    operation,
  );
  const privateContext = snapshotPayloadContext(context);
  return decodeAndValidateNonPairOperationPayloadOwned(
    privateOperation,
    privateContext,
    module,
  );
};
