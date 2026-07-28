/**
 * Reservation-gated identity HELLO opener.
 *
 * This module is the sole current path from a committed pair-open reservation
 * to HPKE work. It derives every transcript input from opaque trial
 * provenance, authenticates the complete HELLO identity bundle, and retains
 * HelloRoot only inside an opaque process-local result.
 *
 * Admission, pair-ledger persistence, ACCEPT construction, and any release of
 * HelloRoot remain deliberately out of scope. This module is absent from the
 * package barrel.
 */

import {
  CanonicalSchemaError,
  bytesEqual,
  decodeCanonicalStrict,
  encodeCanonical,
} from "./canonicalSchema";
import {
  pairBootstrapHeaderHash,
  pairBootstrapTagExporterContext,
  pairEdgeId,
  pairIdentitySignatureHash,
  pairIdentitySignedMessage,
  policyHash,
  stableIdentityCommitment,
} from "./derivations";
import { consumeReservedExpectedIdentityHelloTrialForPairOpenV1 } from "./identityHelloTrial";
import { deriveOperationId, encodeOperation } from "./operation";
import {
  OperationPayloadValidationError,
  validatePresenceOwnershipV1,
} from "./operationPayload";
import {
  PairBootstrapPlaintextKindError,
  openPairBootstrapV1,
} from "./pairCrypto";
import {
  PairPlaintextError,
  encodePairBootstrapInfoV1,
  pairIdentityUnsignedProjectionV1,
} from "./pairPlaintext";
import { encodePairStepEnvelopeV1 } from "./pairStepEnvelope";
import {
  snapshotActivePairOperationCandidate,
  snapshotHistoricalPairPresenceEvidence,
} from "./coreReduce";
import {
  AdmissionPolicySemanticError,
  validateAndCopyPairAttemptLeaseV1,
} from "./admissionPolicy";
import { decodeRoomPolicyV1 } from "../roomPolicy";
import { verify } from "../cryptography/ed25519";
import {
  HybridKemInvalidPublicKeyError,
  validateMlKem768X25519PublicKey,
} from "../cryptography/hybridKem";
import { verifyIdentityCrossSig } from "../cryptography/identityCrossSig";
import { pairOuterBindingV1Schema, pairPlaintextV1Schema } from "./schemas";

import type { LibCrypto } from "../cryptography/libcrypto";
import type {
  ActivePairOperationCandidateSnapshotV1,
  ActivePairOperationCandidateV1,
  VerifiedHistoricalPairPresenceEvidenceV1,
  VerifiedHistoricalPairPresenceSnapshotV1,
} from "./coreReduce";
import type {
  ExpectedIdentityHelloTrialV1,
  ConsumedExpectedIdentityHelloTrialV1,
} from "./identityHelloTrial";
import type { PairAttemptLeaseV1 } from "./admissionPolicy";
import type {
  PairOuterBindingV1,
  PairOuterPrebindingV1,
  PairPlaintextV1,
  PairBootstrapInfoV1,
} from "./pairPlaintext";
import type { ReservedIdentityHelloOpenV1 } from "./pairOpenReservation";
import type { RoomPolicyV4 } from "./roomPolicyV4";

const U64_MAX = 0xffffffffffffffffn;

declare const verifiedIdentityHelloOpenBrand: unique symbol;

/** Opaque authenticated HELLO result. HelloRoot is never structurally exposed. */
export interface VerifiedIdentityHelloOpenV1 {
  readonly [verifiedIdentityHelloOpenBrand]: true;
}

export interface VerifiedIdentityHelloOpenSnapshotV1 {
  readonly version: 1;
  readonly helloOperationId: Uint8Array;
  readonly activeCandidate: ActivePairOperationCandidateSnapshotV1;
  readonly pairOuterBinding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceSnapshotV1;
  readonly remotePresenceEvidence: VerifiedHistoricalPairPresenceSnapshotV1;
  readonly pairIdentitySignatureHash: Uint8Array;
  /**
   * Pre-admission base lease. Sole Admit may validate a carried grant, narrow
   * this horizon, and persist the result atomically; this opener may not.
   */
  readonly basePairAttemptLease: PairAttemptLeaseV1;
  readonly trialOrdinal: number;
  readonly receiverKeyRecordRevision: bigint;
}

export type OpenReservedIdentityHelloResultV1 =
  | {
      readonly kind: "opened";
      readonly value: VerifiedIdentityHelloOpenV1;
    }
  | {
      readonly kind: "not-this-trial";
    }
  | {
      readonly kind: "rejected";
    }
  | {
      readonly kind: "deferred";
      readonly reason: "missing-presence-evidence";
    };

export class IdentityHelloOpenError extends Error {
  override readonly name = "IdentityHelloOpenError";

  constructor(message: string) {
    super(`identityHelloOpen: ${message}`);
  }
}

class AuthenticatedIdentityHelloRejected extends Error {
  override readonly name = "AuthenticatedIdentityHelloRejected";
}

class AuthenticatedIdentityHelloDeferred extends Error {
  override readonly name = "AuthenticatedIdentityHelloDeferred";
}

const fail = (message: string): never => {
  throw new IdentityHelloOpenError(message);
};

const rejectAuthenticated = (): never => {
  throw new AuthenticatedIdentityHelloRejected();
};

const deferMissingPresenceEvidence = (): never => {
  throw new AuthenticatedIdentityHelloDeferred();
};

interface PrivateVerifiedIdentityHelloOpen {
  readonly helloRoot: Uint8Array;
  readonly activeCandidate: ActivePairOperationCandidateV1;
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly remotePresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly bindingBytes: Uint8Array;
  readonly plaintextBytes: Uint8Array;
  readonly helloOperationId: Uint8Array;
  readonly pairIdentitySignatureHash: Uint8Array;
  readonly basePairAttemptLease: PairAttemptLeaseV1;
  readonly trialOrdinal: number;
  readonly receiverKeyRecordRevision: bigint;
}

interface AuthenticatedHelloFacts {
  readonly remotePresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly pairIdentitySignatureHash: Uint8Array;
  readonly basePairAttemptLease: PairAttemptLeaseV1;
}

const verifiedStates = new WeakMap<object, PrivateVerifiedIdentityHelloOpen>();
const genuineVerifiedOpens = new WeakSet<object>();

const requireVerifiedState = (
  value: VerifiedIdentityHelloOpenV1,
): PrivateVerifiedIdentityHelloOpen => {
  if (typeof value !== "object" || value === null)
    return fail("verified HELLO must be a genuine live process-local handle");
  const state = verifiedStates.get(value);
  if (state === undefined)
    return fail("verified HELLO must be a genuine live process-local handle");
  return state;
};

const checkedAddU64 = (left: bigint, right: bigint): bigint => {
  if (left < 0n || right < 0n || left > U64_MAX - right)
    return rejectAuthenticated();
  return left + right;
};

const minimum = (left: bigint, right: bigint): bigint =>
  left < right ? left : right;

const copyVerifiedSnapshot = (
  state: PrivateVerifiedIdentityHelloOpen,
): VerifiedIdentityHelloOpenSnapshotV1 => ({
  version: 1,
  helloOperationId: Uint8Array.from(state.helloOperationId),
  activeCandidate: snapshotActivePairOperationCandidate(state.activeCandidate),
  pairOuterBinding: decodeCanonicalStrict(
    pairOuterBindingV1Schema,
    state.bindingBytes,
  ) as PairOuterBindingV1,
  plaintext: decodeCanonicalStrict(
    pairPlaintextV1Schema,
    state.plaintextBytes,
  ) as PairPlaintextV1,
  localPresenceEvidence: snapshotHistoricalPairPresenceEvidence(
    state.localPresenceEvidence,
  ),
  remotePresenceEvidence: snapshotHistoricalPairPresenceEvidence(
    state.remotePresenceEvidence,
  ),
  pairIdentitySignatureHash: Uint8Array.from(state.pairIdentitySignatureHash),
  basePairAttemptLease: validateAndCopyPairAttemptLeaseV1(
    state.basePairAttemptLease,
  ),
  trialOrdinal: state.trialOrdinal,
  receiverKeyRecordRevision: state.receiverKeyRecordRevision,
});

const assertInternalEvidenceSnapshot = async (
  evidence: VerifiedHistoricalPairPresenceSnapshotV1,
): Promise<void> => {
  if (
    !bytesEqual(
      encodeOperation(evidence.operation),
      evidence.exactPresenceOperationBytes,
    ) ||
    !bytesEqual(
      await deriveOperationId(evidence.operation),
      evidence.presenceOperationId,
    )
  )
    fail("historical presence provenance changed after capture");
};

const basePairAttemptLease = (
  helloOperationId: Uint8Array,
  pairEdgeIdBytes: Uint8Array,
  endpointPresenceOperationIds: readonly [Uint8Array, Uint8Array],
  attemptMode: "planner" | "explicit",
  helloLogicalWindow: bigint,
  outerExpiry: bigint,
  roomPolicy: RoomPolicyV4,
): PairAttemptLeaseV1 => {
  const retentionHorizon = checkedAddU64(
    helloLogicalWindow,
    BigInt(roomPolicy.protocolLimits.pairControlRetentionWindows),
  );
  const validThroughLogicalWindow = minimum(outerExpiry, retentionHorizon);
  if (validThroughLogicalWindow < helloLogicalWindow)
    return rejectAuthenticated();

  try {
    return validateAndCopyPairAttemptLeaseV1({
      version: 1,
      helloOperationId,
      pairEdgeId: pairEdgeIdBytes,
      endpointPresenceOperationIds,
      attemptMode,
      helloLogicalWindow,
      validThroughLogicalWindow,
    });
  } catch (error) {
    if (error instanceof AdmissionPolicySemanticError)
      return rejectAuthenticated();
    throw error;
  }
};

const validateAuthenticatedHello = async (options: {
  readonly consumed: ConsumedExpectedIdentityHelloTrialV1;
  readonly binding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
  readonly helloOperationId: Uint8Array;
  readonly module: LibCrypto;
}): Promise<AuthenticatedHelloFacts> => {
  const { consumed, binding, plaintext, helloOperationId, module } = options;
  const trial = consumed.snapshot;
  const active = trial.activeCandidate;
  const localEvidence = snapshotHistoricalPairPresenceEvidence(
    consumed.localPresenceEvidence,
  );

  if (
    plaintext.kind !== "IDENTITY_HELLO" ||
    plaintext.body.kind !== "IDENTITY_HELLO" ||
    plaintext.direction !== 0 ||
    plaintext.pairSequence !== 0n ||
    plaintext.previousPairOperationId !== null ||
    plaintext.pairDependencies.length !== 0
  )
    return rejectAuthenticated();
  if (
    !bytesEqual(
      plaintext.endpointPresenceOperationIds[1],
      localEvidence.presenceOperationId,
    ) ||
    !bytesEqual(
      plaintext.endpointPresenceOperationIds[1],
      trial.localPresenceOperationId,
    )
  )
    return rejectAuthenticated();
  if (
    !bytesEqual(binding.pairRoutingTag, active.envelope.pairRoutingTag) ||
    !bytesEqual(binding.semanticSlot, active.operation.semanticSlot)
  )
    return rejectAuthenticated();

  await assertInternalEvidenceSnapshot(localEvidence);

  const expectedPairEdgeId = await pairEdgeId(
    trial.roomContextId,
    plaintext.endpointPresenceOperationIds[0],
    plaintext.endpointPresenceOperationIds[1],
  );
  if (!bytesEqual(expectedPairEdgeId, plaintext.pairEdgeId))
    return rejectAuthenticated();

  const hello = plaintext.body.value;
  const senderStableKey = hello.senderIdentity.ed25519PublicKey;
  if (
    bytesEqual(
      senderStableKey,
      trial.receiverCustody.localStableEd25519PublicKey,
    )
  )
    return rejectAuthenticated();

  const expectedSenderCommitment = await stableIdentityCommitment(
    trial.roomContextId,
    senderStableKey,
  );
  if (!bytesEqual(hello.senderPresenceCommitment, expectedSenderCommitment))
    return rejectAuthenticated();

  /*
   * Prove every self-contained identity claim before a missing historical
   * presence can request bounded reconciliation. A RoomRoot holder therefore
   * cannot enqueue arbitrary presence IDs with an unauthenticated HELLO.
   */
  if (
    !(await verifyIdentityCrossSig(
      hello.senderIdentity.x25519PublicKey,
      hello.senderIdentity.x25519CrossSignature,
      senderStableKey,
      module,
    ))
  )
    return rejectAuthenticated();

  const unsignedProjection = pairIdentityUnsignedProjectionV1(plaintext);
  const signatureHash = await pairIdentitySignatureHash(
    binding,
    unsignedProjection,
  );
  const signedMessage = await pairIdentitySignedMessage(
    binding,
    unsignedProjection,
  );
  try {
    if (
      !(await verify(
        signedMessage,
        hello.identityTranscriptSignature,
        senderStableKey,
        module,
      ))
    )
      return rejectAuthenticated();
  } finally {
    signedMessage.fill(0);
  }
  try {
    validateMlKem768X25519PublicKey(hello.responseHybridKemPublicKey, module);
  } catch (error) {
    if (error instanceof HybridKemInvalidPublicKeyError)
      return rejectAuthenticated();
    throw error;
  }

  const remoteHandle = consumed.resolveHistoricalPresenceEvidence(
    plaintext.endpointPresenceOperationIds[0],
  );
  if (remoteHandle === null) return deferMissingPresenceEvidence();
  const remoteEvidence = snapshotHistoricalPairPresenceEvidence(remoteHandle);

  const helloLogicalWindow = active.operation.logicalWindow;
  if (
    !bytesEqual(
      remoteEvidence.presenceOperationId,
      plaintext.endpointPresenceOperationIds[0],
    ) ||
    remoteEvidence.provedAtLogicalWindow !== helloLogicalWindow ||
    remoteEvidence.operation.logicalWindow > helloLogicalWindow ||
    helloLogicalWindow >
      remoteEvidence.presence.core.validThroughLogicalWindow ||
    active.referenceWindow > remoteEvidence.retainThroughLogicalWindow ||
    !bytesEqual(remoteEvidence.roomContextId, trial.roomContextId) ||
    !bytesEqual(
      remoteEvidence.exactCoreStateBytes,
      trial.historicalEvidenceView.exactCoreStateBytes,
    ) ||
    !bytesEqual(
      hello.senderPresenceCommitment,
      remoteEvidence.presence.core.stableIdentityCommitment,
    )
  )
    return rejectAuthenticated();

  await assertInternalEvidenceSnapshot(remoteEvidence);
  try {
    await validatePresenceOwnershipV1(
      remoteEvidence.operation,
      remoteEvidence.presence,
      senderStableKey,
      {
        roomContextId: trial.roomContextId,
        roomPolicy: trial.roomPolicy,
      },
      module,
    );
  } catch (error) {
    if (error instanceof OperationPayloadValidationError)
      return rejectAuthenticated();
    throw error;
  }

  return {
    remotePresenceEvidence: remoteHandle,
    pairIdentitySignatureHash: signatureHash,
    basePairAttemptLease: basePairAttemptLease(
      helloOperationId,
      expectedPairEdgeId,
      [
        plaintext.endpointPresenceOperationIds[0],
        plaintext.endpointPresenceOperationIds[1],
      ],
      hello.attemptMode,
      helloLogicalWindow,
      active.operation.expiresAfterWindow,
      trial.roomPolicy,
    ),
  };
};

const authenticatedCodecFailure = (error: unknown): boolean =>
  error instanceof AuthenticatedIdentityHelloRejected ||
  error instanceof CanonicalSchemaError ||
  error instanceof PairPlaintextError ||
  error instanceof PairBootstrapPlaintextKindError;

/**
 * Consume one committed reservation and try its exact expected HELLO trial.
 *
 * Reservation and trial consumption happen synchronously before the first
 * await. `not-this-trial` means the routing tag or HPKE authentication did not
 * match. `rejected` means authenticated bytes failed the closed HELLO identity
 * gate. Provenance, programming, storage, or cryptographic infrastructure
 * failures throw.
 */
export const openReservedIdentityHelloV1 = async (
  capability: ReservedIdentityHelloOpenV1,
  trial: ExpectedIdentityHelloTrialV1,
  module: LibCrypto,
): Promise<OpenReservedIdentityHelloResultV1> => {
  const consumed = consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
    capability,
    trial,
  );
  const cryptoModule = module;
  const recipientSeed = consumed.recipientHybridKemSecretSeed;
  const roomRoot = consumed.roomRoot;
  let openedRoot: Uint8Array | undefined;
  let transferredRoot = false;

  try {
    const trialSnapshot = consumed.snapshot;
    const active = trialSnapshot.activeCandidate;
    const operation = active.operation;
    const envelope = active.envelope;
    if (
      operation.kind !== "PAIR_STEP" ||
      operation.lifetime !== "PAIR_CAUSAL" ||
      operation.operationPayloadClass !== 0 ||
      operation.dependencies.length !== 0 ||
      envelope.bootstrapHeader === null ||
      envelope.nonce !== null
    )
      return fail("consumed trial lost its class-0 HELLO outer framing");

    const helloOperationId = await deriveOperationId(operation);
    if (!bytesEqual(helloOperationId, trialSnapshot.activeOperationId))
      return fail("active operation ID changed after trial capture");
    const policyDigest = await policyHash(trialSnapshot.roomPolicy);
    const headerHash = await pairBootstrapHeaderHash(envelope.bootstrapHeader);
    const roomPqMode = decodeRoomPolicyV1(
      trialSnapshot.roomPolicy.sessionPolicyV1,
    ).pqMode;

    const prebinding: PairOuterPrebindingV1 = {
      version: 1,
      roomContextConfirmation: operation.roomContextConfirmation,
      policyHash: policyDigest,
      logicalWindow: operation.logicalWindow,
      expiresAfterWindow: operation.expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: operation.authorEpochEd25519Key,
      authorSequence: operation.authorSequence,
      previousAuthorOperationId: operation.previousAuthorOperationId,
      kind: "PAIR_STEP",
      dependencies: [],
      operationPayloadClass: 0,
      bootstrapHeaderHash: headerHash,
      nonce: null,
    };
    const bootstrapInfo: PairBootstrapInfoV1 = {
      version: 1,
      pairBootstrapSuite: trialSnapshot.roomPolicy.pairBootstrapSuite,
      roomContextConfirmation: operation.roomContextConfirmation,
      policyHash: policyDigest,
      stepKind: "IDENTITY_HELLO",
      logicalWindow: operation.logicalWindow,
      expiresAfterWindow: operation.expiresAfterWindow,
      authorEpochEd25519Key: operation.authorEpochEd25519Key,
      authorSequence: operation.authorSequence,
      previousAuthorOperationId: operation.previousAuthorOperationId,
      operationPayloadClass: 0,
      recipientBinding: {
        kind: "presence",
        presenceOperationId: trialSnapshot.localPresenceOperationId,
      },
    };

    /*
     * Validate every provenance-derived structural input outside the catch
     * that maps authenticated plaintext codec failures to `rejected`.
     */
    const encodedInfo = encodePairBootstrapInfoV1(bootstrapInfo);
    const tagContext = pairBootstrapTagExporterContext(prebinding);
    const encodedEnvelope = encodePairStepEnvelopeV1(envelope, 0);
    encodedInfo.fill(0);
    tagContext.fill(0);
    encodedEnvelope.fill(0);

    let authenticatedFacts: AuthenticatedHelloFacts | undefined;
    let opened: Awaited<ReturnType<typeof openPairBootstrapV1>>;
    try {
      opened = await openPairBootstrapV1({
        module: cryptoModule,
        recipientHybridKemSecretKey: recipientSeed,
        psk: roomRoot,
        bootstrapInfo,
        prebinding,
        envelope,
        operationPayloadClass: 0,
        roomPqMode,
        validateAuthenticatedPlaintext: async (binding, plaintext) => {
          try {
            authenticatedFacts = await validateAuthenticatedHello({
              consumed,
              binding,
              plaintext,
              helloOperationId,
              module: cryptoModule,
            });
          } catch (error) {
            /*
             * PairCrypto's canonical/plaintext errors before this callback
             * describe peer-authenticated bytes and become `rejected` below.
             * The same error classes here can only come from our opaque
             * evidence/projection machinery after PairCrypto already
             * validated the plaintext, so preserve them as internal faults.
             */
            if (
              error instanceof CanonicalSchemaError ||
              error instanceof PairPlaintextError
            )
              return fail(
                "authenticated validator encountered invalid internal state",
              );
            throw error;
          }
        },
      });
    } catch (error) {
      if (error instanceof AuthenticatedIdentityHelloDeferred)
        return {
          kind: "deferred",
          reason: "missing-presence-evidence",
        };
      if (authenticatedCodecFailure(error)) return { kind: "rejected" };
      throw error;
    }

    if (opened === null) return { kind: "not-this-trial" };
    openedRoot = opened.bootstrapRoot;
    if (authenticatedFacts === undefined)
      return fail("HPKE open returned without authenticated HELLO facts");

    const handle = Object.freeze({}) as VerifiedIdentityHelloOpenV1;
    genuineVerifiedOpens.add(handle);
    verifiedStates.set(handle, {
      helloRoot: openedRoot,
      activeCandidate: consumed.activeCandidate,
      localPresenceEvidence: consumed.localPresenceEvidence,
      remotePresenceEvidence: authenticatedFacts.remotePresenceEvidence,
      bindingBytes: encodeCanonical(pairOuterBindingV1Schema, opened.binding),
      plaintextBytes: encodeCanonical(pairPlaintextV1Schema, opened.plaintext),
      helloOperationId: Uint8Array.from(helloOperationId),
      pairIdentitySignatureHash: Uint8Array.from(
        authenticatedFacts.pairIdentitySignatureHash,
      ),
      basePairAttemptLease: authenticatedFacts.basePairAttemptLease,
      trialOrdinal: trialSnapshot.trialOrdinal,
      receiverKeyRecordRevision: trialSnapshot.receiverKeyRecordRevision,
    });
    transferredRoot = true;
    return { kind: "opened", value: handle };
  } finally {
    recipientSeed.fill(0);
    roomRoot.fill(0);
    if (!transferredRoot) openedRoot?.fill(0);
  }
};

/** Return a fresh deeply owned snapshot containing no HelloRoot. */
export const snapshotVerifiedIdentityHelloOpenV1 = (
  value: VerifiedIdentityHelloOpenV1,
): VerifiedIdentityHelloOpenSnapshotV1 =>
  copyVerifiedSnapshot(requireVerifiedState(value));

/** Wipe the retained HelloRoot. Idempotent for a genuine handle. */
export const destroyVerifiedIdentityHelloOpenV1 = (
  value: VerifiedIdentityHelloOpenV1,
): void => {
  if (
    typeof value !== "object" ||
    value === null ||
    !genuineVerifiedOpens.has(value)
  )
    return fail("verified HELLO must be a genuine process-local handle");
  const state = verifiedStates.get(value);
  if (state === undefined) return;
  state.helloRoot.fill(0);
  verifiedStates.delete(value);
};
