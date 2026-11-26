/**
 * Pair driver for the flagged two-store prototype.
 *
 * This module is the first caller that runs the pair-bootstrap cryptography
 * end to end: PRESENCE, the two-flight HPKE identity bootstrap
 * (`IDENTITY_HELLO` / `IDENTITY_ACCEPT`), the derived `EstablishedPairRoot`,
 * and the established-flight `TRANSPORT_OFFER` / `TRANSPORT_ANSWER` exchange
 * that carries SDP inside a pair-encrypted, class-padded pair operation. It
 * ends at the handoff facts a protocol-v4 handshake needs — it opens no
 * `RTCPeerConnection`, performs no I/O, and persists nothing.
 *
 * WHAT THIS DELIBERATELY BYPASSES. The prototype runs an explicit OPEN policy:
 * any capability holder is admitted. It therefore does not consult the
 * reservation / trial / admission kernel (`identityHelloTrial.ts`,
 * `identityHelloOpen.ts`, `identityHelloAdmission.ts`), whose exported surface
 * still terminates at `policy-allowed-pre-topology` and never releases
 * HelloRoot. Instead `openIdentityHelloOpenPolicyPrototype` below calls
 * `openPairBootstrapV1` directly and replicates, check for check, the closed
 * identity gate that `identityHelloOpen.ts:567-742` performs inside its
 * `validateAuthenticatedPlaintext` callback. What it drops is the durable
 * pair-open budget, the one-use reservation capability, the fenced historical
 * presence-evidence view, and `Admit()` — not one identity check. This is the
 * honest equivalent of the spec's `eligibility="open"` room with no deny-list
 * (design doc §2, §4.6), and it is not conformant v0.4.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte.
 */

import {
  captureActivePairOperationCandidate,
  coreReduce,
  snapshotActivePairOperationCandidate,
} from "../coreReduce";
import {
  confirmedPairTranscriptId,
  establishedPairRoot,
  pairBootstrapHeaderHash,
  pairEdgeId,
  pairIdentitySignedMessage,
  pairSemanticSlot,
  policyHash,
  presenceOwnershipSignedMessage,
  presenceProofTranscriptHash,
  presenceSemanticSlot,
  rendezvousChannelId,
  roomRoot,
  stableEdgeAttemptClaimSignedMessage,
  stableEdgeId,
  stableIdentityCommitment,
  transportNegotiationTranscriptId,
  transportOfferCandidateId,
} from "../derivations";
import {
  createOperationValidationContext,
  deriveOperationId,
  encodeOperation,
  operationPaddingFor,
  operationValidationContextAt,
  signOperation,
} from "../operation";
import {
  encodePresenceV1,
  validatePresenceOwnershipV1,
} from "../operationPayload";
import {
  openPairBootstrapV1,
  openPairStepV1,
  sealPairBootstrapV1,
  sealPairStepV1,
} from "../pairCrypto";
import {
  createEmptyPairAcceptedSlotLedgerV1,
  previewAuthenticatedPairSlotV1,
  recordAcceptedPairSlotV1,
} from "../pairLedger";
import {
  padPairPlaintextV1,
  pairIdentityUnsignedProjectionV1,
} from "../pairPlaintext";
import { encodePairStepEnvelopeV1 } from "../pairStepEnvelope";
import {
  copyBlindDefaultPolicy,
  decodeRoomPolicyV4,
  encodeRoomPolicyV4,
} from "../roomPolicyV4";
import { RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1 } from "../schemas";
import { newKeyPair, sign, verify } from "../../cryptography/ed25519";
import { deriveHpkeRecipientKeyPair } from "../../cryptography/hpke";
import {
  HybridKemInvalidPublicKeyError,
  validateMlKem768X25519PublicKey,
} from "../../cryptography/hybridKem";
import { verifyIdentityCrossSig } from "../../cryptography/identityCrossSig";
import { decodeRoomPolicyV1 } from "../../roomPolicy";
import {
  buildOfferCandidates,
  compareBytes,
  decodeSdpUtf8,
  selectWebRtcCandidate,
  validateWebRtcSdp,
} from "./transportCandidates";

import type {
  ActivePairOperationCandidateSnapshotV1,
  CoreRoomStateV1,
  OuterValidatedIdentifiedOperationV1,
} from "../coreReduce";
import type {
  AuthenticatedRoomOperationV1,
  OperationPayloadClassV1,
  OperationValidationContext,
  UnsignedRoomOperationV1,
} from "../operation";
import type { PresenceV1 } from "../operationPayload";
import type { PairBootstrapOuterFieldsV1 } from "../pairCrypto";
import type {
  PairAcceptedSlotLedgerV1,
  PairSlotAcceptanceCandidateV1,
} from "../pairLedger";
import type {
  PairBootstrapInfoV1,
  PairIdentityHelloV1,
  PairOuterBindingV1,
  PairOuterPrebindingV1,
  PairPlaintextV1,
  PairTransportAnswerV1,
  PairTransportOfferV1,
  StableEdgeAttemptClaimUnsignedV1,
  StableEdgeAttemptClaimV1,
} from "../pairPlaintext";
import type { RoomPolicyV4 } from "../roomPolicyV4";
import type { LibCrypto } from "../../cryptography/libcrypto";
import type { RoomPqMode } from "../../roomPolicy";
import type { ServiceWorkKindV1 } from "./workKinds";

export class PairDriverError extends Error {
  override readonly name = "PairDriverError";

  constructor(message: string) {
    super(`pairDriver: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new PairDriverError(message);
};

const ZERO32 = new Uint8Array(32);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  compareBytes(left, right) === 0;

/**
 * The endpoint side of a complete-ICE WebRTC negotiation.
 *
 * Every method returns or consumes the exact UTF-8 SDP bytes the engine
 * produced; Section 4.12 forbids any parse-and-reserialize between them.
 */
export interface TransportCandidateProvider {
  /** Complete-ICE offer, bootstrap data channel already created. */
  createOffer(): Promise<Uint8Array>;
  /** Set the remote offer and return the complete-ICE answer. */
  acceptOffer(remoteSdp: Uint8Array): Promise<Uint8Array>;
  acceptAnswer(remoteSdp: Uint8Array): Promise<void>;
}

export type PairDriverPhase =
  | "idle"
  | "presence-published"
  | "peer-observed"
  | "hello-sent"
  | "hello-opened"
  | "accepted"
  | "offer-sent"
  | "offer-opened"
  | "answered"
  | "handoff"
  | "failed";

export type PairEndpointRole = "initiator" | "responder";

/** Everything a protocol-v4 handshake needs once the pair exchange completes. */
export interface HandoffFacts {
  readonly rendezvousChannelId: Uint8Array;
  readonly localFingerprint: Uint8Array;
  readonly remoteFingerprint: Uint8Array;
  readonly sessionRole: PairEndpointRole;
  readonly rendezvousRole: PairEndpointRole;
  readonly peerStableEd25519PublicKey: Uint8Array;
  readonly stableEdgeId: Uint8Array;
}

export interface PairDriverIdentity {
  readonly ed25519PublicKey: Uint8Array;
  readonly ed25519SecretKey: Uint8Array;
  readonly x25519PublicKey: Uint8Array;
  readonly x25519CrossSignature: Uint8Array;
}

export interface PairDriverOptions {
  readonly module: LibCrypto;
  readonly capability: Uint8Array;
  readonly roomPolicy?: RoomPolicyV4;
  readonly identity: PairDriverIdentity;
  readonly publish: (
    operation: AuthenticatedRoomOperationV1,
    workKind: ServiceWorkKindV1,
  ) => void;
  readonly transport: TransportCandidateProvider;
  readonly clock: { nowMs(): bigint };
  readonly random: (length: number) => Uint8Array;
  readonly onPhase?: (phase: PairDriverPhase, detail?: string) => void;
  /**
   * Publish a PRESENCE whose `stableOwnershipSignature` is not the stable
   * key's, so this prototype's own tests can prove that both identity
   * validators verify that proof.
   *
   * The defect cannot be injected from outside the driver: both endpoints must
   * agree on the exact presence operation IDs before either identity flight
   * validates, so a presence forged by a third party is rejected on the
   * endpoint tuple long before the ownership proof is reached. Never set this
   * in a real room.
   *
   * @internal
   */
  readonly forgePresenceOwnershipForPrototypeTests?: boolean;
}

interface ObservedPresence {
  readonly operationId: Uint8Array;
  readonly operation: AuthenticatedRoomOperationV1;
  readonly presence: PresenceV1;
}

export interface IdentityHelloOpenPolicyPrototypeOptions {
  readonly module: LibCrypto;
  readonly roomPqMode: RoomPqMode;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly policyHash: Uint8Array;
  readonly roomRoot: Uint8Array;
  readonly recipientHybridKemSecretKey: Uint8Array;
  readonly localPresenceOperationId: Uint8Array;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly remotePresence: ObservedPresence;
  readonly expectedPairEdgeId: Uint8Array;
  readonly candidate: ActivePairOperationCandidateSnapshotV1;
}

export interface IdentityHelloOpenPolicyPrototypeResultV1 {
  readonly bootstrapRoot: Uint8Array;
  readonly hello: PairIdentityHelloV1;
}

/**
 * Open one candidate `IDENTITY_HELLO` under the prototype's explicit OPEN
 * admission policy.
 *
 * `null` means "not this candidate" (routing tag, KEM, or AEAD mismatch) and
 * must be ignored. A throw means authenticated bytes failed the closed
 * identity gate and the caller must account it as a rejected pair attempt.
 *
 * The validator below is the same list `identityHelloOpen.ts:567-742` runs.
 * What it does NOT do is reserve pair-open budget, consume a one-use
 * reservation capability, resolve remote presence through a fenced historical
 * evidence view, or call `Admit()`: this prototype admits every capability
 * holder by construction and says so (see the module docblock).
 */
export const openIdentityHelloOpenPolicyPrototype = async (
  options: IdentityHelloOpenPolicyPrototypeOptions,
): Promise<IdentityHelloOpenPolicyPrototypeResultV1 | null> => {
  const candidate = options.candidate;
  const operation = candidate.operation;
  const envelope = candidate.envelope;
  if (
    operation.kind !== "PAIR_STEP" ||
    operation.lifetime !== "PAIR_CAUSAL" ||
    operation.operationPayloadClass !== 0 ||
    operation.dependencies.length !== 0 ||
    envelope.bootstrapHeader === null ||
    envelope.nonce !== null
  )
    return null;

  const prebinding: PairOuterPrebindingV1 = {
    version: 1,
    roomContextConfirmation: operation.roomContextConfirmation,
    policyHash: options.policyHash,
    logicalWindow: operation.logicalWindow,
    expiresAfterWindow: operation.expiresAfterWindow,
    lifetime: "PAIR_CAUSAL",
    authorEpochEd25519Key: operation.authorEpochEd25519Key,
    authorSequence: operation.authorSequence,
    previousAuthorOperationId: operation.previousAuthorOperationId,
    kind: "PAIR_STEP",
    dependencies: [],
    operationPayloadClass: 0,
    bootstrapHeaderHash: await pairBootstrapHeaderHash(
      envelope.bootstrapHeader,
    ),
    nonce: null,
  };
  const bootstrapInfo: PairBootstrapInfoV1 = {
    version: 1,
    pairBootstrapSuite: options.roomPolicy.pairBootstrapSuite,
    roomContextConfirmation: operation.roomContextConfirmation,
    policyHash: options.policyHash,
    stepKind: "IDENTITY_HELLO",
    logicalWindow: operation.logicalWindow,
    expiresAfterWindow: operation.expiresAfterWindow,
    authorEpochEd25519Key: operation.authorEpochEd25519Key,
    authorSequence: operation.authorSequence,
    previousAuthorOperationId: operation.previousAuthorOperationId,
    operationPayloadClass: 0,
    recipientBinding: {
      kind: "presence",
      presenceOperationId: options.localPresenceOperationId,
    },
  };

  let hello: PairIdentityHelloV1 | undefined;
  const opened = await openPairBootstrapV1({
    module: options.module,
    recipientHybridKemSecretKey: options.recipientHybridKemSecretKey,
    psk: options.roomRoot,
    bootstrapInfo,
    prebinding,
    envelope,
    operationPayloadClass: 0,
    roomPqMode: options.roomPqMode,
    validateAuthenticatedPlaintext: async (binding, plaintext) => {
      hello = await validateAuthenticatedHelloPrototype({
        ...options,
        binding,
        plaintext,
      });
    },
  });
  if (opened === null) return null;
  if (hello === undefined)
    return fail("HELLO validator did not produce its authenticated facts");
  return { bootstrapRoot: opened.bootstrapRoot, hello };
};

const rejectAuthenticated = (reason: string): never =>
  fail(`authenticated pair identity flight rejected: ${reason}`);

const validateAuthenticatedHelloPrototype = async (options: {
  readonly module: LibCrypto;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly localPresenceOperationId: Uint8Array;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly remotePresence: ObservedPresence;
  readonly expectedPairEdgeId: Uint8Array;
  readonly candidate: ActivePairOperationCandidateSnapshotV1;
  readonly binding: PairOuterBindingV1;
  readonly plaintext: PairPlaintextV1;
}): Promise<PairIdentityHelloV1> => {
  const { binding, plaintext, candidate, remotePresence, module } = options;
  if (
    plaintext.kind !== "IDENTITY_HELLO" ||
    plaintext.body.kind !== "IDENTITY_HELLO" ||
    plaintext.direction !== 0 ||
    plaintext.pairSequence !== 0n ||
    plaintext.previousPairOperationId !== null ||
    plaintext.pairDependencies.length !== 0
  )
    return rejectAuthenticated("HELLO slot shape");

  const endpoints = plaintext.endpointPresenceOperationIds;
  if (compareBytes(endpoints[0], endpoints[1]) >= 0)
    return rejectAuthenticated("endpoint presence ids are not ascending");
  if (
    !bytesEqual(endpoints[1], options.localPresenceOperationId) ||
    !bytesEqual(endpoints[0], remotePresence.operationId)
  )
    return rejectAuthenticated("HELLO names a different endpoint tuple");
  if (
    !bytesEqual(binding.pairRoutingTag, candidate.envelope.pairRoutingTag) ||
    !bytesEqual(binding.semanticSlot, candidate.operation.semanticSlot)
  )
    return rejectAuthenticated("binding does not match the outer operation");

  const expectedPairEdgeId = await pairEdgeId(
    options.roomContextId,
    endpoints[0],
    endpoints[1],
  );
  if (
    !bytesEqual(expectedPairEdgeId, plaintext.pairEdgeId) ||
    !bytesEqual(expectedPairEdgeId, options.expectedPairEdgeId)
  )
    return rejectAuthenticated("PairEdgeId does not recompute");

  const hello = plaintext.body.value;
  const senderStableKey = hello.senderIdentity.ed25519PublicKey;
  if (bytesEqual(senderStableKey, options.localStableEd25519PublicKey))
    return rejectAuthenticated("a presence cannot pair with itself");

  const expectedCommitment = await stableIdentityCommitment(
    options.roomContextId,
    senderStableKey,
  );
  if (
    !bytesEqual(hello.senderPresenceCommitment, expectedCommitment) ||
    !bytesEqual(
      hello.senderPresenceCommitment,
      remotePresence.presence.core.stableIdentityCommitment,
    )
  )
    return rejectAuthenticated("sender commitment does not bind its presence");

  if (
    !(await verifyIdentityCrossSig(
      hello.senderIdentity.x25519PublicKey,
      hello.senderIdentity.x25519CrossSignature,
      senderStableKey,
      module,
    ))
  )
    return rejectAuthenticated("X25519 identity cross-signature");

  const signedMessage = await pairIdentitySignedMessage(
    binding,
    pairIdentityUnsignedProjectionV1(plaintext),
  );
  let signatureValid: boolean;
  try {
    signatureValid = await verify(
      signedMessage,
      hello.identityTranscriptSignature,
      senderStableKey,
      module,
    );
  } finally {
    signedMessage.fill(0);
  }
  if (!signatureValid)
    return rejectAuthenticated("stable identity transcript signature");

  if (
    hello.responseHybridKemPublicKey.length !==
    RENDEZVOUS_HYBRID_KEM_PUBLIC_KEY_BYTES_V1
  )
    return rejectAuthenticated("response hybrid KEM public key width");
  try {
    validateMlKem768X25519PublicKey(hello.responseHybridKemPublicKey, module);
  } catch (error) {
    if (error instanceof HybridKemInvalidPublicKeyError)
      return rejectAuthenticated("response hybrid KEM public key");
    throw error;
  }

  await validatePresenceOwnershipV1(
    remotePresence.operation,
    remotePresence.presence,
    senderStableKey,
    {
      roomContextId: options.roomContextId,
      roomPolicy: options.roomPolicy,
    },
    module,
  );
  return hello;
};

/**
 * One room, one local presence, one pair edge, driven entirely from the
 * operations a carrier hands back.
 *
 * The driver is asynchronous but not reentrant: `start()` and `ingest()` must
 * be awaited in sequence. The composition (`index.ts`) keeps to that by
 * finishing `start()` before it arms the carrier schedule, whose deliveries
 * reach `ingest` one call at a time. Duplicate delivery is free — operations
 * are keyed by `OperationId` and each pair operation is handled at most once.
 */
export class PairDriver {
  readonly roomPolicy: RoomPolicyV4;

  private readonly module: LibCrypto;
  private readonly capability: Uint8Array;
  private readonly identity: PairDriverIdentity;
  private readonly publish: PairDriverOptions["publish"];
  private readonly transport: TransportCandidateProvider;
  private readonly clock: { nowMs(): bigint };
  private readonly random: (length: number) => Uint8Array;
  private readonly onPhase: PairDriverOptions["onPhase"];
  private readonly forgePresenceOwnership: boolean;

  private initialization: Promise<void> | null = null;
  private baseContext: OperationValidationContext | null = null;
  private cachedContext: OperationValidationContext | null = null;
  private cachedContextWindow: bigint | null = null;
  private roomContextIdBytes: Uint8Array | null = null;
  private roomRootBytes: Uint8Array | null = null;
  private policyHashBytes: Uint8Array | null = null;
  private roomPqModeValue: RoomPqMode | null = null;

  private authorPublicKey: Uint8Array | null = null;
  private authorSecretKey: Uint8Array | null = null;
  private authorChainWindow: bigint | null = null;
  private authorSequence = 0n;
  private lastOwnOperationId: Uint8Array | null = null;

  private stableCommitment: Uint8Array | null = null;
  private receiverSecretKey: Uint8Array | null = null;
  private localPresence: ObservedPresence | null = null;
  private remotePresence: ObservedPresence | null = null;

  private readonly knownOperations = new Map<
    string,
    OuterValidatedIdentifiedOperationV1
  >();
  private readonly ownOperationIds = new Set<string>();
  private readonly handledPairOperationIds = new Set<string>();

  private ledger: PairAcceptedSlotLedgerV1 =
    createEmptyPairAcceptedSlotLedgerV1();
  private rendezvousRole: PairEndpointRole | null = null;
  private endpoints: readonly [Uint8Array, Uint8Array] | null = null;
  private pairEdge: Uint8Array | null = null;

  private helloRoot: Uint8Array | null = null;
  private acceptRoot: Uint8Array | null = null;
  private establishedRoot: Uint8Array | null = null;
  private responseSecretKey: Uint8Array | null = null;
  private helloResponsePublicKey: Uint8Array | null = null;
  private helloOperationId: Uint8Array | null = null;
  private acceptOperationId: Uint8Array | null = null;
  private offerOperationId: Uint8Array | null = null;
  private answerOperationId: Uint8Array | null = null;
  private helloLogicalWindow: bigint | null = null;
  private confirmedTranscriptId: Uint8Array | null = null;
  private peerStableKey: Uint8Array | null = null;
  private offerWebRtcCandidateId: Uint8Array | null = null;
  private localSdp: Uint8Array | null = null;
  private remoteSdp: Uint8Array | null = null;

  private phaseValue: PairDriverPhase = "idle";
  private handoffFacts: HandoffFacts | null = null;

  constructor(options: PairDriverOptions) {
    /* Copy every caller-owned byte string before the first await. */
    this.module = options.module;
    this.capability = Uint8Array.from(options.capability);
    if (this.capability.length !== 32)
      fail("room capability must be exactly 32 bytes");
    /*
     * The policy is hashed into RoomContextId, so it must be byte-immutable for
     * this room's lifetime. Encode-then-decode yields an owned, validated copy
     * a caller can no longer mutate underneath PolicyHash.
     */
    this.roomPolicy =
      options.roomPolicy === undefined
        ? copyBlindDefaultPolicy()
        : decodeRoomPolicyV4(encodeRoomPolicyV4(options.roomPolicy));
    this.identity = {
      ed25519PublicKey: Uint8Array.from(options.identity.ed25519PublicKey),
      ed25519SecretKey: Uint8Array.from(options.identity.ed25519SecretKey),
      x25519PublicKey: Uint8Array.from(options.identity.x25519PublicKey),
      x25519CrossSignature: Uint8Array.from(
        options.identity.x25519CrossSignature,
      ),
    };
    this.publish = options.publish;
    this.transport = options.transport;
    this.clock = options.clock;
    this.random = options.random;
    this.onPhase = options.onPhase;
    this.forgePresenceOwnership =
      options.forgePresenceOwnershipForPrototypeTests === true;
  }

  get phase(): PairDriverPhase {
    return this.phaseValue;
  }

  get handoff(): HandoffFacts | null {
    return this.handoffFacts;
  }

  get roomContextId(): Uint8Array {
    if (this.roomContextIdBytes === null)
      return fail("room identity is not initialized yet");
    return this.roomContextIdBytes;
  }

  /** RoomRoot: the carrier-envelope and HELLO PSK secret for this room. */
  get roomRoot(): Uint8Array {
    if (this.roomRootBytes === null)
      return fail("room identity is not initialized yet");
    return this.roomRootBytes;
  }

  get policyHash(): Uint8Array {
    if (this.policyHashBytes === null)
      return fail("room identity is not initialized yet");
    return this.policyHashBytes;
  }

  /** The cached room context rebound to one explicit reference window. */
  validationContextAt(
    referenceLogicalWindow: bigint,
  ): OperationValidationContext {
    if (this.baseContext === null)
      return fail("room identity is not initialized yet");
    if (
      this.cachedContext !== null &&
      this.cachedContextWindow === referenceLogicalWindow
    )
      return this.cachedContext;
    const context = operationValidationContextAt(
      this.baseContext,
      referenceLogicalWindow,
    );
    this.cachedContext = context;
    this.cachedContextWindow = referenceLogicalWindow;
    return context;
  }

  /** Publish this endpoint's PRESENCE for the current logical window. */
  async start(): Promise<void> {
    await this.ensureInitialized();
    if (this.localPresence !== null)
      return fail("this room already published a local presence");

    const logicalWindow = this.logicalWindow();
    const author = await newKeyPair(this.module);
    this.authorPublicKey = author.publicKey;
    this.authorSecretKey = author.secretKey;

    const ikm = this.random(32);
    const receiver = await deriveHpkeRecipientKeyPair(ikm, this.module);
    ikm.fill(0);
    /*
     * `openPairBootstrapV1` decapsulates with the KEM secret key, which the
     * labeled DeriveKeyPair mapping produces from the IKM. Keep that, not the
     * IKM, and wipe the key pair's own copy immediately.
     */
    this.receiverSecretKey = Uint8Array.from(receiver.secretKey);
    const rendezvousHybridKemPublicKey = Uint8Array.from(receiver.publicKey);
    receiver.destroy();

    this.stableCommitment = await stableIdentityCommitment(
      this.roomContextId,
      this.identity.ed25519PublicKey,
    );
    const validThrough =
      logicalWindow +
      BigInt(this.roomPolicy.protocolLimits.operationRetentionWindows);
    const core = {
      version: 1 as const,
      stableIdentityCommitment: this.stableCommitment,
      rendezvousHybridKemPublicKey,
      receiverKeyValidThroughLogicalWindow: validThrough,
      presenceNonce: this.random(32),
      validThroughLogicalWindow: validThrough,
    };
    const transcriptHash = await presenceProofTranscriptHash({
      roomContextId: this.roomContextId,
      policyHash: this.policyHash,
      logicalWindow,
      authorEpochEd25519Key: author.publicKey,
      core,
    });
    const ownershipMessage = presenceOwnershipSignedMessage(transcriptHash);
    let stableOwnershipSignature: Uint8Array;
    try {
      stableOwnershipSignature = await sign(
        ownershipMessage,
        this.identity.ed25519SecretKey,
        this.module,
      );
    } finally {
      ownershipMessage.fill(0);
    }
    if (this.forgePresenceOwnership)
      stableOwnershipSignature = new Uint8Array(64).fill(0xa5);
    const presence: PresenceV1 = {
      core,
      stableOwnershipSignature,
      authorityPermit: null,
    };
    const fixedPayload = encodePresenceV1(presence);
    const chain = this.nextAuthorFields(logicalWindow);
    const unsigned: UnsignedRoomOperationV1 = {
      version: 1,
      roomContextConfirmation:
        this.validationContextAt(logicalWindow).roomContextConfirmation,
      logicalWindow,
      expiresAfterWindow: validThrough,
      lifetime: "WINDOW_TRANSIENT",
      authorEpochEd25519Key: author.publicKey,
      authorSequence: chain.authorSequence,
      previousAuthorOperationId: chain.previousAuthorOperationId,
      kind: "PRESENCE",
      semanticSlot: await presenceSemanticSlot(
        author.publicKey,
        logicalWindow,
        core.presenceNonce,
      ),
      dependencies: [],
      operationPayloadClass: 0,
      fixedPayload,
      operationPadding: operationPaddingFor(0, fixedPayload.length),
    };
    const operation = await signOperation(
      unsigned,
      author.secretKey,
      this.module,
    );
    const operationId = await deriveOperationId(operation);
    this.recordOwnOperation(operationId);
    this.localPresence = { operationId, operation, presence };
    this.publish(operation, "PRESENCE");
    this.setPhase("presence-published");
  }

  /**
   * Fold one batch of carrier-delivered operations into the room, then drive
   * whatever pair step that makes possible.
   */
  async ingest(
    operations: readonly OuterValidatedIdentifiedOperationV1[],
  ): Promise<void> {
    await this.ensureInitialized();
    for (const candidate of operations) {
      const key = hex(candidate.operationId);
      if (!this.knownOperations.has(key))
        this.knownOperations.set(key, candidate);
    }
    if (this.isFailedEdge() || this.localPresence === null) return;

    const logicalWindow = this.logicalWindow();
    const state = await coreReduce(
      [...this.knownOperations.values()],
      this.validationContextAt(logicalWindow),
      this.module,
    );

    if (this.remotePresence === null) await this.observePeer(state);
    if (
      this.remotePresence !== null &&
      this.rendezvousRole === "initiator" &&
      this.phaseValue === "peer-observed"
    )
      await this.sendHello();

    for (const pairOperationId of state.activePairOuterOperationIds) {
      if (this.isFailedEdge()) return;
      const key = hex(pairOperationId);
      if (this.handledPairOperationIds.has(key)) continue;
      if (this.ownOperationIds.has(key)) {
        this.handledPairOperationIds.add(key);
        continue;
      }
      const candidate = this.knownOperations.get(key);
      if (candidate === undefined) continue;
      const snapshot = snapshotActivePairOperationCandidate(
        await captureActivePairOperationCandidate(candidate, state),
      );
      if (await this.handlePairOperation(snapshot))
        this.handledPairOperationIds.add(key);
    }
  }

  /**
   * Byte facts the browser harness greps its wire log for, so it can prove a
   * store never saw them.
   *
   * This deliberately exposes the room secret: `capabilityHex` is the room
   * capability itself, and the two SDP strings carry the DTLS fingerprints.
   * The audit is the only caller — the result must never be logged, persisted,
   * or sent anywhere.
   */
  auditSecrets(): {
    readonly capabilityHex: string;
    readonly roomContextIdHex: string;
    readonly stableKeyHex: string;
    readonly sdpLocal: string | null;
    readonly sdpRemote: string | null;
  } {
    return {
      capabilityHex: hex(this.capability),
      roomContextIdHex: hex(this.roomContextId),
      stableKeyHex: hex(this.identity.ed25519PublicKey),
      sdpLocal: this.localSdp === null ? null : decodeSdpUtf8(this.localSdp),
      sdpRemote: this.remoteSdp === null ? null : decodeSdpUtf8(this.remoteSdp),
    };
  }

  /** Wipe every secret this driver still owns. Idempotent. */
  destroy(): void {
    this.capability.fill(0);
    this.identity.ed25519SecretKey.fill(0);
    this.roomRootBytes?.fill(0);
    this.authorSecretKey?.fill(0);
    this.receiverSecretKey?.fill(0);
    this.responseSecretKey?.fill(0);
    this.helloRoot?.fill(0);
    this.acceptRoot?.fill(0);
    this.establishedRoot?.fill(0);
    this.roomRootBytes = null;
    this.authorSecretKey = null;
    this.receiverSecretKey = null;
    this.responseSecretKey = null;
    this.helloRoot = null;
    this.acceptRoot = null;
    this.establishedRoot = null;
  }

  /**
   * Seal and publish one `IDENTITY_HELLO` toward the observed peer presence.
   *
   * `ingest` calls this once when the local presence is the rendezvous
   * initiator. It is exposed so a test can prove that a second, distinct HELLO
   * for the same authenticated slot is a pair fork.
   *
   * @internal
   */
  async sendHello(): Promise<void> {
    const remote = this.requireRemotePresence();
    const endpoints = this.requireEndpoints();
    const logicalWindow = this.logicalWindow();
    const expiresAfterWindow =
      logicalWindow +
      BigInt(this.roomPolicy.protocolLimits.pairControlRetentionWindows);

    const ikm = this.random(32);
    const responseKeyPair = await deriveHpkeRecipientKeyPair(ikm, this.module);
    ikm.fill(0);
    const responseSecretKey = Uint8Array.from(responseKeyPair.secretKey);
    const responseHybridKemPublicKey = Uint8Array.from(
      responseKeyPair.publicKey,
    );
    responseKeyPair.destroy();

    const chain = this.nextAuthorFields(logicalWindow);
    const outerFields: PairBootstrapOuterFieldsV1 = {
      version: 1,
      roomContextConfirmation:
        this.validationContextAt(logicalWindow).roomContextConfirmation,
      policyHash: this.policyHash,
      logicalWindow,
      expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: this.requireAuthorPublicKey(),
      authorSequence: chain.authorSequence,
      previousAuthorOperationId: chain.previousAuthorOperationId,
      kind: "PAIR_STEP",
      dependencies: [],
      operationPayloadClass: 0,
    };
    const bootstrapInfo: PairBootstrapInfoV1 = {
      ...outerFieldsAsBootstrapInfo(outerFields, this.roomPolicy),
      stepKind: "IDENTITY_HELLO",
      recipientBinding: {
        kind: "presence",
        presenceOperationId: remote.operationId,
      },
    };

    const sealed = await sealPairBootstrapV1({
      module: this.module,
      recipientHybridKemPublicKey:
        remote.presence.core.rendezvousHybridKemPublicKey,
      psk: this.roomRoot,
      bootstrapInfo,
      outerFields,
      roomPqMode: this.roomPqMode,
      createSignedPlaintext: (binding) =>
        this.signIdentityPlaintext(
          {
            version: 1,
            kind: "IDENTITY_HELLO",
            pairEdgeId: this.requirePairEdge(),
            endpointPresenceOperationIds: endpoints,
            direction: 0,
            pairSequence: 0n,
            previousPairOperationId: null,
            pairDependencies: [],
            body: {
              kind: "IDENTITY_HELLO",
              value: {
                version: 1,
                attemptMode: "planner",
                senderIdentity: this.identityBundle(),
                senderPresenceCommitment: this.requireStableCommitment(),
                senderAdmissionGrant: null,
                responseHybridKemPublicKey,
                identityTranscriptSignature: new Uint8Array(64),
              },
            },
            pairPadding: new Uint8Array(0),
          },
          binding,
        ),
    });

    const operation = await this.signPairStepOperation(outerFields, sealed, 0);
    const operationId = await deriveOperationId(operation);
    this.helloRoot?.fill(0);
    this.responseSecretKey?.fill(0);
    this.helloRoot = sealed.bootstrapRoot;
    this.responseSecretKey = responseSecretKey;
    this.helloOperationId = operationId;
    this.helloLogicalWindow = logicalWindow;
    this.recordOwnOperation(operationId);
    this.publish(operation, "IDENTITY_HELLO");
    this.setPhase("hello-sent");
  }

  private async ensureInitialized(): Promise<void> {
    if (this.initialization === null) this.initialization = this.initialize();
    await this.initialization;
  }

  private async initialize(): Promise<void> {
    this.policyHashBytes = await policyHash(this.roomPolicy);
    this.baseContext = await createOperationValidationContext(
      this.capability,
      this.roomPolicy,
      this.logicalWindow(),
    );
    this.roomContextIdBytes = Uint8Array.from(this.baseContext.roomContextId);
    this.roomRootBytes = await roomRoot(this.capability, this.policyHashBytes);
    this.roomPqModeValue = decodeRoomPolicyV1(
      this.roomPolicy.sessionPolicyV1,
    ).pqMode;
  }

  private logicalWindow(): bigint {
    return this.clock.nowMs() / this.roomPolicy.protocolLimits.logicalWindowMs;
  }

  private get roomPqMode(): RoomPqMode {
    if (this.roomPqModeValue === null)
      return fail("room identity is not initialized yet");
    return this.roomPqModeValue;
  }

  /* A method, not a comparison: the phase changes inside other methods. */
  private isFailedEdge(): boolean {
    return this.phaseValue === "failed";
  }

  private setPhase(phase: PairDriverPhase, detail?: string): void {
    this.phaseValue = phase;
    this.onPhase?.(phase, detail);
  }

  private failEdge(detail: string): void {
    this.setPhase("failed", detail);
  }

  /**
   * Allocate the next slot on this author's chain. Chains never cross a
   * logical window, so a new window restarts at sequence 0 with no
   * predecessor.
   */
  private nextAuthorFields(logicalWindow: bigint): {
    readonly authorSequence: bigint;
    readonly previousAuthorOperationId: Uint8Array | null;
  } {
    if (this.authorChainWindow !== logicalWindow) {
      this.authorChainWindow = logicalWindow;
      this.authorSequence = 0n;
      this.lastOwnOperationId = null;
    }
    return {
      authorSequence: this.authorSequence,
      previousAuthorOperationId: this.lastOwnOperationId,
    };
  }

  private recordOwnOperation(operationId: Uint8Array): void {
    this.ownOperationIds.add(hex(operationId));
    this.lastOwnOperationId = Uint8Array.from(operationId);
    this.authorSequence += 1n;
  }

  private identityBundle(): {
    readonly ed25519PublicKey: Uint8Array;
    readonly x25519PublicKey: Uint8Array;
    readonly x25519CrossSignature: Uint8Array;
  } {
    return {
      ed25519PublicKey: Uint8Array.from(this.identity.ed25519PublicKey),
      x25519PublicKey: Uint8Array.from(this.identity.x25519PublicKey),
      x25519CrossSignature: Uint8Array.from(this.identity.x25519CrossSignature),
    };
  }

  private requireStableCommitment(): Uint8Array {
    if (this.stableCommitment === null)
      return fail("local stable commitment is not derived yet");
    return this.stableCommitment;
  }

  private requireAuthorPublicKey(): Uint8Array {
    if (this.authorPublicKey === null)
      return fail("author epoch key is not created yet");
    return this.authorPublicKey;
  }

  private requireAuthorSecretKey(): Uint8Array {
    if (this.authorSecretKey === null)
      return fail("author epoch key is not created yet");
    return this.authorSecretKey;
  }

  private requireRemotePresence(): ObservedPresence {
    if (this.remotePresence === null)
      return fail("no remote presence has been observed yet");
    return this.remotePresence;
  }

  private requireLocalPresence(): ObservedPresence {
    if (this.localPresence === null)
      return fail("no local presence has been published yet");
    return this.localPresence;
  }

  private requireEndpoints(): readonly [Uint8Array, Uint8Array] {
    if (this.endpoints === null)
      return fail("the pair edge endpoints are not resolved yet");
    return this.endpoints;
  }

  private requirePairEdge(): Uint8Array {
    if (this.pairEdge === null)
      return fail("the pair edge is not resolved yet");
    return this.pairEdge;
  }

  /**
   * Pick the one other presence in the room and fix the rendezvous roles.
   *
   * The stable ownership proof cannot be checked here: the stable key is
   * deliberately absent from room-wide presence and only arrives inside the
   * identity flight, where the HELLO validator does verify it. Under the
   * prototype's OPEN policy every other presence is an acceptable peer.
   */
  private async observePeer(state: CoreRoomStateV1): Promise<void> {
    const local = this.requireLocalPresence();
    const commitment = this.requireStableCommitment();
    let remote: ObservedPresence | null = null;
    for (const fact of state.observedPresences) {
      if (bytesEqual(fact.presenceOperationId, local.operationId)) continue;
      if (bytesEqual(fact.presence.core.stableIdentityCommitment, commitment))
        continue;
      const candidate = this.knownOperations.get(hex(fact.presenceOperationId));
      if (candidate === undefined) continue;
      remote = {
        operationId: Uint8Array.from(fact.presenceOperationId),
        operation: candidate.operation,
        presence: fact.presence,
      };
      break;
    }
    if (remote === null) return;

    this.remotePresence = remote;
    this.pairEdge = await pairEdgeId(
      this.roomContextId,
      local.operationId,
      remote.operationId,
    );
    const order = compareBytes(local.operationId, remote.operationId);
    this.rendezvousRole = order < 0 ? "initiator" : "responder";
    this.endpoints =
      order < 0
        ? [local.operationId, remote.operationId]
        : [remote.operationId, local.operationId];
    this.setPhase("peer-observed");
  }

  /** Sign one identity plaintext over the exact outer binding. */
  private async signIdentityPlaintext(
    unsigned: PairPlaintextV1,
    binding: PairOuterBindingV1,
  ): Promise<PairPlaintextV1> {
    const padded = (await padPairPlaintextV1(unsigned, true, this.roomPqMode))
      .plaintext;
    if (
      padded.body.kind !== "IDENTITY_HELLO" &&
      padded.body.kind !== "IDENTITY_ACCEPT"
    )
      return fail("identity plaintext lost its body discriminator");
    const message = await pairIdentitySignedMessage(
      binding,
      pairIdentityUnsignedProjectionV1(padded),
    );
    let identityTranscriptSignature: Uint8Array;
    try {
      identityTranscriptSignature = await sign(
        message,
        this.identity.ed25519SecretKey,
        this.module,
      );
    } finally {
      message.fill(0);
    }
    return {
      ...padded,
      body:
        padded.body.kind === "IDENTITY_HELLO"
          ? {
              kind: "IDENTITY_HELLO",
              value: { ...padded.body.value, identityTranscriptSignature },
            }
          : {
              kind: "IDENTITY_ACCEPT",
              value: { ...padded.body.value, identityTranscriptSignature },
            },
    };
  }

  private async signPairStepOperation(
    outerFields: PairBootstrapOuterFieldsV1,
    sealed: {
      readonly envelope: Parameters<typeof encodePairStepEnvelopeV1>[0];
    },
    operationPayloadClass: OperationPayloadClassV1,
  ): Promise<AuthenticatedRoomOperationV1> {
    const fixedPayload = encodePairStepEnvelopeV1(
      sealed.envelope,
      operationPayloadClass,
    );
    const unsigned: UnsignedRoomOperationV1 = {
      version: 1,
      roomContextConfirmation: outerFields.roomContextConfirmation,
      logicalWindow: outerFields.logicalWindow,
      expiresAfterWindow: outerFields.expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: outerFields.authorEpochEd25519Key,
      authorSequence: outerFields.authorSequence,
      previousAuthorOperationId: outerFields.previousAuthorOperationId,
      kind: "PAIR_STEP",
      semanticSlot: await pairSemanticSlot(sealed.envelope.pairRoutingTag),
      dependencies: [],
      operationPayloadClass,
      fixedPayload,
      operationPadding: operationPaddingFor(
        operationPayloadClass,
        fixedPayload.length,
      ),
    };
    return signOperation(unsigned, this.requireAuthorSecretKey(), this.module);
  }

  /**
   * Route one candidate pair operation to the flight this endpoint expects.
   *
   * Returns false to defer: the operation stays unhandled so a later ingest
   * can retry once the missing predecessor exists.
   */
  private async handlePairOperation(
    candidate: ActivePairOperationCandidateSnapshotV1,
  ): Promise<boolean> {
    if (this.remotePresence === null || this.rendezvousRole === null)
      return false;
    if (candidate.envelope.bootstrapHeader !== null)
      return this.rendezvousRole === "responder"
        ? this.handleIncomingHello(candidate)
        : this.handleIncomingAccept(candidate);
    return this.rendezvousRole === "responder"
      ? this.handleIncomingOffer(candidate)
      : this.handleIncomingAnswer(candidate);
  }

  private async handleIncomingHello(
    candidate: ActivePairOperationCandidateSnapshotV1,
  ): Promise<boolean> {
    if (this.receiverSecretKey === null) return false;
    const local = this.requireLocalPresence();
    const remote = this.requireRemotePresence();

    let opened: IdentityHelloOpenPolicyPrototypeResultV1 | null;
    try {
      opened = await openIdentityHelloOpenPolicyPrototype({
        module: this.module,
        roomPqMode: this.roomPqMode,
        roomContextId: this.roomContextId,
        roomPolicy: this.roomPolicy,
        policyHash: this.policyHash,
        roomRoot: this.roomRoot,
        recipientHybridKemSecretKey: this.receiverSecretKey,
        localPresenceOperationId: local.operationId,
        localStableEd25519PublicKey: this.identity.ed25519PublicKey,
        remotePresence: remote,
        expectedPairEdgeId: this.requirePairEdge(),
        candidate,
      });
    } catch (error) {
      this.failEdge(`HELLO rejected: ${errorDetail(error)}`);
      return true;
    }
    if (opened === null) return true;

    const acceptance = this.slotAcceptanceCandidate(candidate, {
      kind: "IDENTITY_HELLO",
      direction: 0,
      pairSequence: 0n,
      cachedExactResponse: null,
    });
    const preview = previewAuthenticatedPairSlotV1(this.ledger, acceptance);
    if (preview.result !== "unoccupied") {
      opened.bootstrapRoot.fill(0);
      if (preview.result === "replay") return true;
      this.failEdge(`pair edge ${preview.result} at the HELLO slot`);
      return true;
    }

    this.helloRoot?.fill(0);
    this.helloRoot = opened.bootstrapRoot;
    this.helloOperationId = Uint8Array.from(candidate.operationId);
    this.helloLogicalWindow = candidate.operation.logicalWindow;
    this.helloResponsePublicKey = Uint8Array.from(
      opened.hello.responseHybridKemPublicKey,
    );
    this.peerStableKey = Uint8Array.from(
      opened.hello.senderIdentity.ed25519PublicKey,
    );
    this.setPhase("hello-opened");
    await this.sendAccept(acceptance);
    return true;
  }

  /** Seal the ACCEPT, promote the edge, persist the slot, then publish. */
  private async sendAccept(
    acceptance: PairSlotAcceptanceCandidateV1,
  ): Promise<void> {
    const endpoints = this.requireEndpoints();
    const helloOperationId = this.helloOperationId;
    const helloRoot = this.helloRoot;
    const responsePublicKey = this.helloResponsePublicKey;
    if (helloOperationId === null || helloRoot === null)
      return fail("ACCEPT requires an opened HELLO");
    if (responsePublicKey === null)
      return fail("ACCEPT requires the HELLO response hybrid KEM key");

    const logicalWindow = this.logicalWindow();
    const expiresAfterWindow =
      logicalWindow +
      BigInt(this.roomPolicy.protocolLimits.pairControlRetentionWindows);
    const chain = this.nextAuthorFields(logicalWindow);
    const outerFields: PairBootstrapOuterFieldsV1 = {
      version: 1,
      roomContextConfirmation:
        this.validationContextAt(logicalWindow).roomContextConfirmation,
      policyHash: this.policyHash,
      logicalWindow,
      expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: this.requireAuthorPublicKey(),
      authorSequence: chain.authorSequence,
      previousAuthorOperationId: chain.previousAuthorOperationId,
      kind: "PAIR_STEP",
      dependencies: [],
      operationPayloadClass: 0,
    };
    const bootstrapInfo: PairBootstrapInfoV1 = {
      ...outerFieldsAsBootstrapInfo(outerFields, this.roomPolicy),
      stepKind: "IDENTITY_ACCEPT",
      recipientBinding: { kind: "hello-response", helloOperationId },
    };

    const sealed = await sealPairBootstrapV1({
      module: this.module,
      recipientHybridKemPublicKey: responsePublicKey,
      psk: helloRoot,
      bootstrapInfo,
      outerFields,
      roomPqMode: this.roomPqMode,
      createSignedPlaintext: (binding) =>
        this.signIdentityPlaintext(
          {
            version: 1,
            kind: "IDENTITY_ACCEPT",
            pairEdgeId: this.requirePairEdge(),
            endpointPresenceOperationIds: endpoints,
            direction: 1,
            pairSequence: 0n,
            previousPairOperationId: null,
            pairDependencies: [helloOperationId],
            body: {
              kind: "IDENTITY_ACCEPT",
              value: {
                version: 1,
                responderIdentity: this.identityBundle(),
                responderPresenceCommitment: this.requireStableCommitment(),
                responderAdmissionGrant: null,
                identityTranscriptSignature: new Uint8Array(64),
              },
            },
            pairPadding: new Uint8Array(0),
          },
          binding,
        ),
    });

    const operation = await this.signPairStepOperation(outerFields, sealed, 0);
    const acceptOperationId = await deriveOperationId(operation);
    this.acceptRoot = sealed.bootstrapRoot;
    this.acceptOperationId = acceptOperationId;
    await this.promoteEstablishedRoot(helloOperationId, acceptOperationId);

    const transition = recordAcceptedPairSlotV1(this.ledger, {
      ...acceptance,
      cachedExactResponse: encodeOperation(operation),
    });
    if (transition.result !== "accepted") {
      this.failEdge(`pair edge ${transition.result} at the HELLO slot`);
      return;
    }
    this.ledger = transition.ledger;
    this.recordOwnOperation(acceptOperationId);
    this.publish(operation, "IDENTITY_ACCEPT");
    this.setPhase("accepted");
  }

  private async handleIncomingAccept(
    candidate: ActivePairOperationCandidateSnapshotV1,
  ): Promise<boolean> {
    const helloOperationId = this.helloOperationId;
    const helloRoot = this.helloRoot;
    const responseSecretKey = this.responseSecretKey;
    if (
      helloOperationId === null ||
      helloRoot === null ||
      responseSecretKey === null
    )
      return false;

    const operation = candidate.operation;
    const envelope = candidate.envelope;
    if (
      operation.operationPayloadClass !== 0 ||
      operation.dependencies.length !== 0 ||
      envelope.bootstrapHeader === null ||
      envelope.nonce !== null
    )
      return true;

    const prebinding: PairOuterPrebindingV1 = {
      ...this.prebindingFor(operation, 0),
      bootstrapHeaderHash: await pairBootstrapHeaderHash(
        envelope.bootstrapHeader,
      ),
      nonce: null,
    };
    const bootstrapInfo: PairBootstrapInfoV1 = {
      version: 1,
      pairBootstrapSuite: this.roomPolicy.pairBootstrapSuite,
      roomContextConfirmation: operation.roomContextConfirmation,
      policyHash: this.policyHash,
      stepKind: "IDENTITY_ACCEPT",
      logicalWindow: operation.logicalWindow,
      expiresAfterWindow: operation.expiresAfterWindow,
      authorEpochEd25519Key: operation.authorEpochEd25519Key,
      authorSequence: operation.authorSequence,
      previousAuthorOperationId: operation.previousAuthorOperationId,
      operationPayloadClass: 0,
      recipientBinding: { kind: "hello-response", helloOperationId },
    };

    let responderStableKey: Uint8Array | null = null;
    let opened;
    try {
      opened = await openPairBootstrapV1({
        module: this.module,
        recipientHybridKemSecretKey: responseSecretKey,
        psk: helloRoot,
        bootstrapInfo,
        prebinding,
        envelope,
        operationPayloadClass: 0,
        roomPqMode: this.roomPqMode,
        validateAuthenticatedPlaintext: async (binding, plaintext) => {
          responderStableKey = await this.validateAuthenticatedAccept(
            candidate,
            binding,
            plaintext,
            helloOperationId,
          );
        },
      });
    } catch (error) {
      this.failEdge(`ACCEPT rejected: ${errorDetail(error)}`);
      return true;
    }
    if (opened === null) return true;
    if (responderStableKey === null)
      return fail("ACCEPT validator did not produce its authenticated facts");

    this.peerStableKey = responderStableKey;
    this.acceptRoot = opened.bootstrapRoot;
    this.acceptOperationId = Uint8Array.from(candidate.operationId);
    await this.promoteEstablishedRoot(helloOperationId, this.acceptOperationId);
    this.responseSecretKey?.fill(0);
    this.responseSecretKey = null;
    this.setPhase("accepted");
    await this.sendOffer();
    return true;
  }

  private async validateAuthenticatedAccept(
    candidate: ActivePairOperationCandidateSnapshotV1,
    binding: PairOuterBindingV1,
    plaintext: PairPlaintextV1,
    helloOperationId: Uint8Array,
  ): Promise<Uint8Array> {
    const endpoints = this.requireEndpoints();
    const remote = this.requireRemotePresence();
    if (
      plaintext.kind !== "IDENTITY_ACCEPT" ||
      plaintext.body.kind !== "IDENTITY_ACCEPT" ||
      plaintext.direction !== 1 ||
      plaintext.pairSequence !== 0n ||
      plaintext.previousPairOperationId !== null ||
      plaintext.pairDependencies.length !== 1 ||
      !bytesEqual(plaintext.pairDependencies[0], helloOperationId)
    )
      return rejectAuthenticated("ACCEPT slot shape");
    if (
      !bytesEqual(plaintext.endpointPresenceOperationIds[0], endpoints[0]) ||
      !bytesEqual(plaintext.endpointPresenceOperationIds[1], endpoints[1])
    )
      return rejectAuthenticated("ACCEPT names a different endpoint tuple");
    if (
      !bytesEqual(binding.pairRoutingTag, candidate.envelope.pairRoutingTag) ||
      !bytesEqual(binding.semanticSlot, candidate.operation.semanticSlot)
    )
      return rejectAuthenticated("binding does not match the outer operation");
    const expectedPairEdgeId = await pairEdgeId(
      this.roomContextId,
      endpoints[0],
      endpoints[1],
    );
    if (
      !bytesEqual(expectedPairEdgeId, plaintext.pairEdgeId) ||
      !bytesEqual(expectedPairEdgeId, this.requirePairEdge())
    )
      return rejectAuthenticated("PairEdgeId does not recompute");

    const accept = plaintext.body.value;
    const responderStableKey = accept.responderIdentity.ed25519PublicKey;
    if (bytesEqual(responderStableKey, this.identity.ed25519PublicKey))
      return rejectAuthenticated("a presence cannot pair with itself");
    const expectedCommitment = await stableIdentityCommitment(
      this.roomContextId,
      responderStableKey,
    );
    if (
      !bytesEqual(accept.responderPresenceCommitment, expectedCommitment) ||
      !bytesEqual(
        accept.responderPresenceCommitment,
        remote.presence.core.stableIdentityCommitment,
      )
    )
      return rejectAuthenticated(
        "responder commitment does not bind its presence",
      );
    if (
      !(await verifyIdentityCrossSig(
        accept.responderIdentity.x25519PublicKey,
        accept.responderIdentity.x25519CrossSignature,
        responderStableKey,
        this.module,
      ))
    )
      return rejectAuthenticated("X25519 identity cross-signature");
    const message = await pairIdentitySignedMessage(
      binding,
      pairIdentityUnsignedProjectionV1(plaintext),
    );
    let valid: boolean;
    try {
      valid = await verify(
        message,
        accept.identityTranscriptSignature,
        responderStableKey,
        this.module,
      );
    } finally {
      message.fill(0);
    }
    if (!valid)
      return rejectAuthenticated("stable identity transcript signature");

    /*
     * Bind the responder presence — and therefore the rendezvous KEM key this
     * endpoint encapsulated to — to the stable key that just signed the
     * transcript, exactly as the HELLO validator does for the sender.
     */
    await validatePresenceOwnershipV1(
      remote.operation,
      remote.presence,
      responderStableKey,
      {
        roomContextId: this.roomContextId,
        roomPolicy: this.roomPolicy,
      },
      this.module,
    );
    return Uint8Array.from(responderStableKey);
  }

  /** Derive `EstablishedPairRoot` and erase both bootstrap roots. */
  private async promoteEstablishedRoot(
    helloOperationId: Uint8Array,
    acceptOperationId: Uint8Array,
  ): Promise<void> {
    const helloRoot = this.helloRoot;
    const acceptRoot = this.acceptRoot;
    if (helloRoot === null || acceptRoot === null)
      return fail("promotion requires both bootstrap roots");
    this.establishedRoot = await establishedPairRoot(
      helloRoot,
      acceptRoot,
      helloOperationId,
      acceptOperationId,
    );
    this.confirmedTranscriptId = await confirmedPairTranscriptId(
      helloOperationId,
      acceptOperationId,
    );
    helloRoot.fill(0);
    acceptRoot.fill(0);
    this.helloRoot = null;
    this.acceptRoot = null;
  }

  private async sendOffer(): Promise<void> {
    const endpoints = this.requireEndpoints();
    const establishedRoot = this.establishedRoot;
    const helloOperationId = this.helloOperationId;
    const acceptOperationId = this.acceptOperationId;
    if (
      establishedRoot === null ||
      helloOperationId === null ||
      acceptOperationId === null
    )
      return fail("TRANSPORT_OFFER requires a confirmed pair transcript");

    let sdp: Uint8Array;
    try {
      sdp = await this.transport.createOffer();
      validateWebRtcSdp(sdp);
    } catch (error) {
      this.failEdge(`local offer unusable: ${errorDetail(error)}`);
      return;
    }
    const candidates = await buildOfferCandidates(sdp);
    const webrtc = candidates.find(
      (member) => member.kind === "webrtc-complete",
    );
    if (webrtc === undefined)
      return fail("offer candidates lost their webrtc member");
    this.offerWebRtcCandidateId = await transportOfferCandidateId(webrtc);
    this.localSdp = sdp;

    const claim = await this.signStableEdgeClaim();
    const sealedOperation = await this.sealEstablishedFlight({
      slotKind: "TRANSPORT_OFFER",
      direction: 0,
      pairSequence: 1n,
      previousPairOperationId: helloOperationId,
      pairDependencies: [acceptOperationId],
      body: {
        kind: "TRANSPORT_OFFER",
        value: {
          version: 1,
          initiatorStableEdgeClaim: claim,
          candidates,
        },
      },
      endpoints,
    });
    this.offerOperationId = await deriveOperationId(sealedOperation);
    this.recordOwnOperation(this.offerOperationId);
    this.publish(sealedOperation, "TRANSPORT_OFFER");
    // The payload class is reported because it is chosen silently: an SDP that
    // outgrows class 0 moves this flight to class 1, which in the pinned
    // profile is an *earlier* append slot with *less* budget, and nothing else
    // in the event stream would say so.
    this.setPhase(
      "offer-sent",
      `operationPayloadClass ${String(sealedOperation.operationPayloadClass)}`,
    );
  }

  private async handleIncomingOffer(
    candidate: ActivePairOperationCandidateSnapshotV1,
  ): Promise<boolean> {
    const establishedRoot = this.establishedRoot;
    const helloOperationId = this.helloOperationId;
    const acceptOperationId = this.acceptOperationId;
    if (
      establishedRoot === null ||
      helloOperationId === null ||
      acceptOperationId === null
    )
      return false;
    const endpoints = this.requireEndpoints();
    const operation = candidate.operation;
    const envelope = candidate.envelope;
    if (envelope.nonce === null || envelope.bootstrapHeader !== null)
      return true;

    let opened;
    try {
      opened = await openPairStepV1({
        module: this.module,
        baseSecret: establishedRoot,
        expectedSlot: {
          kind: "TRANSPORT_OFFER",
          direction: 0,
          pairSequence: 1n,
        },
        prebinding: {
          ...this.prebindingFor(operation, operation.operationPayloadClass),
          bootstrapHeaderHash: ZERO32,
          nonce: envelope.nonce,
        },
        envelope,
        operationPayloadClass: operation.operationPayloadClass,
        roomPqMode: this.roomPqMode,
      });
    } catch (error) {
      this.failEdge(`TRANSPORT_OFFER rejected: ${errorDetail(error)}`);
      return true;
    }
    if (opened === null) return true;

    /*
     * Peer-authored facts only. Local construction stays outside this catch so
     * an internal fault is never misreported as a peer violation.
     */
    let selected: Awaited<ReturnType<typeof selectWebRtcCandidate>>;
    try {
      const plaintext = opened.plaintext;
      const offer = transportOfferBody(plaintext);
      if (
        plaintext.previousPairOperationId === null ||
        !bytesEqual(plaintext.previousPairOperationId, helloOperationId) ||
        plaintext.pairDependencies.length !== 1 ||
        !bytesEqual(plaintext.pairDependencies[0], acceptOperationId) ||
        !bytesEqual(plaintext.pairEdgeId, this.requirePairEdge()) ||
        !bytesEqual(plaintext.endpointPresenceOperationIds[0], endpoints[0]) ||
        !bytesEqual(plaintext.endpointPresenceOperationIds[1], endpoints[1])
      )
        rejectAuthenticated("TRANSPORT_OFFER slot shape");
      await this.verifyStableEdgeClaim(
        offer.initiatorStableEdgeClaim,
        this.requirePeerStableKey(),
      );
      selected = await selectWebRtcCandidate(offer.candidates);
    } catch (error) {
      this.failEdge(`TRANSPORT_OFFER rejected: ${errorDetail(error)}`);
      return true;
    }
    this.remoteSdp = selected.sdp;
    this.offerOperationId = Uint8Array.from(candidate.operationId);

    let answerSdp: Uint8Array;
    try {
      answerSdp = await this.transport.acceptOffer(selected.sdp);
      validateWebRtcSdp(answerSdp);
    } catch (error) {
      this.failEdge(`local answer unusable: ${errorDetail(error)}`);
      return true;
    }
    this.localSdp = answerSdp;
    this.setPhase("offer-opened");

    const claim = await this.signStableEdgeClaim();
    const answerOperation = await this.sealEstablishedFlight({
      slotKind: "TRANSPORT_ANSWER",
      direction: 1,
      pairSequence: 1n,
      previousPairOperationId: acceptOperationId,
      pairDependencies: [this.offerOperationId],
      body: {
        kind: "TRANSPORT_ANSWER",
        value: {
          version: 1,
          responderStableEdgeClaim: claim,
          selectedOfferCandidateId: selected.id,
          answer: {
            version: 1,
            kind: "webrtc-complete",
            exactSdpUtf8: answerSdp,
          },
        },
      },
      endpoints,
    });
    this.answerOperationId = await deriveOperationId(answerOperation);
    this.recordOwnOperation(this.answerOperationId);
    this.publish(answerOperation, "TRANSPORT_ANSWER");
    this.setPhase(
      "answered",
      `operationPayloadClass ${String(answerOperation.operationPayloadClass)}`,
    );
    await this.completeHandoff();
    return true;
  }

  private async handleIncomingAnswer(
    candidate: ActivePairOperationCandidateSnapshotV1,
  ): Promise<boolean> {
    const establishedRoot = this.establishedRoot;
    const acceptOperationId = this.acceptOperationId;
    const offerOperationId = this.offerOperationId;
    const offerCandidateId = this.offerWebRtcCandidateId;
    if (
      establishedRoot === null ||
      acceptOperationId === null ||
      offerOperationId === null ||
      offerCandidateId === null
    )
      return false;
    const endpoints = this.requireEndpoints();
    const operation = candidate.operation;
    const envelope = candidate.envelope;
    if (envelope.nonce === null || envelope.bootstrapHeader !== null)
      return true;

    let opened;
    try {
      opened = await openPairStepV1({
        module: this.module,
        baseSecret: establishedRoot,
        expectedSlot: {
          kind: "TRANSPORT_ANSWER",
          direction: 1,
          pairSequence: 1n,
        },
        prebinding: {
          ...this.prebindingFor(operation, operation.operationPayloadClass),
          bootstrapHeaderHash: ZERO32,
          nonce: envelope.nonce,
        },
        envelope,
        operationPayloadClass: operation.operationPayloadClass,
        roomPqMode: this.roomPqMode,
      });
    } catch (error) {
      this.failEdge(`TRANSPORT_ANSWER rejected: ${errorDetail(error)}`);
      return true;
    }
    if (opened === null) return true;

    let remoteSdp: Uint8Array;
    try {
      const plaintext = opened.plaintext;
      const answer = transportAnswerBody(plaintext);
      if (
        plaintext.previousPairOperationId === null ||
        !bytesEqual(plaintext.previousPairOperationId, acceptOperationId) ||
        plaintext.pairDependencies.length !== 1 ||
        !bytesEqual(plaintext.pairDependencies[0], offerOperationId) ||
        !bytesEqual(plaintext.pairEdgeId, this.requirePairEdge()) ||
        !bytesEqual(plaintext.endpointPresenceOperationIds[0], endpoints[0]) ||
        !bytesEqual(plaintext.endpointPresenceOperationIds[1], endpoints[1])
      )
        rejectAuthenticated("TRANSPORT_ANSWER slot shape");
      await this.verifyStableEdgeClaim(
        answer.responderStableEdgeClaim,
        this.requirePeerStableKey(),
      );
      if (!bytesEqual(answer.selectedOfferCandidateId, offerCandidateId))
        rejectAuthenticated("answer selected a candidate we never offered");
      const selectedAnswer = answer.answer;
      if (selectedAnswer.kind !== "webrtc-complete")
        throw new PairDriverError(
          "authenticated pair identity flight rejected: answer kind does not equal the selected offer",
        );
      remoteSdp = Uint8Array.from(selectedAnswer.exactSdpUtf8);
      validateWebRtcSdp(remoteSdp);
    } catch (error) {
      this.failEdge(`TRANSPORT_ANSWER rejected: ${errorDetail(error)}`);
      return true;
    }
    this.remoteSdp = remoteSdp;
    this.answerOperationId = Uint8Array.from(candidate.operationId);
    try {
      await this.transport.acceptAnswer(remoteSdp);
    } catch (error) {
      this.failEdge(
        `local transport rejected the answer: ${errorDetail(error)}`,
      );
      return true;
    }
    await this.completeHandoff();
    return true;
  }

  private requirePeerStableKey(): Uint8Array {
    if (this.peerStableKey === null)
      return fail("the peer stable identity is not confirmed yet");
    return this.peerStableKey;
  }

  private prebindingFor(
    operation: AuthenticatedRoomOperationV1,
    operationPayloadClass: OperationPayloadClassV1,
  ): PairOuterPrebindingV1 {
    return {
      version: 1,
      roomContextConfirmation: operation.roomContextConfirmation,
      policyHash: this.policyHash,
      logicalWindow: operation.logicalWindow,
      expiresAfterWindow: operation.expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: operation.authorEpochEd25519Key,
      authorSequence: operation.authorSequence,
      previousAuthorOperationId: operation.previousAuthorOperationId,
      kind: "PAIR_STEP",
      dependencies: [],
      operationPayloadClass,
      bootstrapHeaderHash: ZERO32,
      nonce: null,
    };
  }

  private slotAcceptanceCandidate(
    candidate: ActivePairOperationCandidateSnapshotV1,
    slot: {
      readonly kind: "IDENTITY_HELLO";
      readonly direction: 0 | 1;
      readonly pairSequence: bigint;
      readonly cachedExactResponse: Uint8Array | null;
    },
  ): PairSlotAcceptanceCandidateV1 {
    return {
      coordinate: {
        pairEdgeId: this.requirePairEdge(),
        endpointPresenceOperationIds: this.requireEndpoints(),
        direction: slot.direction,
        pairSequence: slot.pairSequence,
      },
      kind: slot.kind,
      acceptedOperationId: candidate.operationId,
      exactOperationBytes: candidate.exactOperationBytes,
      acceptedLogicalWindow: candidate.operation.logicalWindow,
      retainThroughLogicalWindow: candidate.operation.expiresAfterWindow,
      routingTag: candidate.envelope.pairRoutingTag,
      authorChainPrefix: candidate.authorChainPrefix,
      cachedExactResponse: slot.cachedExactResponse,
    };
  }

  /**
   * Seal one established flight under `EstablishedPairRoot` and wrap it as the
   * `PAIR_STEP` operation the carrier publishes.
   */
  private async sealEstablishedFlight(options: {
    readonly slotKind: "TRANSPORT_OFFER" | "TRANSPORT_ANSWER";
    readonly direction: 0 | 1;
    readonly pairSequence: bigint;
    readonly previousPairOperationId: Uint8Array;
    readonly pairDependencies: readonly Uint8Array[];
    readonly body: PairPlaintextV1["body"];
    readonly endpoints: readonly [Uint8Array, Uint8Array];
  }): Promise<AuthenticatedRoomOperationV1> {
    const establishedRoot = this.establishedRoot;
    if (establishedRoot === null)
      return fail("an established flight requires EstablishedPairRoot");

    const padded = await padPairPlaintextV1(
      {
        version: 1,
        kind: options.slotKind,
        pairEdgeId: this.requirePairEdge(),
        endpointPresenceOperationIds: options.endpoints,
        direction: options.direction,
        pairSequence: options.pairSequence,
        previousPairOperationId: options.previousPairOperationId,
        pairDependencies: options.pairDependencies,
        body: options.body,
        pairPadding: new Uint8Array(0),
      },
      false,
      this.roomPqMode,
    );

    const logicalWindow = this.logicalWindow();
    const expiresAfterWindow =
      logicalWindow +
      BigInt(this.roomPolicy.protocolLimits.pairControlRetentionWindows);
    const chain = this.nextAuthorFields(logicalWindow);
    const outerFields: PairBootstrapOuterFieldsV1 = {
      version: 1,
      roomContextConfirmation:
        this.validationContextAt(logicalWindow).roomContextConfirmation,
      policyHash: this.policyHash,
      logicalWindow,
      expiresAfterWindow,
      lifetime: "PAIR_CAUSAL",
      authorEpochEd25519Key: this.requireAuthorPublicKey(),
      authorSequence: chain.authorSequence,
      previousAuthorOperationId: chain.previousAuthorOperationId,
      kind: "PAIR_STEP",
      dependencies: [],
      operationPayloadClass: padded.operationPayloadClass,
    };
    const nonce = this.random(24);
    const sealed = await sealPairStepV1({
      module: this.module,
      baseSecret: establishedRoot,
      expectedSlot: {
        kind: options.slotKind,
        direction: options.direction,
        pairSequence: options.pairSequence,
      },
      prebinding: {
        ...outerFields,
        bootstrapHeaderHash: ZERO32,
        nonce,
      },
      plaintext: padded.plaintext,
      roomPqMode: this.roomPqMode,
    });
    return this.signPairStepOperation(
      outerFields,
      sealed,
      padded.operationPayloadClass,
    );
  }

  private async signStableEdgeClaim(): Promise<StableEdgeAttemptClaimV1> {
    const unsigned = await this.stableEdgeClaimWindows(
      this.identity.ed25519PublicKey,
    );
    const message = await stableEdgeAttemptClaimSignedMessage(unsigned);
    let claimantSignature: Uint8Array;
    try {
      claimantSignature = await sign(
        message,
        this.identity.ed25519SecretKey,
        this.module,
      );
    } finally {
      message.fill(0);
    }
    return { ...unsigned, claimantSignature };
  }

  private async stableEdgeClaimWindows(
    claimantStableEd25519PublicKey: Uint8Array,
  ): Promise<StableEdgeAttemptClaimUnsignedV1> {
    const helloLogicalWindow = this.helloLogicalWindow;
    const confirmed = this.confirmedTranscriptId;
    if (helloLogicalWindow === null || confirmed === null)
      return fail("a stable-edge claim requires a confirmed pair attempt");
    return {
      version: 1,
      stableEdgeId: await stableEdgeId(
        this.roomContextId,
        this.identity.ed25519PublicKey,
        this.requirePeerStableKey(),
      ),
      pairEdgeId: this.requirePairEdge(),
      confirmedPairTranscriptId: confirmed,
      claimantStableEd25519PublicKey: Uint8Array.from(
        claimantStableEd25519PublicKey,
      ),
      claimNotBeforeLogicalWindow: helloLogicalWindow,
      claimNotAfterLogicalWindow:
        helloLogicalWindow +
        BigInt(this.roomPolicy.protocolLimits.pairControlRetentionWindows),
    };
  }

  /**
   * Both endpoints recompute `StableEdgeId` from the two confirmed stable keys
   * and require byte equality, then verify the signature under the exact
   * authenticated claimant key over the exact lease interval.
   */
  private async verifyStableEdgeClaim(
    claim: StableEdgeAttemptClaimV1,
    expectedClaimantKey: Uint8Array,
  ): Promise<void> {
    const expected = await this.stableEdgeClaimWindows(expectedClaimantKey);
    if (
      claim.version !== 1 ||
      !bytesEqual(claim.stableEdgeId, expected.stableEdgeId) ||
      !bytesEqual(claim.pairEdgeId, expected.pairEdgeId) ||
      !bytesEqual(
        claim.confirmedPairTranscriptId,
        expected.confirmedPairTranscriptId,
      ) ||
      !bytesEqual(
        claim.claimantStableEd25519PublicKey,
        expected.claimantStableEd25519PublicKey,
      ) ||
      claim.claimNotBeforeLogicalWindow !==
        expected.claimNotBeforeLogicalWindow ||
      claim.claimNotAfterLogicalWindow !== expected.claimNotAfterLogicalWindow
    )
      rejectAuthenticated("stable-edge attempt claim does not match the pair");

    const { claimantSignature: _signature, ...unsigned } = claim;
    const message = await stableEdgeAttemptClaimSignedMessage(unsigned);
    let valid: boolean;
    try {
      valid = await verify(
        message,
        claim.claimantSignature,
        expectedClaimantKey,
        this.module,
      );
    } finally {
      message.fill(0);
    }
    if (!valid) rejectAuthenticated("stable-edge attempt claim signature");
  }

  private async completeHandoff(): Promise<void> {
    const offerOperationId = this.offerOperationId;
    const answerOperationId = this.answerOperationId;
    const confirmed = this.confirmedTranscriptId;
    const localSdp = this.localSdp;
    const remoteSdp = this.remoteSdp;
    if (
      offerOperationId === null ||
      answerOperationId === null ||
      confirmed === null ||
      localSdp === null ||
      remoteSdp === null ||
      this.rendezvousRole === null
    )
      return fail("handoff requires a complete transport negotiation");

    const negotiation = await transportNegotiationTranscriptId(
      offerOperationId,
      answerOperationId,
    );
    const peerStableKey = this.requirePeerStableKey();
    this.handoffFacts = {
      rendezvousChannelId: await rendezvousChannelId(
        this.roomContextId,
        this.requirePairEdge(),
        confirmed,
        negotiation,
      ),
      localFingerprint: validateWebRtcSdp(localSdp).fingerprint,
      remoteFingerprint: validateWebRtcSdp(remoteSdp).fingerprint,
      sessionRole:
        compareBytes(this.identity.ed25519PublicKey, peerStableKey) < 0
          ? "initiator"
          : "responder",
      rendezvousRole: this.rendezvousRole,
      peerStableEd25519PublicKey: Uint8Array.from(peerStableKey),
      stableEdgeId: await stableEdgeId(
        this.roomContextId,
        this.identity.ed25519PublicKey,
        peerStableKey,
      ),
    };
    this.setPhase("handoff");
  }
}

const transportOfferBody = (
  plaintext: PairPlaintextV1,
): PairTransportOfferV1 => {
  if (plaintext.body.kind !== "TRANSPORT_OFFER")
    return rejectAuthenticated("TRANSPORT_OFFER body");
  return plaintext.body.value;
};

const transportAnswerBody = (
  plaintext: PairPlaintextV1,
): PairTransportAnswerV1 => {
  if (plaintext.body.kind !== "TRANSPORT_ANSWER")
    return rejectAuthenticated("TRANSPORT_ANSWER body");
  return plaintext.body.value;
};

const outerFieldsAsBootstrapInfo = (
  outerFields: PairBootstrapOuterFieldsV1,
  roomPolicy: RoomPolicyV4,
): Omit<PairBootstrapInfoV1, "stepKind" | "recipientBinding"> => ({
  version: 1,
  pairBootstrapSuite: roomPolicy.pairBootstrapSuite,
  roomContextConfirmation: outerFields.roomContextConfirmation,
  policyHash: outerFields.policyHash,
  logicalWindow: outerFields.logicalWindow,
  expiresAfterWindow: outerFields.expiresAfterWindow,
  authorEpochEd25519Key: outerFields.authorEpochEd25519Key,
  authorSequence: outerFields.authorSequence,
  previousAuthorOperationId: outerFields.previousAuthorOperationId,
  operationPayloadClass: 0,
});

const errorDetail = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);
