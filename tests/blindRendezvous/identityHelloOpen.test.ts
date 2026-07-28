import { readFileSync } from "node:fs";

import { afterEach, describe, expect, test } from "bun:test";

import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import { crossSignIdentityX25519 } from "../../src/cryptography/identityCrossSig";
import { generateHpkeRecipientKeyPair } from "../../src/cryptography/hpke";
import { loadTestModule } from "../../src/cryptography/testModule";
import { newX25519KeyPair } from "../../src/cryptography/x25519";
import {
  captureActivePairOperationCandidate,
  captureHistoricalPairPresenceEvidence,
  coreReduce,
  validateAndIdentifyOperationCandidate,
} from "../../src/blindRendezvous/coreReduce";
import {
  leaveSemanticSlot,
  pairEdgeId,
  pairIdentitySignedMessage,
  pairSemanticSlot,
  policyHash,
  presenceOwnershipSignedMessage,
  presenceProofTranscriptHash,
  presenceSemanticSlot,
  stableIdentityCommitment,
} from "../../src/blindRendezvous/derivations";
import {
  destroyVerifiedAdmissionContextV1,
  destroyVerifiedIdentityHelloOpenV1,
  openReservedIdentityHelloV1,
  promoteVerifiedIdentityHelloOpenForAdmissionV1,
  snapshotVerifiedAdmissionContextV1,
  snapshotVerifiedIdentityHelloOpenV1,
} from "../../src/blindRendezvous/identityHelloOpen";
import {
  createExpectedIdentityHelloTrialV1,
  createHistoricalIdentityHelloEvidenceViewV1,
  createLocalHelloReceiverCustodyV1,
  destroyExpectedIdentityHelloTrialV1,
  destroyHistoricalIdentityHelloEvidenceViewV1,
  destroyLocalHelloReceiverCustodyV1,
  snapshotExpectedIdentityHelloTrialV1,
} from "../../src/blindRendezvous/identityHelloTrial";
import {
  createOperationValidationContext,
  operationPaddingFor,
  operationValidationContextAt,
  signOperation,
} from "../../src/blindRendezvous/operation";
import {
  encodeLeaveV1,
  encodePresenceV1,
} from "../../src/blindRendezvous/operationPayload";
import { sealPairBootstrapV1 } from "../../src/blindRendezvous/pairCrypto";
import { PAIR_BOOTSTRAP_SUITE_V1 } from "../../src/blindRendezvous/pairBootstrapSuite";
import { createPairOpenReservationServiceV1 } from "../../src/blindRendezvous/pairOpenReservation";
import {
  padPairPlaintextV1,
  pairIdentityUnsignedProjectionV1,
} from "../../src/blindRendezvous/pairPlaintext";
import { encodePairStepEnvelopeV1 } from "../../src/blindRendezvous/pairStepEnvelope";
import { copyBlindDefaultPolicy } from "../../src/blindRendezvous/roomPolicyV4";
import { decodeRoomPolicyV1 } from "../../src/roomPolicy";
import { AdmissionInputError } from "../../src/blindRendezvous/admissionInput";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  ActivePairOperationCandidateV1,
  CoreRoomStateV1,
  OuterValidatedIdentifiedOperationV1,
  VerifiedHistoricalPairPresenceEvidenceV1,
} from "../../src/blindRendezvous/coreReduce";
import type {
  ExpectedIdentityHelloTrialV1,
  HistoricalIdentityHelloEvidenceViewV1,
  LocalHelloReceiverCustodyV1,
} from "../../src/blindRendezvous/identityHelloTrial";
import type {
  OperationValidationContext,
  UnsignedRoomOperationV1,
} from "../../src/blindRendezvous/operation";
import type { VerifiedAdmissionContextV1 } from "../../src/blindRendezvous/identityHelloOpen";
import type {
  AdmissionGrantV1,
  PresenceCoreV1,
} from "../../src/blindRendezvous/operationPayload";
import type {
  PairBootstrapInfoV1,
  PairPlaintextV1,
} from "../../src/blindRendezvous/pairPlaintext";
import type {
  PairBootstrapOuterFieldsV1,
  PairBootstrapSealResultV1,
} from "../../src/blindRendezvous/pairCrypto";
import type {
  PairOpenReservationStorePortV1,
  ReservedIdentityHelloOpenV1,
} from "../../src/blindRendezvous/pairOpenReservation";

const module = await loadTestModule();
const HELLO_WINDOW = 1_000n;
const RECEIVER_REVISION = 17n;

type AuthenticatedDefect =
  | "none"
  | "pair-edge"
  | "local-tuple"
  | "commitment"
  | "cross-signature"
  | "identity-signature"
  | "ownership"
  | "self"
  | "response-x25519"
  | "response-mlkem";

interface PresenceFixture {
  readonly identified: OuterValidatedIdentifiedOperationV1;
  readonly stablePublicKey: Uint8Array;
  readonly stableSecretKey: Uint8Array;
  readonly authorPublicKey: Uint8Array;
  readonly authorSecretKey: Uint8Array;
  readonly receiverPublicKey: Uint8Array;
  readonly receiverSecretSeed: Uint8Array;
  readonly identityX25519PublicKey: Uint8Array;
  readonly identityX25519CrossSignature: Uint8Array;
  readonly stableCommitment: Uint8Array;
}

interface HelloFixture {
  readonly context: OperationValidationContext;
  readonly remote: PresenceFixture;
  readonly local: PresenceFixture;
  readonly alternate: PresenceFixture;
  readonly presences: readonly PresenceFixture[];
  readonly pair: OuterValidatedIdentifiedOperationV1;
  readonly state: CoreRoomStateV1;
  readonly active: ActivePairOperationCandidateV1;
  readonly evidenceByPresence: ReadonlyMap<
    PresenceFixture,
    VerifiedHistoricalPairPresenceEvidenceV1
  >;
  readonly evidenceView: HistoricalIdentityHelloEvidenceViewV1;
  readonly localCustody: LocalHelloReceiverCustodyV1;
  readonly roomRoot: Uint8Array;
}

const trackedSecrets = new Set<Uint8Array>();
const trackedTrials = new Set<ExpectedIdentityHelloTrialV1>();
const trackedViews = new Set<HistoricalIdentityHelloEvidenceViewV1>();
const trackedCustodies = new Set<LocalHelloReceiverCustodyV1>();
const trackedOpens = new Set<
  Extract<
    Awaited<ReturnType<typeof openReservedIdentityHelloV1>>,
    { kind: "opened" }
  >["value"]
>();
const trackedAdmissionContexts = new Set<VerifiedAdmissionContextV1>();
let fixtureOrdinal = 0;

const trackSecret = (value: Uint8Array): Uint8Array => {
  trackedSecrets.add(value);
  return value;
};

afterEach(() => {
  for (const context of trackedAdmissionContexts)
    destroyVerifiedAdmissionContextV1(context);
  trackedAdmissionContexts.clear();
  for (const opened of trackedOpens) destroyVerifiedIdentityHelloOpenV1(opened);
  trackedOpens.clear();
  for (const trial of trackedTrials) destroyExpectedIdentityHelloTrialV1(trial);
  trackedTrials.clear();
  for (const custody of trackedCustodies)
    destroyLocalHelloReceiverCustodyV1(custody);
  trackedCustodies.clear();
  for (const view of trackedViews)
    destroyHistoricalIdentityHelloEvidenceViewV1(view);
  trackedViews.clear();
  for (const secret of trackedSecrets) secret.fill(0);
  trackedSecrets.clear();
});

const expectBytesEqual = (left: Uint8Array, right: Uint8Array): void => {
  expect(Buffer.from(left)).toEqual(Buffer.from(right));
};

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const flipped = (value: Uint8Array): Uint8Array => {
  const result = Uint8Array.from(value);
  result[0] ^= 1;
  return result;
};

const containsSecretField = (
  value: unknown,
  seen = new Set<object>(),
): boolean => {
  if (
    value === null ||
    typeof value !== "object" ||
    value instanceof Uint8Array ||
    seen.has(value)
  )
    return false;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (
      typeof key === "string" &&
      (key.toLowerCase().includes("secret") ||
        key.toLowerCase().includes("helloroot") ||
        key.toLowerCase().includes("roomroot"))
    )
      return true;
    if (containsSecretField(Reflect.get(value, key), seen)) return true;
  }
  return false;
};

const buildPresence = async (
  context: OperationValidationContext,
  nonceByte: number,
  options: {
    readonly genuineOwnership?: boolean;
    readonly stable?: {
      readonly publicKey: Uint8Array;
      readonly secretKey: Uint8Array;
    };
  } = {},
): Promise<PresenceFixture> => {
  const stable = options.stable ?? (await newKeyPair(module));
  if (options.stable === undefined) trackSecret(stable.secretKey);
  const author = await newKeyPair(module);
  trackSecret(author.secretKey);
  const receiver = await generateHpkeRecipientKeyPair(module);
  const receiverSecretSeed = trackSecret(Uint8Array.from(receiver.secretKey));
  const identityX25519 = await newX25519KeyPair(module);
  const identityX25519CrossSignature = await crossSignIdentityX25519(
    identityX25519.publicKey,
    stable.secretKey,
    module,
  );
  identityX25519.secretKey.fill(0);

  const validThrough =
    HELLO_WINDOW +
    BigInt(context.roomPolicy.protocolLimits.operationRetentionWindows);
  const stableCommitment = await stableIdentityCommitment(
    context.roomContextId,
    stable.publicKey,
  );
  const core: PresenceCoreV1 = {
    version: 1,
    stableIdentityCommitment: stableCommitment,
    rendezvousHybridKemPublicKey: Uint8Array.from(receiver.publicKey),
    receiverKeyValidThroughLogicalWindow: validThrough,
    presenceNonce: new Uint8Array(32).fill(nonceByte),
    validThroughLogicalWindow: validThrough,
  };
  const proofHash = await presenceProofTranscriptHash({
    roomContextId: context.roomContextId,
    policyHash: await policyHash(context.roomPolicy),
    logicalWindow: HELLO_WINDOW,
    authorEpochEd25519Key: author.publicKey,
    core,
  });
  const ownershipSignature =
    options.genuineOwnership === false
      ? new Uint8Array(64).fill(nonceByte ^ 0xff)
      : await sign(
          presenceOwnershipSignedMessage(proofHash),
          stable.secretKey,
          module,
        );
  const payload = encodePresenceV1({
    core,
    stableOwnershipSignature: ownershipSignature,
    authorityPermit: null,
  });
  const unsigned: UnsignedRoomOperationV1 = {
    version: 1,
    roomContextConfirmation: context.roomContextConfirmation,
    logicalWindow: HELLO_WINDOW,
    expiresAfterWindow: validThrough,
    lifetime: "WINDOW_TRANSIENT",
    authorEpochEd25519Key: author.publicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    kind: "PRESENCE",
    semanticSlot: await presenceSemanticSlot(
      author.publicKey,
      HELLO_WINDOW,
      core.presenceNonce,
    ),
    dependencies: [],
    operationPayloadClass: 0,
    fixedPayload: payload,
    operationPadding: operationPaddingFor(0, payload.length),
  };
  const signed = await signOperation(unsigned, author.secretKey, module);
  const identified = await validateAndIdentifyOperationCandidate(
    signed,
    context,
    module,
  );
  const result: PresenceFixture = {
    identified,
    stablePublicKey: Uint8Array.from(stable.publicKey),
    stableSecretKey: stable.secretKey,
    authorPublicKey: Uint8Array.from(author.publicKey),
    authorSecretKey: author.secretKey,
    receiverPublicKey: Uint8Array.from(receiver.publicKey),
    receiverSecretSeed,
    identityX25519PublicKey: Uint8Array.from(identityX25519.publicKey),
    identityX25519CrossSignature,
    stableCommitment,
  };
  receiver.destroy();
  return result;
};

const dummyGrant = (
  context: OperationValidationContext,
  senderStableKey: Uint8Array,
  notAfterLogicalWindow: bigint,
): AdmissionGrantV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(context.roomContextId),
  stableEd25519PublicKey: Uint8Array.from(senderStableKey),
  generation: 999n,
  issuedAtLogicalWindow: HELLO_WINDOW,
  notBeforeLogicalWindow: HELLO_WINDOW,
  notAfterLogicalWindow,
  authoritySignature: new Uint8Array(64).fill(0xa7),
});

const buildSignedHelloPlaintext = async (options: {
  readonly fixtureDefect: AuthenticatedDefect;
  readonly context: OperationValidationContext;
  readonly binding: Parameters<
    NonNullable<
      Parameters<typeof sealPairBootstrapV1>[0]["createSignedPlaintext"]
    >
  >[0];
  readonly remote: PresenceFixture;
  readonly local: PresenceFixture;
  readonly alternate: PresenceFixture;
  readonly responseHybridKemPublicKey: Uint8Array;
  readonly carriedGrantNotAfter: bigint | null;
}): Promise<PairPlaintextV1> => {
  const {
    fixtureDefect,
    context,
    binding,
    remote,
    local,
    alternate,
    carriedGrantNotAfter,
  } = options;
  const endpoints: readonly [Uint8Array, Uint8Array] =
    fixtureDefect === "local-tuple"
      ? [remote.identified.operationId, alternate.identified.operationId]
      : [remote.identified.operationId, local.identified.operationId];
  let edge = await pairEdgeId(
    context.roomContextId,
    endpoints[0],
    endpoints[1],
  );
  if (fixtureDefect === "pair-edge") edge = flipped(edge);
  const crossSignature =
    fixtureDefect === "cross-signature"
      ? flipped(remote.identityX25519CrossSignature)
      : Uint8Array.from(remote.identityX25519CrossSignature);
  const senderCommitment =
    fixtureDefect === "commitment"
      ? flipped(remote.stableCommitment)
      : Uint8Array.from(remote.stableCommitment);
  const responseHybridKemPublicKey = Uint8Array.from(
    options.responseHybridKemPublicKey,
  );
  if (fixtureDefect === "response-x25519")
    responseHybridKemPublicKey
      .subarray(responseHybridKemPublicKey.length - 32)
      .fill(0);
  if (fixtureDefect === "response-mlkem")
    responseHybridKemPublicKey.subarray(0, 3).fill(0xff);
  const placeholder: PairPlaintextV1 = {
    version: 1,
    kind: "IDENTITY_HELLO",
    pairEdgeId: edge,
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
        senderIdentity: {
          ed25519PublicKey: Uint8Array.from(remote.stablePublicKey),
          x25519PublicKey: Uint8Array.from(remote.identityX25519PublicKey),
          x25519CrossSignature: crossSignature,
        },
        senderPresenceCommitment: senderCommitment,
        senderAdmissionGrant:
          carriedGrantNotAfter === null
            ? null
            : dummyGrant(context, remote.stablePublicKey, carriedGrantNotAfter),
        responseHybridKemPublicKey,
        identityTranscriptSignature: new Uint8Array(64),
      },
    },
    pairPadding: new Uint8Array(0),
  };
  const padded = await padPairPlaintextV1(
    placeholder,
    true,
    decodeRoomPolicyV1(context.roomPolicy.sessionPolicyV1).pqMode,
  );
  if (padded.operationPayloadClass !== 0)
    throw new Error("test HELLO unexpectedly exceeded payload class 0");
  if (padded.plaintext.body.kind !== "IDENTITY_HELLO")
    throw new Error("test HELLO lost its body discriminator");
  const signedMessage = await pairIdentitySignedMessage(
    binding,
    pairIdentityUnsignedProjectionV1(padded.plaintext),
  );
  let identityTranscriptSignature: Uint8Array;
  try {
    identityTranscriptSignature = await sign(
      signedMessage,
      remote.stableSecretKey,
      module,
    );
  } finally {
    signedMessage.fill(0);
  }
  if (fixtureDefect === "identity-signature")
    identityTranscriptSignature = flipped(identityTranscriptSignature);
  return {
    ...padded.plaintext,
    body: {
      kind: "IDENTITY_HELLO",
      value: {
        ...padded.plaintext.body.value,
        identityTranscriptSignature,
      },
    },
  };
};

const buildHelloFixture = async (
  options: {
    readonly defect?: AuthenticatedDefect;
    readonly omitRemoteFromEvidence?: boolean;
    readonly wrongRoutingTag?: boolean;
    readonly corruptCiphertext?: boolean;
    readonly lowOrderKemCiphertext?: boolean;
    readonly carriedGrantNotAfter?: bigint | null;
    readonly pairLifetimeWindows?: number;
  } = {},
): Promise<HelloFixture> => {
  fixtureOrdinal += 1;
  const capability = trackSecret(
    new Uint8Array(32).fill(0x30 + (fixtureOrdinal % 128)),
  );
  const context = await createOperationValidationContext(
    capability,
    copyBlindDefaultPolicy(),
    HELLO_WINDOW,
  );
  const defect = options.defect ?? "none";
  let presences: PresenceFixture[];
  let remote: PresenceFixture;
  let local: PresenceFixture;
  let alternate: PresenceFixture;

  if (defect === "self") {
    const sharedStable = await newKeyPair(module);
    trackSecret(sharedStable.secretKey);
    const first = await buildPresence(context, 0x21, {
      stable: sharedStable,
    });
    const second = await buildPresence(context, 0x22, {
      stable: sharedStable,
    });
    alternate = await buildPresence(context, 0x23);
    [remote, local] = [first, second].sort((left, right) =>
      compareBytes(left.identified.operationId, right.identified.operationId),
    ) as [PresenceFixture, PresenceFixture];
    presences = [remote, local, alternate];
  } else if (defect === "ownership") {
    const genuine: PresenceFixture[] = [
      await buildPresence(context, 0x22),
      await buildPresence(context, 0x23),
    ];
    let nonceByte = 0x21;
    remote = await buildPresence(context, nonceByte, {
      genuineOwnership: false,
    });
    while (
      genuine.every(
        (presence) =>
          compareBytes(
            remote.identified.operationId,
            presence.identified.operationId,
          ) >= 0,
      )
    ) {
      nonceByte += 1;
      remote = await buildPresence(context, nonceByte, {
        genuineOwnership: false,
      });
    }
    local = genuine.find(
      (presence) =>
        compareBytes(
          remote.identified.operationId,
          presence.identified.operationId,
        ) < 0,
    ) as PresenceFixture;
    alternate = genuine.find(
      (presence) => presence !== local,
    ) as PresenceFixture;
    presences = [remote, ...genuine];
  } else {
    const sorted = [
      await buildPresence(context, 0x21),
      await buildPresence(context, 0x22),
      await buildPresence(context, 0x23),
    ].sort((left, right) =>
      compareBytes(left.identified.operationId, right.identified.operationId),
    );
    [remote, local, alternate] = sorted as [
      PresenceFixture,
      PresenceFixture,
      PresenceFixture,
    ];
    presences = sorted;
  }

  const pairAuthor = await newKeyPair(module);
  trackSecret(pairAuthor.secretKey);
  const pairExpiry =
    HELLO_WINDOW +
    BigInt(
      options.pairLifetimeWindows ??
        context.roomPolicy.protocolLimits.pairControlRetentionWindows,
    );
  const policyDigest = await policyHash(context.roomPolicy);
  const outerFields: PairBootstrapOuterFieldsV1 = {
    version: 1,
    roomContextConfirmation: context.roomContextConfirmation,
    policyHash: policyDigest,
    logicalWindow: HELLO_WINDOW,
    expiresAfterWindow: pairExpiry,
    lifetime: "PAIR_CAUSAL",
    authorEpochEd25519Key: pairAuthor.publicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    kind: "PAIR_STEP",
    dependencies: [],
    operationPayloadClass: 0,
  };
  const bootstrapInfo: PairBootstrapInfoV1 = {
    version: 1,
    pairBootstrapSuite: context.roomPolicy.pairBootstrapSuite,
    roomContextConfirmation: context.roomContextConfirmation,
    policyHash: policyDigest,
    stepKind: "IDENTITY_HELLO",
    logicalWindow: HELLO_WINDOW,
    expiresAfterWindow: pairExpiry,
    authorEpochEd25519Key: pairAuthor.publicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    operationPayloadClass: 0,
    recipientBinding: {
      kind: "presence",
      presenceOperationId: local.identified.operationId,
    },
  };
  const roomRoot = trackSecret(
    new Uint8Array(PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes).fill(
      0x60 + (fixtureOrdinal % 16),
    ),
  );
  const responseReceiver = await generateHpkeRecipientKeyPair(module);
  let sealed: PairBootstrapSealResultV1;
  try {
    sealed = await sealPairBootstrapV1({
      module,
      recipientHybridKemPublicKey: local.receiverPublicKey,
      psk: roomRoot,
      bootstrapInfo,
      outerFields,
      roomPqMode: decodeRoomPolicyV1(context.roomPolicy.sessionPolicyV1).pqMode,
      createSignedPlaintext: (binding) =>
        buildSignedHelloPlaintext({
          fixtureDefect: defect,
          context,
          binding,
          remote,
          local,
          alternate,
          responseHybridKemPublicKey: responseReceiver.publicKey,
          carriedGrantNotAfter: options.carriedGrantNotAfter ?? null,
        }),
    });
  } finally {
    responseReceiver.destroy();
  }
  sealed.bootstrapRoot.fill(0);

  let envelope = sealed.envelope;
  if (options.wrongRoutingTag === true) {
    envelope = {
      ...envelope,
      pairRoutingTag: flipped(envelope.pairRoutingTag),
    };
  }
  if (options.corruptCiphertext === true) {
    envelope = {
      ...envelope,
      pairCiphertextAndTag: flipped(envelope.pairCiphertextAndTag),
    };
  }
  if (options.lowOrderKemCiphertext === true) {
    if (envelope.bootstrapHeader === null)
      throw new Error("test HELLO unexpectedly lacks its KEM header");
    const hybridKemCiphertext = Uint8Array.from(
      envelope.bootstrapHeader.hybridKemCiphertext,
    );
    hybridKemCiphertext.subarray(hybridKemCiphertext.length - 32).fill(0);
    envelope = {
      ...envelope,
      bootstrapHeader: {
        ...envelope.bootstrapHeader,
        hybridKemCiphertext,
      },
    };
  }

  const pairPayload = encodePairStepEnvelopeV1(envelope, 0);
  const pairUnsigned: UnsignedRoomOperationV1 = {
    version: 1,
    roomContextConfirmation: context.roomContextConfirmation,
    logicalWindow: HELLO_WINDOW,
    expiresAfterWindow: pairExpiry,
    lifetime: "PAIR_CAUSAL",
    authorEpochEd25519Key: pairAuthor.publicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    kind: "PAIR_STEP",
    semanticSlot: await pairSemanticSlot(envelope.pairRoutingTag),
    dependencies: [],
    operationPayloadClass: 0,
    fixedPayload: pairPayload,
    operationPadding: operationPaddingFor(0, pairPayload.length),
  };
  const pair = await validateAndIdentifyOperationCandidate(
    await signOperation(pairUnsigned, pairAuthor.secretKey, module),
    context,
    module,
  );
  const observedPresences =
    options.omitRemoteFromEvidence === true
      ? presences.filter((presence) => presence !== remote)
      : presences;
  const state = await coreReduce(
    [...observedPresences.map((presence) => presence.identified), pair],
    context,
    module,
  );
  const active = await captureActivePairOperationCandidate(pair, state);
  const evidenceByPresence = new Map<
    PresenceFixture,
    VerifiedHistoricalPairPresenceEvidenceV1
  >();
  for (const presence of observedPresences)
    evidenceByPresence.set(
      presence,
      await captureHistoricalPairPresenceEvidence(
        presence.identified,
        state,
        HELLO_WINDOW,
      ),
    );
  const evidenceView = await createHistoricalIdentityHelloEvidenceViewV1({
    historicalPresenceEvidence: [...evidenceByPresence.values()],
  });
  trackedViews.add(evidenceView);
  const localEvidence = evidenceByPresence.get(local);
  if (localEvidence === undefined)
    throw new Error("test Core omitted the local presence");
  const localCustody = await createLocalHelloReceiverCustodyV1({
    module,
    localPresenceEvidence: localEvidence,
    recipientHybridKemSecretSeed: local.receiverSecretSeed,
    roomRoot,
    localStableEd25519PublicKey: local.stablePublicKey,
    receiverKeyRecordRevision: RECEIVER_REVISION,
  });
  trackedCustodies.add(localCustody);
  return {
    context,
    remote,
    local,
    alternate,
    presences,
    pair,
    state,
    active,
    evidenceByPresence,
    evidenceView,
    localCustody,
    roomRoot,
  };
};

const createTrial = (
  fixture: HelloFixture,
  options: {
    readonly active?: ActivePairOperationCandidateV1;
    readonly custody?: LocalHelloReceiverCustodyV1;
    readonly evidenceView?: HistoricalIdentityHelloEvidenceViewV1;
  } = {},
): ExpectedIdentityHelloTrialV1 => {
  const trial = createExpectedIdentityHelloTrialV1({
    activeCandidate: options.active ?? fixture.active,
    receiverCustody: options.custody ?? fixture.localCustody,
    historicalEvidenceView: options.evidenceView ?? fixture.evidenceView,
    trialOrdinal: trackedTrials.size,
  });
  trackedTrials.add(trial);
  return trial;
};

const reserveTrial = async (
  candidate: ActivePairOperationCandidateV1,
  trial: ExpectedIdentityHelloTrialV1,
): Promise<ReservedIdentityHelloOpenV1> => {
  const port: PairOpenReservationStorePortV1 = {
    readExactBudgetRow: async () => ({ kind: "absent" }),
    compareAndSwap: async (request) => {
      if (request.budgetMutation.kind !== "replace")
        throw new Error("test expected a fresh replacement budget row");
      return {
        status: "committed",
        exactBudgetRowBytes: Uint8Array.from(
          request.budgetMutation.exactNextBytes,
        ),
      };
    },
  };
  const service = createPairOpenReservationServiceV1(port, {
    maxPairOpenTrialsPerPresenceWindow: 8,
    maxPairOpenBytesPerPresenceWindow: Number.MAX_SAFE_INTEGER,
  });
  const result = await service.reserveIdentityHelloOpen(candidate, trial);
  if (result.kind !== "reserved")
    throw new Error(`test expected reservation, received ${result.kind}`);
  return result.capability;
};

const openFresh = async (
  fixture: HelloFixture,
  options: {
    readonly active?: ActivePairOperationCandidateV1;
    readonly custody?: LocalHelloReceiverCustodyV1;
    readonly evidenceView?: HistoricalIdentityHelloEvidenceViewV1;
    readonly cryptoModule?: LibCrypto;
  } = {},
) => {
  const active = options.active ?? fixture.active;
  const trial = createTrial(fixture, options);
  const capability = await reserveTrial(active, trial);
  const result = await openReservedIdentityHelloV1(
    capability,
    trial,
    options.cryptoModule ?? module,
  );
  if (result.kind === "opened") trackedOpens.add(result.value);
  return result;
};

const createCustody = async (
  fixture: HelloFixture,
  presence: PresenceFixture,
  roomRoot: Uint8Array,
): Promise<LocalHelloReceiverCustodyV1> => {
  const evidence = fixture.evidenceByPresence.get(presence);
  if (evidence === undefined)
    throw new Error("test presence has no exact historical evidence");
  const custody = await createLocalHelloReceiverCustodyV1({
    module,
    localPresenceEvidence: evidence,
    recipientHybridKemSecretSeed: presence.receiverSecretSeed,
    roomRoot,
    localStableEd25519PublicKey: presence.stablePublicKey,
    receiverKeyRecordRevision: RECEIVER_REVISION + 1n,
  });
  trackedCustodies.add(custody);
  return custody;
};

describe("reservation-gated identity HELLO open", () => {
  test("opens a real signed HELLO into an opaque owned snapshot and a base-only lease", async () => {
    const fixture = await buildHelloFixture({
      carriedGrantNotAfter: HELLO_WINDOW,
      pairLifetimeWindows: 37,
    });
    const callerSeed = trackSecret(
      Uint8Array.from(fixture.local.receiverSecretSeed),
    );
    const callerRoot = trackSecret(Uint8Array.from(fixture.roomRoot));
    const result = await openFresh(fixture);
    expect(result.kind).toBe("opened");
    if (result.kind !== "opened") return;

    const snapshot = snapshotVerifiedIdentityHelloOpenV1(result.value);
    expect(snapshot.version).toBe(1);
    expect(snapshot.plaintext.kind).toBe("IDENTITY_HELLO");
    expectBytesEqual(
      snapshot.plaintext.endpointPresenceOperationIds[0],
      fixture.remote.identified.operationId,
    );
    expectBytesEqual(
      snapshot.plaintext.endpointPresenceOperationIds[1],
      fixture.local.identified.operationId,
    );
    expectBytesEqual(
      snapshot.remotePresenceEvidence.presenceOperationId,
      fixture.remote.identified.operationId,
    );
    expect(snapshot.remotePresenceEvidence.provedAtLogicalWindow).toBe(
      HELLO_WINDOW,
    );
    expect(snapshot.basePairAttemptLease.helloLogicalWindow).toBe(HELLO_WINDOW);
    expect(snapshot.basePairAttemptLease.validThroughLogicalWindow).toBe(
      HELLO_WINDOW + 37n,
    );
    expect(
      snapshot.basePairAttemptLease.validThroughLogicalWindow,
    ).toBeGreaterThan(
      snapshot.plaintext.body.kind === "IDENTITY_HELLO"
        ? (snapshot.plaintext.body.value.senderAdmissionGrant
            ?.notAfterLogicalWindow ?? 0n)
        : 0n,
    );
    expect(containsSecretField(snapshot)).toBe(false);
    expectBytesEqual(fixture.local.receiverSecretSeed, callerSeed);
    expectBytesEqual(fixture.roomRoot, callerRoot);

    const expectedRemote = Uint8Array.from(
      snapshot.remotePresenceEvidence.presenceOperationId,
    );
    snapshot.helloOperationId.fill(0);
    snapshot.plaintext.pairEdgeId.fill(0);
    snapshot.remotePresenceEvidence.presenceOperationId.fill(0);
    snapshot.basePairAttemptLease.pairEdgeId.fill(0);
    const fresh = snapshotVerifiedIdentityHelloOpenV1(result.value);
    expectBytesEqual(
      fresh.remotePresenceEvidence.presenceOperationId,
      expectedRemote,
    );
    expect(fresh.plaintext.pairEdgeId.some((byte) => byte !== 0)).toBe(true);

    const spread = { ...(result.value as object) };
    expect(() =>
      snapshotVerifiedIdentityHelloOpenV1(spread as typeof result.value),
    ).toThrow("genuine live process-local handle");
    destroyVerifiedIdentityHelloOpenV1(result.value);
    destroyVerifiedIdentityHelloOpenV1(result.value);
    expect(() => snapshotVerifiedIdentityHelloOpenV1(result.value)).toThrow(
      "genuine live process-local handle",
    );
  });

  test("moves an authenticated HELLO exactly once into an opaque root-custody admission context", async () => {
    const fixture = await buildHelloFixture({
      carriedGrantNotAfter: HELLO_WINDOW + 9n,
      pairLifetimeWindows: 23,
    });
    const result = await openFresh(fixture);
    expect(result.kind).toBe("opened");
    if (result.kind !== "opened") return;

    const context = promoteVerifiedIdentityHelloOpenForAdmissionV1(
      result.value,
    );
    trackedAdmissionContexts.add(context);
    expect(Reflect.ownKeys(context)).toEqual([]);
    expect(() => snapshotVerifiedIdentityHelloOpenV1(result.value)).toThrow(
      "genuine live process-local handle",
    );
    let secondPromotionError: unknown;
    try {
      promoteVerifiedIdentityHelloOpenForAdmissionV1(result.value);
    } catch (error) {
      secondPromotionError = error;
    }
    expect(secondPromotionError).toBeInstanceOf(AdmissionInputError);
    expect((secondPromotionError as AdmissionInputError).code).toBe(
      "invalid-admission-kernel-input",
    );

    const snapshot = snapshotVerifiedAdmissionContextV1(context);
    expect(snapshot).toMatchObject({
      version: 1,
      decisionRole: "hello-responder",
      kind: "IDENTITY_HELLO",
      logicalWindow: HELLO_WINDOW,
      direction: 0,
      pairSequence: 0n,
      previousPairOperationId: null,
      pairDependencies: [],
    });
    expectBytesEqual(snapshot.operationId, fixture.pair.operationId);
    expectBytesEqual(snapshot.roomContextId, fixture.context.roomContextId);
    expectBytesEqual(
      snapshot.stableEd25519PublicKey,
      fixture.remote.stablePublicKey,
    );
    expectBytesEqual(
      snapshot.claimedStableIdentityCommitment,
      fixture.remote.stableCommitment,
    );
    expectBytesEqual(
      snapshot.admittedPresenceOperationId,
      fixture.remote.identified.operationId,
    );
    expectBytesEqual(
      snapshot.basePairAttemptLease.helloOperationId,
      fixture.pair.operationId,
    );
    expect(snapshot.basePairAttemptLease.validThroughLogicalWindow).toBe(
      HELLO_WINDOW + 23n,
    );
    expect(snapshot.optionalGrant?.notAfterLogicalWindow).toBe(
      HELLO_WINDOW + 9n,
    );
    expect(containsSecretField(snapshot)).toBe(false);

    snapshot.operationId.fill(0);
    snapshot.stableEd25519PublicKey.fill(0);
    snapshot.optionalGrant?.authoritySignature.fill(0);
    const fresh = snapshotVerifiedAdmissionContextV1(context);
    expectBytesEqual(fresh.operationId, fixture.pair.operationId);
    expectBytesEqual(
      fresh.stableEd25519PublicKey,
      fixture.remote.stablePublicKey,
    );
    expect(
      fresh.optionalGrant?.authoritySignature.some((byte) => byte !== 0),
    ).toBe(true);

    const spread = { ...(context as object) };
    expect(() =>
      snapshotVerifiedAdmissionContextV1(spread as VerifiedAdmissionContextV1),
    ).toThrow("genuine live process-local handle");

    destroyVerifiedAdmissionContextV1(context);
    destroyVerifiedAdmissionContextV1(context);
    expect(() => snapshotVerifiedAdmissionContextV1(context)).toThrow(
      "genuine live process-local handle",
    );
  });

  test("classifies wrong RoomRoot, another genuine receiver, tag, AEAD, and low-order KEM ciphertext as not-this-trial", async () => {
    const fixture = await buildHelloFixture();
    const wrongRoot = trackSecret(flipped(fixture.roomRoot));
    const wrongRootCustody = await createCustody(
      fixture,
      fixture.local,
      wrongRoot,
    );
    expect((await openFresh(fixture, { custody: wrongRootCustody })).kind).toBe(
      "not-this-trial",
    );
    const alternateCustody = await createCustody(
      fixture,
      fixture.alternate,
      fixture.roomRoot,
    );
    expect((await openFresh(fixture, { custody: alternateCustody })).kind).toBe(
      "not-this-trial",
    );

    for (const mutation of [
      { wrongRoutingTag: true },
      { corruptCiphertext: true },
      { lowOrderKemCiphertext: true },
    ] as const) {
      const mutated = await buildHelloFixture(mutation);
      expect((await openFresh(mutated)).kind).toBe("not-this-trial");
    }
  });

  test("rejects authenticated edge, role, commitment, cross-signature, transcript, ownership, self, and response-key defects", async () => {
    for (const defect of [
      "pair-edge",
      "local-tuple",
      "commitment",
      "cross-signature",
      "identity-signature",
      "ownership",
      "self",
      "response-x25519",
      "response-mlkem",
    ] as const) {
      const fixture = await buildHelloFixture({ defect });
      expect((await openFresh(fixture)).kind, defect).toBe("rejected");
    }
  });

  test("defers only a self-authenticated missing sender, consumes that attempt, then opens with a fresh complete Core view", async () => {
    const fixture = await buildHelloFixture({
      omitRemoteFromEvidence: true,
    });
    const firstTrial = createTrial(fixture);
    const firstCapability = await reserveTrial(fixture.active, firstTrial);
    expect(
      await openReservedIdentityHelloV1(firstCapability, firstTrial, module),
    ).toEqual({
      kind: "deferred",
      reason: "missing-presence-evidence",
    });
    await expect(
      openReservedIdentityHelloV1(firstCapability, firstTrial, module),
    ).rejects.toThrow();

    const fullState = await coreReduce(
      [
        ...fixture.presences.map((presence) => presence.identified),
        fixture.pair,
      ],
      fixture.context,
      module,
    );
    const fullActive = await captureActivePairOperationCandidate(
      fixture.pair,
      fullState,
    );
    const fullEvidence: VerifiedHistoricalPairPresenceEvidenceV1[] = [];
    for (const presence of fixture.presences)
      fullEvidence.push(
        await captureHistoricalPairPresenceEvidence(
          presence.identified,
          fullState,
          HELLO_WINDOW,
        ),
      );
    const fullView = await createHistoricalIdentityHelloEvidenceViewV1({
      historicalPresenceEvidence: fullEvidence,
    });
    trackedViews.add(fullView);
    const retried = await openFresh(fixture, {
      active: fullActive,
      evidenceView: fullView,
    });
    expect(retried.kind).toBe("opened");

    const forgedMissing = await buildHelloFixture({
      omitRemoteFromEvidence: true,
      defect: "identity-signature",
    });
    expect((await openFresh(forgedMissing)).kind).toBe("rejected");
  });

  test("uses exact HELLO-time evidence after an effective LEAVE in a later active Core", async () => {
    const fixture = await buildHelloFixture();
    const leaveWindow = HELLO_WINDOW + 1n;
    const laterContext = operationValidationContextAt(
      fixture.context,
      HELLO_WINDOW + 2n,
    );
    const leavePayload = encodeLeaveV1({
      version: 1,
      presenceOperationId: fixture.remote.identified.operationId,
      effectiveLogicalWindow: leaveWindow,
    });
    const leaveUnsigned: UnsignedRoomOperationV1 = {
      version: 1,
      roomContextConfirmation: laterContext.roomContextConfirmation,
      logicalWindow: leaveWindow,
      expiresAfterWindow:
        leaveWindow +
        BigInt(
          laterContext.roomPolicy.protocolLimits.operationRetentionWindows,
        ),
      lifetime: "WINDOW_TRANSIENT",
      authorEpochEd25519Key: fixture.remote.authorPublicKey,
      authorSequence: 0n,
      previousAuthorOperationId: null,
      kind: "LEAVE",
      semanticSlot: await leaveSemanticSlot(
        fixture.remote.identified.operationId,
        leaveWindow,
      ),
      dependencies: [fixture.remote.identified.operationId],
      operationPayloadClass: 0,
      fixedPayload: leavePayload,
      operationPadding: operationPaddingFor(0, leavePayload.length),
    };
    const leave = await validateAndIdentifyOperationCandidate(
      await signOperation(
        leaveUnsigned,
        fixture.remote.authorSecretKey,
        module,
      ),
      laterContext,
      module,
    );
    const laterState = await coreReduce(
      [
        ...fixture.presences.map((presence) => presence.identified),
        fixture.pair,
        leave,
      ],
      laterContext,
      module,
    );
    expect(
      laterState.observedPresences.some((presence) =>
        Buffer.from(presence.presenceOperationId).equals(
          Buffer.from(fixture.remote.identified.operationId),
        ),
      ),
    ).toBe(false);
    const laterActive = await captureActivePairOperationCandidate(
      fixture.pair,
      laterState,
    );
    const delayed = await openFresh(fixture, {
      active: laterActive,
    });
    expect(delayed.kind).toBe("opened");
    if (delayed.kind !== "opened") return;
    const snapshot = snapshotVerifiedIdentityHelloOpenV1(delayed.value);
    expect(snapshot.activeCandidate.referenceWindow).toBe(HELLO_WINDOW + 2n);
    expect(snapshot.remotePresenceEvidence.provedAtLogicalWindow).toBe(
      HELLO_WINDOW,
    );
    expect(snapshot.activeCandidate.exactCoreStateBytes).not.toEqual(
      snapshot.remotePresenceEvidence.exactCoreStateBytes,
    );
  });

  test("requires a genuine reservation before module access and consumes capability and trial synchronously", async () => {
    const fixture = await buildHelloFixture();
    const trial = createTrial(fixture);
    let moduleReads = 0;
    const poisonModule = new Proxy({} as LibCrypto, {
      get() {
        moduleReads += 1;
        throw new Error("poison module was accessed");
      },
    });
    await expect(
      openReservedIdentityHelloV1(
        {} as ReservedIdentityHelloOpenV1,
        trial,
        poisonModule,
      ),
    ).rejects.toThrow("genuine unused reservation");
    expect(moduleReads).toBe(0);
    expect(() => snapshotExpectedIdentityHelloTrialV1(trial)).not.toThrow();

    const capability = await reserveTrial(fixture.active, trial);
    await expect(
      openReservedIdentityHelloV1(
        { ...(capability as object) } as ReservedIdentityHelloOpenV1,
        trial,
        poisonModule,
      ),
    ).rejects.toThrow("genuine unused reservation");
    expect(moduleReads).toBe(0);

    const pending = openReservedIdentityHelloV1(capability, trial, module);
    expect(() => snapshotExpectedIdentityHelloTrialV1(trial)).toThrow(
      "genuine live process-local capability",
    );
    const stillLiveTrial = createTrial(fixture);
    const reused = openReservedIdentityHelloV1(
      capability,
      stillLiveTrial,
      poisonModule,
    );
    expect(moduleReads).toBe(0);
    await expect(reused).rejects.toThrow("genuine unused reservation");
    expect(() =>
      snapshotExpectedIdentityHelloTrialV1(stillLiveTrial),
    ).not.toThrow();
    const result = await pending;
    expect(result.kind).toBe("opened");
    if (result.kind === "opened") trackedOpens.add(result.value);
  });

  test("propagates infrastructure failures after consumption", async () => {
    const fixture = await buildHelloFixture();
    const trial = createTrial(fixture);
    const capability = await reserveTrial(fixture.active, trial);
    const throwingModule = new Proxy(module, {
      get(target, property, receiver) {
        if (property === "wasmMemory")
          throw new Error("injected infrastructure failure");
        return Reflect.get(target, property, receiver);
      },
    });
    await expect(
      openReservedIdentityHelloV1(capability, trial, throwingModule),
    ).rejects.toThrow("injected infrastructure failure");
    await expect(
      openReservedIdentityHelloV1(capability, trial, module),
    ).rejects.toThrow();
  });

  test("keeps raw HelloRoot transfer private and wipes every owned secret path in finally/destroy", async () => {
    const moduleExports =
      await import("../../src/blindRendezvous/identityHelloOpen");
    expect(
      Object.keys(moduleExports).some((name) =>
        name.toLowerCase().includes("helloroot"),
      ),
    ).toBe(false);
    const source = readFileSync(
      new URL(
        "../../src/blindRendezvous/identityHelloOpen.ts",
        import.meta.url,
      ),
      "utf8",
    );
    expect(source).toContain("recipientSeed.fill(0)");
    expect(source).toContain("roomRoot.fill(0)");
    expect(source).toContain("openedRoot?.fill(0)");
    expect(source).toContain("state.helloRoot.fill(0)");
    expect(source.indexOf("openedRoot = opened.bootstrapRoot")).toBeLessThan(
      source.indexOf("if (authenticatedFacts === undefined)"),
    );
    expect(source).not.toContain("export const consumeVerifiedIdentityHello");
  });
});
