import { afterEach, describe, expect, test } from "bun:test";

import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import { generateHpkeRecipientKeyPair } from "../../src/cryptography/hpke";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  captureActivePairOperationCandidate,
  captureHistoricalPairPresenceEvidence,
  coreReduce,
  validateAndIdentifyOperationCandidate,
} from "../../src/blindRendezvous/coreReduce";
import {
  leaveSemanticSlot,
  pairSemanticSlot,
  policyHash,
  presenceOwnershipSignedMessage,
  presenceProofTranscriptHash,
  presenceSemanticSlot,
  stableIdentityCommitment,
} from "../../src/blindRendezvous/derivations";
import {
  assertExpectedIdentityHelloTrialBindingsV1,
  assertExpectedIdentityHelloTrialCandidateBindingV1,
  consumeReservedExpectedIdentityHelloTrialForPairOpenV1,
  createExpectedIdentityHelloTrialV1,
  createHistoricalIdentityHelloEvidenceViewV1,
  createLocalHelloReceiverCustodyV1,
  destroyExpectedIdentityHelloTrialV1,
  destroyHistoricalIdentityHelloEvidenceViewV1,
  destroyLocalHelloReceiverCustodyV1,
  snapshotExpectedIdentityHelloTrialV1,
  snapshotHistoricalIdentityHelloEvidenceViewV1,
  snapshotLocalHelloReceiverCustodyV1,
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
import {
  encodePairStepEnvelopeV1,
  pairCiphertextAndTagTargetBytesV1,
} from "../../src/blindRendezvous/pairStepEnvelope";
import { PAIR_BOOTSTRAP_SUITE_V1 } from "../../src/blindRendezvous/pairBootstrapSuite";
import { createPairOpenReservationServiceV1 } from "../../src/blindRendezvous/pairOpenReservation";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";
import {
  createLocalStableIdentityCustodyV1,
  destroyLocalStableIdentityCustodyV1,
  snapshotLocalStableIdentityCustodyV1,
} from "../../src/blindRendezvous/localStableIdentityCustody";

import type {
  ActivePairOperationCandidateV1,
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
import type {
  PairOpenReservationStorePortV1,
  ReservedIdentityHelloOpenV1,
} from "../../src/blindRendezvous/pairOpenReservation";
import type { PresenceCoreV1 } from "../../src/blindRendezvous/operationPayload";
import type { LocalStableIdentityCustodyV1 } from "../../src/blindRendezvous/localStableIdentityCustody";

const module = await loadTestModule();
const policy = DEFAULT_BLIND_POLICY_V4_0;
const DEFAULT_CAPABILITY = new Uint8Array(32).fill(0x53);
const HELLO_WINDOW = 1_000n;
const RECEIVER_KEY_RECORD_REVISION = 9n;
const LOCAL_IDENTITY_KEY_RECORD_REVISION = 7n;

const copyPolicy = () => ({
  ...policy,
  sessionPolicyV1: Uint8Array.from(policy.sessionPolicyV1),
  protocolLimits: { ...policy.protocolLimits },
  admissionFloor: { ...policy.admissionFloor },
});

const expectBytesEqual = (left: Uint8Array, right: Uint8Array): void => {
  expect(Buffer.from(left)).toEqual(Buffer.from(right));
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
    if (typeof key === "string") {
      const normalized = key.toLowerCase();
      if (normalized.includes("secret") || normalized.includes("roomroot"))
        return true;
    }
    if (containsSecretField(Reflect.get(value, key), seen)) return true;
  }
  return false;
};

interface PresenceFixture {
  readonly identified: OuterValidatedIdentifiedOperationV1;
  readonly authorPublicKey: Uint8Array;
  readonly authorSecretKey: Uint8Array;
  readonly stablePublicKey: Uint8Array;
  readonly stableSecretKey: Uint8Array;
  readonly receiverPublicKey: Uint8Array;
  readonly receiverSecretSeed: Uint8Array;
}

const buildPresence = async (
  context: OperationValidationContext,
  seedByte: number,
  genuineOwnership: boolean,
): Promise<PresenceFixture> => {
  const stable = await newKeyPair(module);
  const author = await newKeyPair(module);
  const receiver = await generateHpkeRecipientKeyPair(module);
  const validThrough = HELLO_WINDOW + 8n;
  const core: PresenceCoreV1 = {
    version: 1,
    stableIdentityCommitment: await stableIdentityCommitment(
      context.roomContextId,
      stable.publicKey,
    ),
    rendezvousHybridKemPublicKey: Uint8Array.from(receiver.publicKey),
    receiverKeyValidThroughLogicalWindow: validThrough,
    presenceNonce: new Uint8Array(32).fill(seedByte),
    validThroughLogicalWindow: validThrough,
  };
  const proofHash = await presenceProofTranscriptHash({
    roomContextId: context.roomContextId,
    policyHash: await policyHash(context.roomPolicy),
    logicalWindow: HELLO_WINDOW,
    authorEpochEd25519Key: author.publicKey,
    core,
  });
  const ownershipSignature = genuineOwnership
    ? await sign(
        presenceOwnershipSignedMessage(proofHash),
        stable.secretKey,
        module,
      )
    : new Uint8Array(64).fill(seedByte ^ 0xff);
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
  const operation = await signOperation(unsigned, author.secretKey, module);
  const identified = await validateAndIdentifyOperationCandidate(
    operation,
    context,
    module,
  );
  const receiverSecretSeed = Uint8Array.from(receiver.secretKey);
  const receiverPublicKey = Uint8Array.from(receiver.publicKey);
  const authorPublicKey = Uint8Array.from(author.publicKey);
  const authorSecretKey = Uint8Array.from(author.secretKey);
  const stablePublicKey = Uint8Array.from(stable.publicKey);
  const stableSecretKey = Uint8Array.from(stable.secretKey);
  receiver.destroy();
  stable.secretKey.fill(0);
  author.secretKey.fill(0);
  return {
    identified,
    authorPublicKey,
    authorSecretKey,
    stablePublicKey,
    stableSecretKey,
    receiverPublicKey,
    receiverSecretSeed,
  };
};

const buildPairCandidate = async (
  context: OperationValidationContext,
  bootstrap: boolean,
): Promise<OuterValidatedIdentifiedOperationV1> => {
  const author = await newKeyPair(module);
  const routingTag = new Uint8Array(32).fill(bootstrap ? 0x71 : 0x72);
  const envelope = {
    version: 1 as const,
    pairRoutingTag: routingTag,
    bootstrapHeader: bootstrap
      ? {
          version: 1 as const,
          suiteId: 1 as const,
          hybridKemCiphertext: new Uint8Array(1_120).fill(0x73),
        }
      : null,
    nonce: bootstrap ? null : new Uint8Array(24).fill(0x74),
    pairCiphertextAndTag: new Uint8Array(
      pairCiphertextAndTagTargetBytesV1(0, bootstrap),
    ).fill(0x75),
  };
  const payload = encodePairStepEnvelopeV1(envelope, 0);
  const unsigned: UnsignedRoomOperationV1 = {
    version: 1,
    roomContextConfirmation: context.roomContextConfirmation,
    logicalWindow: HELLO_WINDOW,
    expiresAfterWindow: HELLO_WINDOW + 8n,
    lifetime: "PAIR_CAUSAL",
    authorEpochEd25519Key: author.publicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    kind: "PAIR_STEP",
    semanticSlot: await pairSemanticSlot(routingTag),
    dependencies: [],
    operationPayloadClass: 0,
    fixedPayload: payload,
    operationPadding: operationPaddingFor(0, payload.length),
  };
  const operation = await signOperation(unsigned, author.secretKey, module);
  author.secretKey.fill(0);
  return validateAndIdentifyOperationCandidate(operation, context, module);
};

const buildLeaveCandidate = async (
  context: OperationValidationContext,
  presenceOperationId: Uint8Array,
  authorPublicKey: Uint8Array,
  authorSecretKey: Uint8Array,
  effectiveLogicalWindow: bigint,
): Promise<OuterValidatedIdentifiedOperationV1> => {
  const leave = {
    version: 1 as const,
    presenceOperationId: Uint8Array.from(presenceOperationId),
    effectiveLogicalWindow,
  };
  const payload = encodeLeaveV1(leave);
  const unsigned: UnsignedRoomOperationV1 = {
    version: 1,
    roomContextConfirmation: context.roomContextConfirmation,
    logicalWindow: effectiveLogicalWindow,
    expiresAfterWindow: effectiveLogicalWindow + 8n,
    lifetime: "WINDOW_TRANSIENT",
    authorEpochEd25519Key: authorPublicKey,
    authorSequence: 0n,
    previousAuthorOperationId: null,
    kind: "LEAVE",
    semanticSlot: await leaveSemanticSlot(
      leave.presenceOperationId,
      leave.effectiveLogicalWindow,
    ),
    dependencies: [leave.presenceOperationId],
    operationPayloadClass: 0,
    fixedPayload: payload,
    operationPadding: operationPaddingFor(0, payload.length),
  };
  const operation = await signOperation(unsigned, authorSecretKey, module);
  return validateAndIdentifyOperationCandidate(operation, context, module);
};

interface TrialFixture {
  readonly context: OperationValidationContext;
  readonly active: ActivePairOperationCandidateV1;
  readonly pair: OuterValidatedIdentifiedOperationV1;
  readonly localEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly remoteEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly localEvidenceFromDifferentCore: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly remoteEvidenceFromDifferentCore: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly evidenceView: HistoricalIdentityHelloEvidenceViewV1;
  readonly evidenceViewFromDifferentCore: HistoricalIdentityHelloEvidenceViewV1;
  readonly local: PresenceFixture;
  readonly remote: PresenceFixture;
  readonly custody: LocalHelloReceiverCustodyV1;
  readonly roomRoot: Uint8Array;
}

const fixtures = new Set<TrialFixture>();
const extraCustodies = new Set<LocalHelloReceiverCustodyV1>();
const stableCustodies = new Set<LocalStableIdentityCustodyV1>();
const extraEvidenceViews = new Set<HistoricalIdentityHelloEvidenceViewV1>();

afterEach(() => {
  for (const custody of extraCustodies)
    destroyLocalHelloReceiverCustodyV1(custody);
  extraCustodies.clear();
  for (const view of extraEvidenceViews)
    destroyHistoricalIdentityHelloEvidenceViewV1(view);
  extraEvidenceViews.clear();
  for (const fixture of fixtures) {
    destroyLocalHelloReceiverCustodyV1(fixture.custody);
    destroyHistoricalIdentityHelloEvidenceViewV1(fixture.evidenceView);
    destroyHistoricalIdentityHelloEvidenceViewV1(
      fixture.evidenceViewFromDifferentCore,
    );
    fixture.local.receiverSecretSeed.fill(0);
    fixture.remote.receiverSecretSeed.fill(0);
    fixture.local.authorSecretKey.fill(0);
    fixture.remote.authorSecretKey.fill(0);
    fixture.local.stableSecretKey.fill(0);
    fixture.remote.stableSecretKey.fill(0);
    fixture.roomRoot.fill(0);
  }
  fixtures.clear();
  for (const custody of stableCustodies)
    destroyLocalStableIdentityCustodyV1(custody);
  stableCustodies.clear();
});

const createStableCustody = async (
  presence: PresenceFixture,
  revision = LOCAL_IDENTITY_KEY_RECORD_REVISION,
): Promise<LocalStableIdentityCustodyV1> => {
  const custody = await createLocalStableIdentityCustodyV1({
    module,
    stableEd25519SecretKey: presence.stableSecretKey,
    localIdentityKeyRecordRevision: revision,
  });
  stableCustodies.add(custody);
  return custody;
};

const buildFixture = async (
  bootstrap = true,
  roomCapability = DEFAULT_CAPABILITY,
): Promise<TrialFixture> => {
  const context = await createOperationValidationContext(
    roomCapability,
    copyPolicy(),
    HELLO_WINDOW,
  );
  const local = await buildPresence(context, 0x21, true);
  const remote = await buildPresence(context, 0x22, false);
  const pair = await buildPairCandidate(context, bootstrap);
  const fullState = await coreReduce(
    [local.identified, remote.identified, pair],
    context,
    module,
  );
  const presenceOnlyState = await coreReduce(
    [local.identified, remote.identified],
    context,
    module,
  );
  const localEvidence = await captureHistoricalPairPresenceEvidence(
    local.identified,
    fullState,
    HELLO_WINDOW,
  );
  const remoteEvidence = await captureHistoricalPairPresenceEvidence(
    remote.identified,
    fullState,
    HELLO_WINDOW,
  );
  const localEvidenceFromDifferentCore =
    await captureHistoricalPairPresenceEvidence(
      local.identified,
      presenceOnlyState,
      HELLO_WINDOW,
    );
  const remoteEvidenceFromDifferentCore =
    await captureHistoricalPairPresenceEvidence(
      remote.identified,
      presenceOnlyState,
      HELLO_WINDOW,
    );
  const evidenceView = await createHistoricalIdentityHelloEvidenceViewV1({
    historicalPresenceEvidence: [localEvidence, remoteEvidence],
  });
  const evidenceViewFromDifferentCore =
    await createHistoricalIdentityHelloEvidenceViewV1({
      historicalPresenceEvidence: [
        localEvidenceFromDifferentCore,
        remoteEvidenceFromDifferentCore,
      ],
    });
  const roomRoot = new Uint8Array(PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes).fill(
    0x61,
  );
  const custody = await createLocalHelloReceiverCustodyV1({
    module,
    localPresenceEvidence: localEvidence,
    recipientHybridKemSecretSeed: local.receiverSecretSeed,
    roomRoot,
    localStableIdentityCustody: await createStableCustody(local),
    receiverKeyRecordRevision: RECEIVER_KEY_RECORD_REVISION,
  });
  const fixture: TrialFixture = {
    context,
    active: await captureActivePairOperationCandidate(pair, fullState),
    pair,
    localEvidence,
    remoteEvidence,
    localEvidenceFromDifferentCore,
    remoteEvidenceFromDifferentCore,
    evidenceView,
    evidenceViewFromDifferentCore,
    local,
    remote,
    custody,
    roomRoot,
  };
  fixtures.add(fixture);
  return fixture;
};

const createTrial = (
  fixture: TrialFixture,
  overrides: Partial<
    Parameters<typeof createExpectedIdentityHelloTrialV1>[0]
  > = {},
): ExpectedIdentityHelloTrialV1 =>
  createExpectedIdentityHelloTrialV1({
    activeCandidate: fixture.active,
    receiverCustody: fixture.custody,
    historicalEvidenceView: fixture.evidenceView,
    trialOrdinal: 3,
    ...overrides,
  });

const reserveTrial = async (
  candidate: ActivePairOperationCandidateV1,
  trial: ExpectedIdentityHelloTrialV1,
): Promise<ReservedIdentityHelloOpenV1> => {
  const port: PairOpenReservationStorePortV1 = {
    readExactBudgetRow: async () => ({ kind: "absent" }),
    compareAndSwap: async (request) => {
      if (request.budgetMutation.kind !== "replace")
        throw new Error("test expected the first reservation to replace");
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

describe("identity HELLO receiver custody and expected trial", () => {
  test("derives stable identity custody from owned secret bytes and rejects structural forgeries", async () => {
    const keyPair = await newKeyPair(module);
    const callerSecret = Uint8Array.from(keyPair.secretKey);
    const expectedPublic = Uint8Array.from(keyPair.publicKey);
    const pending = createLocalStableIdentityCustodyV1({
      module,
      stableEd25519SecretKey: callerSecret,
      localIdentityKeyRecordRevision: LOCAL_IDENTITY_KEY_RECORD_REVISION,
    });
    callerSecret.fill(0xff);
    keyPair.secretKey.fill(0);

    const custody = await pending;
    stableCustodies.add(custody);
    const snapshot = snapshotLocalStableIdentityCustodyV1(custody);
    expect(snapshot).toMatchObject({
      version: 1,
      localIdentityKeyRecordRevision: LOCAL_IDENTITY_KEY_RECORD_REVISION,
    });
    expectBytesEqual(snapshot.localStableEd25519PublicKey, expectedPublic);
    snapshot.localStableEd25519PublicKey.fill(0);
    expectBytesEqual(
      snapshotLocalStableIdentityCustodyV1(custody).localStableEd25519PublicKey,
      expectedPublic,
    );

    const spread = { ...custody } as LocalStableIdentityCustodyV1;
    const cloned = structuredClone(custody) as LocalStableIdentityCustodyV1;
    expect(() => snapshotLocalStableIdentityCustodyV1(spread)).toThrow(
      "genuine live process-local handle",
    );
    expect(() => snapshotLocalStableIdentityCustodyV1(cloned)).toThrow(
      "genuine live process-local handle",
    );
    await expect(
      createLocalStableIdentityCustodyV1({
        module,
        stableEd25519SecretKey: new Uint8Array(63),
        localIdentityKeyRecordRevision: 1n,
      }),
    ).rejects.toThrow();
    const inconsistentSecret = await newKeyPair(module);
    inconsistentSecret.secretKey[63] ^= 1;
    await expect(
      createLocalStableIdentityCustodyV1({
        module,
        stableEd25519SecretKey: inconsistentSecret.secretKey,
        localIdentityKeyRecordRevision: 1n,
      }),
    ).rejects.toThrow("inconsistent public suffix");
    inconsistentSecret.secretKey.fill(0);
    await expect(
      createLocalStableIdentityCustodyV1({
        module,
        stableEd25519SecretKey: new Uint8Array(64),
        localIdentityKeyRecordRevision: 0x10000000000000000n,
      }),
    ).rejects.toThrow("unsigned 64-bit");

    destroyLocalStableIdentityCustodyV1(custody);
    destroyLocalStableIdentityCustodyV1(custody);
    expect(() => snapshotLocalStableIdentityCustodyV1(custody)).toThrow(
      "genuine live process-local handle",
    );
    expectedPublic.fill(0);
  });

  test("captures one verified custody and creates a cryptography-free, provenance-bound trial", async () => {
    const fixture = await buildFixture();
    const moduleExports =
      await import("../../src/blindRendezvous/identityHelloTrial");
    expect(
      "consumeExpectedIdentityHelloTrialForPairOpenV1" in moduleExports,
    ).toBe(false);
    const originalSeed = Uint8Array.from(fixture.local.receiverSecretSeed);
    const originalRoomRoot = Uint8Array.from(fixture.roomRoot);
    const evidence = [fixture.localEvidence, fixture.remoteEvidence];
    const pendingEvidenceView = createHistoricalIdentityHelloEvidenceViewV1({
      historicalPresenceEvidence: evidence,
    });
    evidence.splice(0, evidence.length, fixture.remoteEvidence);
    const evidenceView = await pendingEvidenceView;
    extraEvidenceViews.add(evidenceView);
    const trial = createTrial(fixture, {
      historicalEvidenceView: evidenceView,
    });

    const custodySnapshot = snapshotLocalHelloReceiverCustodyV1(
      fixture.custody,
    );
    const evidenceViewSnapshot =
      snapshotHistoricalIdentityHelloEvidenceViewV1(evidenceView);
    const snapshot = snapshotExpectedIdentityHelloTrialV1(trial);
    expect(snapshot.version).toBe(1);
    expect(snapshot.activeCandidate.operation.kind).toBe("PAIR_STEP");
    expect(snapshot.activeCandidate.envelope.bootstrapHeader).not.toBeNull();
    expect(snapshot.helloLogicalWindow).toBe(HELLO_WINDOW);
    expect(snapshot.historicalEvidenceView.presenceOperationIds).toHaveLength(
      2,
    );
    expect(evidenceViewSnapshot.presenceOperationIds).toHaveLength(2);
    expect(evidenceViewSnapshot.helloLogicalWindow).toBe(HELLO_WINDOW);
    expect(snapshot.trialOrdinal).toBe(3);
    expect(snapshot.receiverKeyRecordRevision).toBe(
      RECEIVER_KEY_RECORD_REVISION,
    );
    expect(snapshot.localIdentityKeyRecordRevision).toBe(
      LOCAL_IDENTITY_KEY_RECORD_REVISION,
    );
    expect(custodySnapshot.localIdentityKeyRecordRevision).toBe(
      LOCAL_IDENTITY_KEY_RECORD_REVISION,
    );
    expectBytesEqual(snapshot.activeOperationId, fixture.pair.operationId);
    expectBytesEqual(
      snapshot.localPresenceOperationId,
      fixture.local.identified.operationId,
    );
    expectBytesEqual(
      snapshot.advertisedReceiverHybridKemPublicKey,
      fixture.local.receiverPublicKey,
    );
    expectBytesEqual(
      custodySnapshot.advertisedReceiverHybridKemPublicKey,
      fixture.local.receiverPublicKey,
    );
    expect(containsSecretField(custodySnapshot)).toBe(false);
    expect(containsSecretField(snapshot)).toBe(false);
    expectBytesEqual(fixture.local.receiverSecretSeed, originalSeed);
    expectBytesEqual(fixture.roomRoot, originalRoomRoot);

    expect(() =>
      assertExpectedIdentityHelloTrialCandidateBindingV1(trial, fixture.active),
    ).not.toThrow();
    expect(() =>
      assertExpectedIdentityHelloTrialBindingsV1(
        trial,
        fixture.active,
        fixture.custody,
      ),
    ).not.toThrow();
    expect(() =>
      assertExpectedIdentityHelloTrialCandidateBindingV1(
        trial,
        {} as ActivePairOperationCandidateV1,
      ),
    ).toThrow("another active candidate capability");
    expect(() =>
      assertExpectedIdentityHelloTrialBindingsV1(
        trial,
        fixture.active,
        {} as LocalHelloReceiverCustodyV1,
      ),
    ).toThrow("another receiver custody capability");

    snapshot.advertisedReceiverHybridKemPublicKey.fill(0);
    snapshot.receiverCustody.localStableEd25519PublicKey.fill(0);
    snapshot.roomPolicy.sessionPolicyV1.fill(0);
    snapshot.localPresenceEvidence.exactPresenceOperationBytes.fill(0);
    snapshot.historicalEvidenceView.exactCoreStateBytes.fill(0);
    custodySnapshot.exactPresenceOperationBytes.fill(0);
    const fresh = snapshotExpectedIdentityHelloTrialV1(trial);
    const freshCustody = snapshotLocalHelloReceiverCustodyV1(fixture.custody);
    expectBytesEqual(
      fresh.advertisedReceiverHybridKemPublicKey,
      fixture.local.receiverPublicKey,
    );
    expectBytesEqual(
      fresh.receiverCustody.localStableEd25519PublicKey,
      fixture.local.stablePublicKey,
    );
    expect(fresh.roomPolicy.sessionPolicyV1.some((byte) => byte !== 0)).toBe(
      true,
    );
    expect(
      fresh.localPresenceEvidence.exactPresenceOperationBytes.some(
        (byte) => byte !== 0,
      ),
    ).toBe(true);
    expect(
      fresh.historicalEvidenceView.exactCoreStateBytes.some(
        (byte) => byte !== 0,
      ),
    ).toBe(true);
    expect(
      freshCustody.exactPresenceOperationBytes.some((byte) => byte !== 0),
    ).toBe(true);

    destroyExpectedIdentityHelloTrialV1(trial);
    destroyExpectedIdentityHelloTrialV1(trial);
    expect(() => snapshotExpectedIdentityHelloTrialV1(trial)).toThrow(
      "genuine live process-local capability",
    );
  });

  test("custody snapshots mutable inputs before await and remains reusable across one-use trials", async () => {
    const fixture = await buildFixture();
    const seed = Uint8Array.from(fixture.local.receiverSecretSeed);
    const roomRoot = Uint8Array.from(fixture.roomRoot);
    const expectedSeed = Uint8Array.from(seed);
    const expectedRoomRoot = Uint8Array.from(roomRoot);
    const stableCustody = await createStableCustody(fixture.local, 8n);
    const pending = createLocalHelloReceiverCustodyV1({
      module,
      localPresenceEvidence: fixture.localEvidence,
      recipientHybridKemSecretSeed: seed,
      roomRoot,
      localStableIdentityCustody: stableCustody,
      receiverKeyRecordRevision: 10n,
    });
    seed.fill(0xff);
    roomRoot.fill(0xee);
    const custody = await pending;
    extraCustodies.add(custody);

    const firstTrial = createTrial(fixture, { receiverCustody: custody });
    expect(() =>
      consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
        {} as ReservedIdentityHelloOpenV1,
        firstTrial,
      ),
    ).toThrow("genuine unused reservation");
    const firstReservation = await reserveTrial(fixture.active, firstTrial);
    const wrongTrial = createTrial(fixture, {
      receiverCustody: custody,
      trialOrdinal: 4,
    });
    expect(() =>
      consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
        firstReservation,
        wrongTrial,
      ),
    ).toThrow("another trial");
    expect(() =>
      snapshotExpectedIdentityHelloTrialV1(wrongTrial),
    ).not.toThrow();
    const first = consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
      firstReservation,
      firstTrial,
    );
    expectBytesEqual(first.recipientHybridKemSecretSeed, expectedSeed);
    expectBytesEqual(first.roomRoot, expectedRoomRoot);
    expect(
      first.resolveHistoricalPresenceEvidence(
        fixture.local.identified.operationId,
      ),
    ).toBe(fixture.localEvidence);
    expect(
      first.resolveHistoricalPresenceEvidence(
        fixture.remote.identified.operationId,
      ),
    ).toBe(fixture.remoteEvidence);
    expect(
      first.resolveHistoricalPresenceEvidence(new Uint8Array(32).fill(0xff)),
    ).toBeNull();
    expect(() =>
      consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
        firstReservation,
        firstTrial,
      ),
    ).toThrow("genuine live process-local capability");
    first.recipientHybridKemSecretSeed.fill(0);
    first.roomRoot.fill(0);
    expect(() =>
      consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
        firstReservation,
        wrongTrial,
      ),
    ).toThrow("genuine unused reservation");
    destroyExpectedIdentityHelloTrialV1(wrongTrial);

    const secondTrial = createTrial(fixture, { receiverCustody: custody });
    const secondReservation = await reserveTrial(fixture.active, secondTrial);
    const second = consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
      secondReservation,
      secondTrial,
    );
    expectBytesEqual(second.recipientHybridKemSecretSeed, expectedSeed);
    expectBytesEqual(second.roomRoot, expectedRoomRoot);
    second.recipientHybridKemSecretSeed.fill(0);
    second.roomRoot.fill(0);
    expectedSeed.fill(0);
    expectedRoomRoot.fill(0);
  });

  test("keeps the current active Core fence separate from the exact historical HELLO proof fence", async () => {
    const fixture = await buildFixture();
    const laterContext = operationValidationContextAt(
      fixture.context,
      HELLO_WINDOW + 2n,
    );
    const leave = await buildLeaveCandidate(
      laterContext,
      fixture.remote.identified.operationId,
      fixture.remote.authorPublicKey,
      fixture.remote.authorSecretKey,
      HELLO_WINDOW + 1n,
    );
    const laterState = await coreReduce(
      [
        fixture.local.identified,
        fixture.remote.identified,
        fixture.pair,
        leave,
      ],
      laterContext,
      module,
    );
    expect(laterState.effectiveLeaveOperationIds).toHaveLength(1);
    expect(
      laterState.observedPresences.some((presence) =>
        Buffer.from(presence.presenceOperationId).equals(
          Buffer.from(fixture.remote.identified.operationId),
        ),
      ),
    ).toBe(false);
    expect(
      laterState.activePairOuterOperationIds.some((operationId) =>
        Buffer.from(operationId).equals(Buffer.from(fixture.pair.operationId)),
      ),
    ).toBe(true);
    const laterActive = await captureActivePairOperationCandidate(
      fixture.pair,
      laterState,
    );
    const trial = createTrial(fixture, { activeCandidate: laterActive });
    const snapshot = snapshotExpectedIdentityHelloTrialV1(trial);
    expect(snapshot.helloLogicalWindow).toBe(HELLO_WINDOW);
    expect(snapshot.activeCandidate.referenceWindow).toBe(HELLO_WINDOW + 2n);
    expect(snapshot.localPresenceEvidence.provedAtLogicalWindow).toBe(
      HELLO_WINDOW,
    );
    expectBytesEqual(
      snapshot.exactEvidenceCoreStateBytes,
      snapshot.localPresenceEvidence.exactCoreStateBytes,
    );
    expect(snapshot.exactEvidenceCoreStateBytes).not.toEqual(
      snapshot.exactCoreStateBytes,
    );

    const casRequests: Array<
      Parameters<PairOpenReservationStorePortV1["compareAndSwap"]>[0]
    > = [];
    const service = createPairOpenReservationServiceV1(
      {
        readExactBudgetRow: async () => ({ kind: "absent" }),
        compareAndSwap: async (request) => {
          casRequests.push(request);
          if (request.budgetMutation.kind !== "replace")
            throw new Error("test expected a replacement budget row");
          return {
            status: "committed",
            exactBudgetRowBytes: Uint8Array.from(
              request.budgetMutation.exactNextBytes,
            ),
          };
        },
      },
      {
        maxPairOpenTrialsPerPresenceWindow: 8,
        maxPairOpenBytesPerPresenceWindow: Number.MAX_SAFE_INTEGER,
      },
    );
    const reservation = await service.reserveIdentityHelloOpen(
      laterActive,
      trial,
    );
    if (reservation.kind !== "reserved")
      throw new Error("test expected the delayed HELLO trial to reserve");
    const casRequest = casRequests[0];
    if (casRequest === undefined)
      throw new Error("test expected one CAS request");
    expectBytesEqual(
      casRequest.expectedExactCoreStateBytes,
      snapshot.exactCoreStateBytes,
    );
    expectBytesEqual(
      casRequest.expectedExactEvidenceCoreStateBytes,
      snapshot.exactEvidenceCoreStateBytes,
    );
    expect(casRequest.expectedExactEvidenceCoreStateBytes).not.toEqual(
      casRequest.expectedExactCoreStateBytes,
    );
    const consumed = consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
      reservation.capability,
      trial,
    );
    consumed.recipientHybridKemSecretSeed.fill(0);
    consumed.roomRoot.fill(0);
    destroyExpectedIdentityHelloTrialV1(trial);
  });

  test("rejects fake provenance, established framing, missing local custody, duplicates, and mixed historical Core snapshots", async () => {
    const fixture = await buildFixture();
    expect(() =>
      createTrial(fixture, {
        activeCandidate: {} as ActivePairOperationCandidateV1,
      }),
    ).toThrow();
    expect(() =>
      createTrial(fixture, {
        receiverCustody: {} as LocalHelloReceiverCustodyV1,
      }),
    ).toThrow("genuine live process-local handle");
    expect(() =>
      createTrial(fixture, {
        historicalEvidenceView: {} as HistoricalIdentityHelloEvidenceViewV1,
      }),
    ).toThrow("genuine live process-local handle");

    const established = await buildFixture(false);
    expect(() => createTrial(established)).toThrow(
      "class-0 bootstrap PAIR_STEP",
    );

    const remoteOnlyState = await coreReduce(
      [fixture.remote.identified],
      fixture.context,
      module,
    );
    const remoteOnlyEvidence = await captureHistoricalPairPresenceEvidence(
      fixture.remote.identified,
      remoteOnlyState,
      HELLO_WINDOW,
    );
    const remoteOnlyView = await createHistoricalIdentityHelloEvidenceViewV1({
      historicalPresenceEvidence: [remoteOnlyEvidence],
    });
    extraEvidenceViews.add(remoteOnlyView);
    expect(() =>
      createTrial(fixture, {
        historicalEvidenceView: remoteOnlyView,
      }),
    ).toThrow("does not include the custody presence");

    const localOnlyView = await createHistoricalIdentityHelloEvidenceViewV1({
      historicalPresenceEvidence: [fixture.localEvidence],
    });
    extraEvidenceViews.add(localOnlyView);
    const localOnlyTrial = createTrial(fixture, {
      historicalEvidenceView: localOnlyView,
    });
    expect(
      snapshotExpectedIdentityHelloTrialV1(localOnlyTrial)
        .historicalEvidenceView.presenceOperationIds,
    ).toHaveLength(1);
    destroyExpectedIdentityHelloTrialV1(localOnlyTrial);
    await expect(
      createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: [
          fixture.localEvidence,
          fixture.localEvidence,
        ],
      }),
    ).rejects.toThrow("IDs must be unique");
    await expect(
      createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: [
          fixture.localEvidenceFromDifferentCore,
          fixture.remoteEvidence,
        ],
      }),
    ).rejects.toThrow("exact same Core snapshot");

    const coherentHistoricalView = createTrial(fixture, {
      historicalEvidenceView: fixture.evidenceViewFromDifferentCore,
    });
    const coherentSnapshot = snapshotExpectedIdentityHelloTrialV1(
      coherentHistoricalView,
    );
    expect(coherentSnapshot.exactEvidenceCoreStateBytes).not.toEqual(
      coherentSnapshot.exactCoreStateBytes,
    );
    destroyExpectedIdentityHelloTrialV1(coherentHistoricalView);

    const otherRoom = await buildFixture(true, new Uint8Array(32).fill(0x54));
    expect(() =>
      createTrial(fixture, { receiverCustody: otherRoom.custody }),
    ).toThrow("another room or policy");
  });

  test("accepts a bounded selected evidence view from an overcapacity Core", async () => {
    const overcapacityPolicy = {
      ...copyPolicy(),
      maxRoomMembers: 2,
    };
    const context = await createOperationValidationContext(
      new Uint8Array(32).fill(0x55),
      overcapacityPolicy,
      HELLO_WINDOW,
    );
    const local = await buildPresence(context, 0x31, true);
    const selectedRemote = await buildPresence(context, 0x32, false);
    const excessRemote = await buildPresence(context, 0x33, false);
    const pair = await buildPairCandidate(context, true);
    const roomRoot = new Uint8Array(PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes).fill(
      0x62,
    );
    let trial: ExpectedIdentityHelloTrialV1 | undefined;
    try {
      const state = await coreReduce(
        [
          local.identified,
          selectedRemote.identified,
          excessRemote.identified,
          pair,
        ],
        context,
        module,
      );
      expect(state.roomCapacityState).toBe("overcapacity");
      expect(state.observedPresences).toHaveLength(3);

      const localEvidence = await captureHistoricalPairPresenceEvidence(
        local.identified,
        state,
        HELLO_WINDOW,
      );
      const selectedRemoteEvidence =
        await captureHistoricalPairPresenceEvidence(
          selectedRemote.identified,
          state,
          HELLO_WINDOW,
        );
      const evidenceView = await createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: [localEvidence, selectedRemoteEvidence],
      });
      extraEvidenceViews.add(evidenceView);
      const custody = await createLocalHelloReceiverCustodyV1({
        module,
        localPresenceEvidence: localEvidence,
        recipientHybridKemSecretSeed: local.receiverSecretSeed,
        roomRoot,
        localStableIdentityCustody: await createStableCustody(local),
        receiverKeyRecordRevision: RECEIVER_KEY_RECORD_REVISION,
      });
      extraCustodies.add(custody);
      trial = createExpectedIdentityHelloTrialV1({
        activeCandidate: await captureActivePairOperationCandidate(pair, state),
        receiverCustody: custody,
        historicalEvidenceView: evidenceView,
        trialOrdinal: 0,
      });
      const snapshot = snapshotExpectedIdentityHelloTrialV1(trial);
      expect(snapshot.historicalEvidenceView.presenceOperationIds).toHaveLength(
        2,
      );
      expect(
        snapshot.historicalEvidenceView.presenceOperationIds.some(
          (operationId) =>
            Buffer.from(operationId).equals(
              Buffer.from(excessRemote.identified.operationId),
            ),
        ),
      ).toBe(false);
    } finally {
      if (trial !== undefined) destroyExpectedIdentityHelloTrialV1(trial);
      for (const presence of [local, selectedRemote, excessRemote]) {
        presence.receiverSecretSeed.fill(0);
        presence.authorSecretKey.fill(0);
      }
      roomRoot.fill(0);
    }
  });

  test("rejects sparse, accessor-backed, non-plain, oversized evidence views and invalid trial scalars", async () => {
    const fixture = await buildFixture();
    expect(() => createTrial(fixture, { trialOrdinal: -1 })).toThrow(
      "unsigned 32-bit",
    );
    await expect(
      createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: Array.from(
          { length: policy.maxRoomMembers + 1 },
          () => fixture.localEvidence,
        ),
      }),
    ).rejects.toThrow("bounded projected-view limit");

    const sparse = new Array<VerifiedHistoricalPairPresenceEvidenceV1>(2);
    sparse[1] = fixture.remoteEvidence;
    await expect(
      createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: sparse,
      }),
    ).rejects.toThrow("dense own data elements");

    let accessorReads = 0;
    const accessorBacked = [fixture.localEvidence, fixture.remoteEvidence];
    Object.defineProperty(accessorBacked, "0", {
      configurable: true,
      enumerable: true,
      get: () => {
        accessorReads++;
        return fixture.localEvidence;
      },
    });
    await expect(
      createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: accessorBacked,
      }),
    ).rejects.toThrow("dense own data elements");
    expect(accessorReads).toBe(0);

    const nonPlain = [fixture.localEvidence, fixture.remoteEvidence];
    Object.setPrototypeOf(nonPlain, null);
    await expect(
      createHistoricalIdentityHelloEvidenceViewV1({
        historicalPresenceEvidence: nonPlain,
      }),
    ).rejects.toThrow("plain bounded readonly array");
  });

  test("rejects unverified custody ownership, mismatched receiver material, and malformed trusted-record fields", async () => {
    const fixture = await buildFixture();
    const originalSeed = Uint8Array.from(fixture.local.receiverSecretSeed);
    const originalRoomRoot = Uint8Array.from(fixture.roomRoot);
    const wrongStable = await newKeyPair(module);
    const wrongStableCustody = await createLocalStableIdentityCustodyV1({
      module,
      stableEd25519SecretKey: wrongStable.secretKey,
      localIdentityKeyRecordRevision: 10n,
    });
    stableCustodies.add(wrongStableCustody);
    const localStableCustody = await createStableCustody(fixture.local, 10n);
    const remoteStableCustody = await createStableCustody(fixture.remote, 10n);
    try {
      await expect(
        createLocalHelloReceiverCustodyV1({
          module,
          localPresenceEvidence: fixture.localEvidence,
          recipientHybridKemSecretSeed: fixture.local.receiverSecretSeed,
          roomRoot: fixture.roomRoot,
          localStableIdentityCustody: wrongStableCustody,
          receiverKeyRecordRevision: 10n,
        }),
      ).rejects.toThrow("stable key does not match the presence commitment");
    } finally {
      wrongStable.secretKey.fill(0);
    }

    const wrongReceiver = await generateHpkeRecipientKeyPair(module);
    try {
      await expect(
        createLocalHelloReceiverCustodyV1({
          module,
          localPresenceEvidence: fixture.localEvidence,
          recipientHybridKemSecretSeed: wrongReceiver.secretKey,
          roomRoot: fixture.roomRoot,
          localStableIdentityCustody: localStableCustody,
          receiverKeyRecordRevision: 10n,
        }),
      ).rejects.toThrow("does not match the local presence");
    } finally {
      wrongReceiver.destroy();
    }

    await expect(
      createLocalHelloReceiverCustodyV1({
        module,
        localPresenceEvidence: fixture.remoteEvidence,
        recipientHybridKemSecretSeed: fixture.remote.receiverSecretSeed,
        roomRoot: fixture.roomRoot,
        localStableIdentityCustody: remoteStableCustody,
        receiverKeyRecordRevision: 10n,
      }),
    ).rejects.toThrow("stable presence ownership signature does not verify");

    await expect(
      createLocalHelloReceiverCustodyV1({
        module,
        localPresenceEvidence: fixture.localEvidence,
        recipientHybridKemSecretSeed: fixture.local.receiverSecretSeed,
        roomRoot: new Uint8Array(PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes - 1),
        localStableIdentityCustody: localStableCustody,
        receiverKeyRecordRevision: 10n,
      }),
    ).rejects.toThrow();
    await expect(
      createLocalHelloReceiverCustodyV1({
        module,
        localPresenceEvidence: fixture.localEvidence,
        recipientHybridKemSecretSeed: fixture.local.receiverSecretSeed,
        roomRoot: fixture.roomRoot,
        localStableIdentityCustody: localStableCustody,
        receiverKeyRecordRevision: 0x10000000000000000n,
      }),
    ).rejects.toThrow("unsigned 64-bit");
    await expect(
      createLocalHelloReceiverCustodyV1({
        module,
        localPresenceEvidence: {} as VerifiedHistoricalPairPresenceEvidenceV1,
        recipientHybridKemSecretSeed: fixture.local.receiverSecretSeed,
        roomRoot: fixture.roomRoot,
        localStableIdentityCustody: localStableCustody,
        receiverKeyRecordRevision: 10n,
      }),
    ).rejects.toThrow();

    expectBytesEqual(fixture.local.receiverSecretSeed, originalSeed);
    expectBytesEqual(fixture.roomRoot, originalRoomRoot);
    originalSeed.fill(0);
    originalRoomRoot.fill(0);
  });

  test("opaque handles resist cloning, and custody destruction fails dependent trials closed", async () => {
    const fixture = await buildFixture();
    const trial = createTrial(fixture);
    const siblingTrial = createTrial(fixture, { trialOrdinal: 4 });
    const reservation = await reserveTrial(fixture.active, trial);
    const spreadTrial = { ...trial } as ExpectedIdentityHelloTrialV1;
    const clonedTrial = structuredClone(trial) as ExpectedIdentityHelloTrialV1;
    const spreadCustody = {
      ...fixture.custody,
    } as LocalHelloReceiverCustodyV1;
    const clonedCustody = structuredClone(
      fixture.custody,
    ) as LocalHelloReceiverCustodyV1;
    const spreadEvidenceView = {
      ...fixture.evidenceView,
    } as HistoricalIdentityHelloEvidenceViewV1;
    const clonedEvidenceView = structuredClone(
      fixture.evidenceView,
    ) as HistoricalIdentityHelloEvidenceViewV1;
    expect(() => snapshotExpectedIdentityHelloTrialV1(spreadTrial)).toThrow(
      "genuine live process-local capability",
    );
    expect(() => snapshotExpectedIdentityHelloTrialV1(clonedTrial)).toThrow(
      "genuine live process-local capability",
    );
    expect(() => snapshotLocalHelloReceiverCustodyV1(spreadCustody)).toThrow(
      "genuine live process-local handle",
    );
    expect(() => snapshotLocalHelloReceiverCustodyV1(clonedCustody)).toThrow(
      "genuine live process-local handle",
    );
    expect(() =>
      snapshotHistoricalIdentityHelloEvidenceViewV1(spreadEvidenceView),
    ).toThrow("genuine live process-local handle");
    expect(() =>
      snapshotHistoricalIdentityHelloEvidenceViewV1(clonedEvidenceView),
    ).toThrow("genuine live process-local handle");

    destroyLocalHelloReceiverCustodyV1(fixture.custody);
    destroyLocalHelloReceiverCustodyV1(fixture.custody);
    expect(() => snapshotLocalHelloReceiverCustodyV1(fixture.custody)).toThrow(
      "genuine live process-local handle",
    );
    expect(() => snapshotExpectedIdentityHelloTrialV1(trial)).toThrow(
      "genuine live process-local handle",
    );
    expect(() =>
      consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
        reservation,
        trial,
      ),
    ).toThrow("genuine live process-local handle");
    expect(() =>
      consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
        reservation,
        siblingTrial,
      ),
    ).toThrow("genuine unused reservation");
    destroyExpectedIdentityHelloTrialV1(trial);
    destroyExpectedIdentityHelloTrialV1(siblingTrial);
  });

  test("historical evidence-view retirement fails dependent trials and post-budget lookups closed", async () => {
    const fixture = await buildFixture();
    const trial = createTrial(fixture);
    const siblingTrial = createTrial(fixture, { trialOrdinal: 4 });
    const reservation = await reserveTrial(fixture.active, trial);
    const consumed = consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
      reservation,
      trial,
    );

    destroyHistoricalIdentityHelloEvidenceViewV1(fixture.evidenceView);
    destroyHistoricalIdentityHelloEvidenceViewV1(fixture.evidenceView);
    expect(() =>
      snapshotHistoricalIdentityHelloEvidenceViewV1(fixture.evidenceView),
    ).toThrow("genuine live process-local handle");
    expect(() => snapshotExpectedIdentityHelloTrialV1(siblingTrial)).toThrow(
      "genuine live process-local handle",
    );
    expect(() =>
      consumed.resolveHistoricalPresenceEvidence(
        fixture.remote.identified.operationId,
      ),
    ).toThrow("genuine live process-local handle");

    consumed.recipientHybridKemSecretSeed.fill(0);
    consumed.roomRoot.fill(0);
    destroyExpectedIdentityHelloTrialV1(siblingTrial);
  });

  test("destroying stable identity custody fails receiver liveness but not receiver cleanup", async () => {
    const fixture = await buildFixture();
    const stableCustody = await createStableCustody(fixture.local, 12n);
    const receiverCustody = await createLocalHelloReceiverCustodyV1({
      module,
      localPresenceEvidence: fixture.localEvidence,
      recipientHybridKemSecretSeed: fixture.local.receiverSecretSeed,
      roomRoot: fixture.roomRoot,
      localStableIdentityCustody: stableCustody,
      receiverKeyRecordRevision: 13n,
    });
    extraCustodies.add(receiverCustody);
    const trial = createTrial(fixture, {
      receiverCustody,
      trialOrdinal: 9,
    });

    destroyLocalStableIdentityCustodyV1(stableCustody);
    destroyLocalStableIdentityCustodyV1(stableCustody);
    expect(() => snapshotLocalHelloReceiverCustodyV1(receiverCustody)).toThrow(
      "genuine live process-local handle",
    );
    expect(() => snapshotExpectedIdentityHelloTrialV1(trial)).toThrow(
      "genuine live process-local handle",
    );
    expect(() =>
      destroyLocalHelloReceiverCustodyV1(receiverCustody),
    ).not.toThrow();
    expect(() =>
      destroyLocalHelloReceiverCustodyV1(receiverCustody),
    ).not.toThrow();
    destroyExpectedIdentityHelloTrialV1(trial);
  });
});
