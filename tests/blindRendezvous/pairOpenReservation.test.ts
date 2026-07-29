import { afterAll, describe, expect, test } from "bun:test";

import { bytesEqual } from "../../src/blindRendezvous/canonicalSchema";
import {
  captureActivePairOperationCandidate,
  captureHistoricalPairPresenceEvidence,
  coreReduce,
  snapshotActivePairOperationCandidate,
  validateAndIdentifyOperationCandidate,
} from "../../src/blindRendezvous/coreReduce";
import {
  localRoomId,
  pairSemanticSlot,
  policyHash,
  presenceOwnershipSignedMessage,
  presenceProofTranscriptHash,
  presenceSemanticSlot,
  stableIdentityCommitment,
} from "../../src/blindRendezvous/derivations";
import {
  consumeReservedExpectedIdentityHelloTrialForPairOpenV1,
  createExpectedIdentityHelloTrialV1,
  createHistoricalIdentityHelloEvidenceViewV1,
  createLocalHelloReceiverCustodyV1,
  destroyExpectedIdentityHelloTrialV1,
  destroyHistoricalIdentityHelloEvidenceViewV1,
  destroyLocalHelloReceiverCustodyV1,
} from "../../src/blindRendezvous/identityHelloTrial";
import {
  createOperationValidationContext,
  operationPaddingFor,
  signOperation,
} from "../../src/blindRendezvous/operation";
import { encodePresenceV1 } from "../../src/blindRendezvous/operationPayload";
import {
  decodePairOpenBudgetSnapshotV1,
  encodePairOpenBudgetSnapshotV1,
  reducePairOpenBudgetV1,
} from "../../src/blindRendezvous/pairOpenBudget";
import {
  consumeReservedIdentityHelloOpenV1,
  createPairOpenReservationServiceV1,
} from "../../src/blindRendezvous/pairOpenReservation";
import {
  encodePairStepEnvelopeV1,
  pairCiphertextAndTagTargetBytesV1,
} from "../../src/blindRendezvous/pairStepEnvelope";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";
import { newKeyPair, sign } from "../../src/cryptography/ed25519";
import { generateHpkeRecipientKeyPair } from "../../src/cryptography/hpke";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  createLocalStableIdentityCustodyV1,
  destroyLocalStableIdentityCustodyV1,
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
import type { PresenceCoreV1 } from "../../src/blindRendezvous/operationPayload";
import type {
  PairOpenBudgetLimitsV1,
  PairOpenBudgetSnapshotV1,
} from "../../src/blindRendezvous/pairOpenBudget";
import type {
  ExactPairOpenBudgetRowV1,
  PairOpenBudgetSubjectV1,
  PairOpenReservationCasRequestV1,
  PairOpenReservationCasResultV1,
  PairOpenReservationStorePortV1,
  ReservedIdentityHelloOpenV1,
} from "../../src/blindRendezvous/pairOpenReservation";
import type { LocalStableIdentityCustodyV1 } from "../../src/blindRendezvous/localStableIdentityCustody";

const cryptoModule = await loadTestModule();
const policy = DEFAULT_BLIND_POLICY_V4_0;
const ROOM_CAPABILITY = new Uint8Array(32).fill(0x59);
const ROOM_ROOT = new Uint8Array(32).fill(0x5a);
const HELLO_WINDOW = 1_000n;
const RECEIVER_KEY_REVISION = 9n;
const LOCAL_IDENTITY_KEY_REVISION = 7n;
const ENVELOPE_BYTES = 4_096;

const copyPolicy = () => ({
  ...policy,
  sessionPolicyV1: Uint8Array.from(policy.sessionPolicyV1),
  protocolLimits: { ...policy.protocolLimits },
  admissionFloor: { ...policy.admissionFloor },
});

const bytes = (value: number, length: number): Uint8Array =>
  new Uint8Array(length).fill(value);

const copySubject = (
  subject: PairOpenBudgetSubjectV1,
): PairOpenBudgetSubjectV1 => ({
  localRoomId: subject.localRoomId,
  localPresenceOperationId: Uint8Array.from(subject.localPresenceOperationId),
});

const sameSubject = (
  left: PairOpenBudgetSubjectV1,
  right: PairOpenBudgetSubjectV1,
): boolean =>
  left.localRoomId === right.localRoomId &&
  bytesEqual(left.localPresenceOperationId, right.localPresenceOperationId);

const copyExactRow = (
  row: ExactPairOpenBudgetRowV1,
): ExactPairOpenBudgetRowV1 =>
  row.kind === "absent"
    ? { kind: "absent" }
    : { kind: "present", exactBytes: Uint8Array.from(row.exactBytes) };

interface PresenceFixture {
  readonly operation: OuterValidatedIdentifiedOperationV1;
  readonly stablePublicKey: Uint8Array;
  readonly stableSecretKey: Uint8Array;
  readonly receiverSecretSeed: Uint8Array;
}

const buildPresence = async (
  context: OperationValidationContext,
): Promise<PresenceFixture> => {
  const stable = await newKeyPair(cryptoModule);
  const author = await newKeyPair(cryptoModule);
  const receiver = await generateHpkeRecipientKeyPair(cryptoModule);
  const validThrough = HELLO_WINDOW + 8n;
  const core: PresenceCoreV1 = {
    version: 1,
    stableIdentityCommitment: await stableIdentityCommitment(
      context.roomContextId,
      stable.publicKey,
    ),
    rendezvousHybridKemPublicKey: Uint8Array.from(receiver.publicKey),
    receiverKeyValidThroughLogicalWindow: validThrough,
    presenceNonce: bytes(0x21, 32),
    validThroughLogicalWindow: validThrough,
  };
  const proofHash = await presenceProofTranscriptHash({
    roomContextId: context.roomContextId,
    policyHash: await policyHash(context.roomPolicy),
    logicalWindow: HELLO_WINDOW,
    authorEpochEd25519Key: author.publicKey,
    core,
  });
  const payload = encodePresenceV1({
    core,
    stableOwnershipSignature: await sign(
      presenceOwnershipSignedMessage(proofHash),
      stable.secretKey,
      cryptoModule,
    ),
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
  const signed = await signOperation(unsigned, author.secretKey, cryptoModule);
  const operation = await validateAndIdentifyOperationCandidate(
    signed,
    context,
    cryptoModule,
  );
  const fixture = {
    operation,
    stablePublicKey: Uint8Array.from(stable.publicKey),
    stableSecretKey: Uint8Array.from(stable.secretKey),
    receiverSecretSeed: Uint8Array.from(receiver.secretKey),
  };
  stable.secretKey.fill(0);
  author.secretKey.fill(0);
  receiver.destroy();
  return fixture;
};

const buildPairCandidate = async (
  context: OperationValidationContext,
): Promise<OuterValidatedIdentifiedOperationV1> => {
  const author = await newKeyPair(cryptoModule);
  const routingTag = bytes(0x71, 32);
  const payload = encodePairStepEnvelopeV1(
    {
      version: 1,
      pairRoutingTag: routingTag,
      bootstrapHeader: {
        version: 1,
        suiteId: 1,
        hybridKemCiphertext: bytes(0x73, 1_120),
      },
      nonce: null,
      pairCiphertextAndTag: bytes(
        0x75,
        pairCiphertextAndTagTargetBytesV1(0, true),
      ),
    },
    0,
  );
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
  const signed = await signOperation(unsigned, author.secretKey, cryptoModule);
  author.secretKey.fill(0);
  return validateAndIdentifyOperationCandidate(signed, context, cryptoModule);
};

interface ReservationFixture {
  readonly candidate: ActivePairOperationCandidateV1;
  readonly custody: LocalHelloReceiverCustodyV1;
  readonly stableCustody: LocalStableIdentityCustodyV1;
  readonly evidenceView: HistoricalIdentityHelloEvidenceViewV1;
  readonly localEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly subject: PairOpenBudgetSubjectV1;
  readonly exactCoreStateBytes: Uint8Array;
  readonly exactEvidenceCoreStateBytes: Uint8Array;
  readonly receiverSecretSeed: Uint8Array;
  readonly stableSecretKey: Uint8Array;
}

const buildReservationFixture = async (): Promise<ReservationFixture> => {
  const context = await createOperationValidationContext(
    ROOM_CAPABILITY,
    copyPolicy(),
    HELLO_WINDOW,
  );
  const local = await buildPresence(context);
  const pair = await buildPairCandidate(context);
  const state = await coreReduce(
    [local.operation, pair],
    context,
    cryptoModule,
  );
  const candidate = await captureActivePairOperationCandidate(pair, state);
  const localEvidence = await captureHistoricalPairPresenceEvidence(
    local.operation,
    state,
    HELLO_WINDOW,
  );
  const evidenceView = await createHistoricalIdentityHelloEvidenceViewV1({
    historicalPresenceEvidence: [localEvidence],
  });
  const stableCustody = await createLocalStableIdentityCustodyV1({
    module: cryptoModule,
    stableEd25519SecretKey: local.stableSecretKey,
    localIdentityKeyRecordRevision: LOCAL_IDENTITY_KEY_REVISION,
  });
  const custody = await createLocalHelloReceiverCustodyV1({
    module: cryptoModule,
    localPresenceEvidence: localEvidence,
    recipientHybridKemSecretSeed: local.receiverSecretSeed,
    roomRoot: ROOM_ROOT,
    localStableIdentityCustody: stableCustody,
    receiverKeyRecordRevision: RECEIVER_KEY_REVISION,
  });
  const candidateSnapshot = snapshotActivePairOperationCandidate(candidate);
  return {
    candidate,
    custody,
    stableCustody,
    evidenceView,
    localEvidence,
    subject: {
      localRoomId: await localRoomId(context.roomContextId),
      localPresenceOperationId: Uint8Array.from(local.operation.operationId),
    },
    exactCoreStateBytes: Uint8Array.from(candidateSnapshot.exactCoreStateBytes),
    exactEvidenceCoreStateBytes: Uint8Array.from(
      candidateSnapshot.exactCoreStateBytes,
    ),
    receiverSecretSeed: local.receiverSecretSeed,
    stableSecretKey: local.stableSecretKey,
  };
};

const fixture = await buildReservationFixture();
const createdTrials: ExpectedIdentityHelloTrialV1[] = [];

const newTrial = (trialOrdinal = createdTrials.length) => {
  const trial = createExpectedIdentityHelloTrialV1({
    activeCandidate: fixture.candidate,
    receiverCustody: fixture.custody,
    historicalEvidenceView: fixture.evidenceView,
    trialOrdinal,
  });
  createdTrials.push(trial);
  return trial;
};

afterAll(() => {
  for (const trial of createdTrials) destroyExpectedIdentityHelloTrialV1(trial);
  destroyLocalHelloReceiverCustodyV1(fixture.custody);
  destroyLocalStableIdentityCustodyV1(fixture.stableCustody);
  destroyHistoricalIdentityHelloEvidenceViewV1(fixture.evidenceView);
  fixture.receiverSecretSeed.fill(0);
  fixture.stableSecretKey.fill(0);
});

const limits = (
  maxPairOpenTrialsPerPresenceWindow = 8,
  maxPairOpenBytesPerPresenceWindow = ENVELOPE_BYTES * 8,
): PairOpenBudgetLimitsV1 => ({
  maxPairOpenTrialsPerPresenceWindow,
  maxPairOpenBytesPerPresenceWindow,
});

const onePreparedBudget = (): Uint8Array => {
  const transition = reducePairOpenBudgetV1(
    null,
    {
      localRoomId: fixture.subject.localRoomId,
      localPresenceOperationId: fixture.subject.localPresenceOperationId,
      capturedReferenceWindow: HELLO_WINDOW,
      completeEnvelopeBytes: ENVELOPE_BYTES,
    },
    limits(),
  );
  if (transition.result !== "prepared")
    throw new Error("fixture expected one prepared budget row");
  return encodePairOpenBudgetSnapshotV1(transition.next);
};

class InMemoryPairOpenPort implements PairOpenReservationStorePortV1 {
  private coreBytes: Uint8Array;
  private evidenceCoreBytes: Uint8Array;
  private receiverRevision: bigint;
  private budgetBytes: Uint8Array | null;
  private readonly expectedSubject: PairOpenBudgetSubjectV1;
  private readonly pendingReads: Array<{
    readonly row: ExactPairOpenBudgetRowV1;
    readonly resolve: (row: ExactPairOpenBudgetRowV1) => void;
  }> = [];

  readonly mutations: Array<"keep" | "replace"> = [];
  readCount = 0;
  casCount = 0;
  readBarrierTarget = 0;
  corruptCommittedEcho = false;
  mutateBorrowedReadOnCas = false;
  mutateCasRequestAfterCommit = false;
  beforeNextCas: (() => void) | null = null;
  lastCasRequest: PairOpenReservationCasRequestV1 | null = null;
  private lastBorrowedRead: Uint8Array | null = null;

  constructor(
    options: {
      readonly coreBytes?: Uint8Array;
      readonly evidenceCoreBytes?: Uint8Array;
      readonly receiverRevision?: bigint;
      readonly budgetBytes?: Uint8Array | null;
    } = {},
  ) {
    this.coreBytes = Uint8Array.from(
      options.coreBytes ?? fixture.exactCoreStateBytes,
    );
    this.evidenceCoreBytes = Uint8Array.from(
      options.evidenceCoreBytes ?? fixture.exactEvidenceCoreStateBytes,
    );
    this.receiverRevision = options.receiverRevision ?? RECEIVER_KEY_REVISION;
    this.budgetBytes =
      options.budgetBytes === undefined || options.budgetBytes === null
        ? null
        : Uint8Array.from(options.budgetBytes);
    this.expectedSubject = copySubject(fixture.subject);
  }

  private currentBudgetRow(): ExactPairOpenBudgetRowV1 {
    if (this.budgetBytes === null) return { kind: "absent" };
    const borrowed = Uint8Array.from(this.budgetBytes);
    this.lastBorrowedRead = borrowed;
    return { kind: "present", exactBytes: borrowed };
  }

  readExactBudgetRow(
    subject: PairOpenBudgetSubjectV1,
  ): Promise<ExactPairOpenBudgetRowV1> {
    this.readCount++;
    if (!sameSubject(subject, this.expectedSubject))
      return Promise.reject(new Error("reservation derived the wrong subject"));
    const row = this.currentBudgetRow();
    if (this.readBarrierTarget < 2) return Promise.resolve(row);
    return new Promise((resolve) => {
      this.pendingReads.push({ row, resolve });
      if (this.pendingReads.length !== this.readBarrierTarget) return;
      const pending = this.pendingReads.splice(0);
      this.readBarrierTarget = 0;
      for (const item of pending) item.resolve(copyExactRow(item.row));
    });
  }

  compareAndSwap(
    request: PairOpenReservationCasRequestV1,
  ): Promise<PairOpenReservationCasResultV1> {
    this.casCount++;
    this.lastCasRequest = request;
    const beforeCas = this.beforeNextCas;
    this.beforeNextCas = null;
    beforeCas?.();
    if (this.mutateBorrowedReadOnCas) this.lastBorrowedRead?.fill(0xee);

    let result: PairOpenReservationCasResultV1;
    if (!sameSubject(request.subject, this.expectedSubject)) {
      throw new Error("reservation CAS used the wrong subject");
    } else if (
      !bytesEqual(request.expectedExactCoreStateBytes, this.coreBytes)
    ) {
      result = { status: "conflict", fence: "core" };
    } else if (
      !bytesEqual(
        request.expectedExactEvidenceCoreStateBytes,
        this.evidenceCoreBytes,
      )
    ) {
      result = { status: "conflict", fence: "historical-evidence" };
    } else if (
      request.expectedReceiverKeyRecordRevision !== this.receiverRevision
    ) {
      result = { status: "conflict", fence: "receiver-key" };
    } else if (!this.budgetMatches(request.expectedBudgetRow)) {
      result = { status: "conflict", fence: "budget" };
    } else {
      this.mutations.push(request.budgetMutation.kind);
      if (request.budgetMutation.kind === "replace")
        this.budgetBytes = Uint8Array.from(
          request.budgetMutation.exactNextBytes,
        );
      if (this.budgetBytes === null)
        throw new Error("committed reservation has no durable budget row");
      const echo = Uint8Array.from(this.budgetBytes);
      if (this.corruptCommittedEcho) echo[0] ^= 0x01;
      result = { status: "committed", exactBudgetRowBytes: echo };
    }

    if (this.mutateCasRequestAfterCommit) {
      request.subject.localPresenceOperationId.fill(0xa1);
      request.expectedExactCoreStateBytes.fill(0xa2);
      request.expectedExactEvidenceCoreStateBytes.fill(0xa5);
      if (request.expectedBudgetRow.kind === "present")
        request.expectedBudgetRow.exactBytes.fill(0xa3);
      if (request.budgetMutation.kind === "replace")
        request.budgetMutation.exactNextBytes.fill(0xa4);
    }
    return Promise.resolve(result);
  }

  private budgetMatches(expected: ExactPairOpenBudgetRowV1): boolean {
    if (expected.kind === "absent") return this.budgetBytes === null;
    return (
      this.budgetBytes !== null &&
      bytesEqual(expected.exactBytes, this.budgetBytes)
    );
  }

  corruptCore(): void {
    this.coreBytes[0] ^= 0x01;
  }

  corruptHistoricalEvidence(): void {
    this.evidenceCoreBytes[0] ^= 0x01;
  }

  changeReceiverRevision(): void {
    this.receiverRevision++;
  }

  replaceBudget(bytesValue: Uint8Array): void {
    this.budgetBytes = Uint8Array.from(bytesValue);
  }

  snapshotBudget(): PairOpenBudgetSnapshotV1 {
    if (this.budgetBytes === null)
      throw new Error("expected one durable budget row");
    return decodePairOpenBudgetSnapshotV1(this.budgetBytes);
  }
}

const reservedCapability = (
  value: Awaited<
    ReturnType<
      ReturnType<
        typeof createPairOpenReservationServiceV1
      >["reserveIdentityHelloOpen"]
    >
  >,
): ReservedIdentityHelloOpenV1 => {
  expect(value.kind).toBe("reserved");
  if (value.kind !== "reserved") throw new Error("expected reservation");
  return value.capability;
};

describe("effectful pair-open reservation", () => {
  test("derives every fence, commits exact bytes, and mints only after commit", async () => {
    const port = new InMemoryPairOpenPort();
    const service = createPairOpenReservationServiceV1(port, limits());
    const trial = newTrial();
    const result = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      trial,
    );
    const capability = reservedCapability(result);

    expect(port.readCount).toBe(1);
    expect(port.casCount).toBe(1);
    expect(port.mutations).toEqual(["replace"]);
    const request = port.lastCasRequest;
    if (request === null) throw new Error("expected one CAS request");
    expect(sameSubject(request.subject, fixture.subject)).toBe(true);
    expect(
      bytesEqual(
        request.expectedExactCoreStateBytes,
        fixture.exactCoreStateBytes,
      ),
    ).toBe(true);
    expect(
      bytesEqual(
        request.expectedExactEvidenceCoreStateBytes,
        fixture.exactEvidenceCoreStateBytes,
      ),
    ).toBe(true);
    expect(request.expectedReceiverKeyRecordRevision).toBe(
      RECEIVER_KEY_REVISION,
    );
    expect(request.expectedBudgetRow).toEqual({ kind: "absent" });
    expect(request.budgetMutation.kind).toBe("replace");
    expect(port.snapshotBudget()).toMatchObject({
      budgetRevision: 1n,
      reservedTrialCount: 1,
      reservedEnvelopeBytes: BigInt(ENVELOPE_BYTES),
      saturated: false,
    });

    expect(consumeReservedIdentityHelloOpenV1(capability, trial)).toBe(
      fixture.candidate,
    );
    expect(() => consumeReservedIdentityHelloOpenV1(capability, trial)).toThrow(
      "genuine unused reservation",
    );
  });

  test("classifies all four conflicts and never retries internally", async () => {
    const corePort = new InMemoryPairOpenPort();
    corePort.corruptCore();
    const coreResult = await createPairOpenReservationServiceV1(
      corePort,
      limits(),
    ).reserveIdentityHelloOpen(fixture.candidate, newTrial());
    expect(coreResult).toEqual({
      kind: "stale",
      reason: "core-changed",
    });
    expect([corePort.readCount, corePort.casCount]).toEqual([1, 1]);

    const evidencePort = new InMemoryPairOpenPort();
    evidencePort.corruptHistoricalEvidence();
    const evidenceResult = await createPairOpenReservationServiceV1(
      evidencePort,
      limits(),
    ).reserveIdentityHelloOpen(fixture.candidate, newTrial());
    expect(evidenceResult).toEqual({
      kind: "stale",
      reason: "historical-evidence-changed",
    });
    expect([evidencePort.readCount, evidencePort.casCount]).toEqual([1, 1]);

    const keyPort = new InMemoryPairOpenPort();
    keyPort.changeReceiverRevision();
    const keyResult = await createPairOpenReservationServiceV1(
      keyPort,
      limits(),
    ).reserveIdentityHelloOpen(fixture.candidate, newTrial());
    expect(keyResult).toEqual({
      kind: "stale",
      reason: "receiver-key-changed",
    });
    expect([keyPort.readCount, keyPort.casCount]).toEqual([1, 1]);

    const budgetPort = new InMemoryPairOpenPort();
    budgetPort.beforeNextCas = () =>
      budgetPort.replaceBudget(onePreparedBudget());
    const budgetResult = await createPairOpenReservationServiceV1(
      budgetPort,
      limits(),
    ).reserveIdentityHelloOpen(fixture.candidate, newTrial());
    expect(budgetResult).toEqual({
      kind: "retry",
      reason: "budget-conflict",
    });
    expect([budgetPort.readCount, budgetPort.casCount]).toEqual([1, 1]);
  });

  test("allows only one winner when concurrent reservations read the same prior row", async () => {
    const port = new InMemoryPairOpenPort();
    port.readBarrierTarget = 2;
    const service = createPairOpenReservationServiceV1(port, limits());
    const results = await Promise.all([
      service.reserveIdentityHelloOpen(fixture.candidate, newTrial()),
      service.reserveIdentityHelloOpen(fixture.candidate, newTrial()),
    ]);

    expect(results.filter(({ kind }) => kind === "reserved")).toHaveLength(1);
    expect(results.filter(({ kind }) => kind === "retry")).toEqual([
      { kind: "retry", reason: "budget-conflict" },
    ]);
    expect(port.readCount).toBe(2);
    expect(port.casCount).toBe(2);
    expect(port.mutations).toEqual(["replace"]);
    expect(port.snapshotBudget().reservedTrialCount).toBe(1);
  });

  test("persists first saturation and still fences an already sticky row", async () => {
    const port = new InMemoryPairOpenPort();
    const service = createPairOpenReservationServiceV1(
      port,
      limits(1, ENVELOPE_BYTES),
    );
    const first = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      newTrial(),
    );
    expect(first.kind).toBe("reserved");

    const saturation = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      newTrial(),
    );
    expect(saturation).toEqual({
      kind: "saturated",
      condition: "pair-control-DoS/stalled",
    });
    const sticky = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      newTrial(),
    );
    expect(sticky).toEqual({
      kind: "saturated",
      condition: "pair-control-DoS/stalled",
    });
    expect(port.mutations).toEqual(["replace", "replace", "keep"]);
    expect(port.snapshotBudget()).toMatchObject({
      budgetRevision: 2n,
      reservedTrialCount: 1,
      reservedEnvelopeBytes: BigInt(ENVELOPE_BYTES),
      saturated: true,
    });

    port.corruptCore();
    const staleSticky = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      newTrial(),
    );
    expect(staleSticky).toEqual({
      kind: "stale",
      reason: "core-changed",
    });
    expect(port.mutations).toEqual(["replace", "replace", "keep"]);
  });

  test("rejects a wrong committed-byte echo after storage writes and before mint", async () => {
    const port = new InMemoryPairOpenPort();
    port.corruptCommittedEcho = true;
    const service = createPairOpenReservationServiceV1(port, limits());
    await expect(
      service.reserveIdentityHelloOpen(fixture.candidate, newTrial()),
    ).rejects.toThrow(
      "committed budget-row echo does not equal the intended exact bytes",
    );
    expect(port.mutations).toEqual(["replace"]);
    expect(port.snapshotBudget().reservedTrialCount).toBe(1);
  });

  test("owns borrowed reads and CAS bytes across hostile adapter mutation", async () => {
    const initialBudget = onePreparedBudget();
    const port = new InMemoryPairOpenPort({ budgetBytes: initialBudget });
    port.mutateBorrowedReadOnCas = true;
    port.mutateCasRequestAfterCommit = true;
    const service = createPairOpenReservationServiceV1(port, limits());
    const trial = newTrial();
    const result = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      trial,
    );
    const capability = reservedCapability(result);

    expect(port.snapshotBudget()).toMatchObject({
      budgetRevision: 2n,
      reservedTrialCount: 2,
      reservedEnvelopeBytes: BigInt(ENVELOPE_BYTES * 2),
      saturated: false,
    });
    expect(consumeReservedIdentityHelloOpenV1(capability, trial)).toBe(
      fixture.candidate,
    );
  });

  test("rejects spread/clone/wrong-trial capabilities and gates secret transfer through the import cycle", async () => {
    const port = new InMemoryPairOpenPort();
    const service = createPairOpenReservationServiceV1(port, limits());
    const trial = newTrial();
    const result = await service.reserveIdentityHelloOpen(
      fixture.candidate,
      trial,
    );
    const capability = reservedCapability(result);
    const spread = { ...capability } as ReservedIdentityHelloOpenV1;
    const cloned = structuredClone(capability) as ReservedIdentityHelloOpenV1;

    expect(() => consumeReservedIdentityHelloOpenV1(spread, trial)).toThrow(
      "genuine unused reservation",
    );
    expect(() => consumeReservedIdentityHelloOpenV1(cloned, trial)).toThrow(
      "genuine unused reservation",
    );
    expect(() =>
      consumeReservedIdentityHelloOpenV1(capability, newTrial()),
    ).toThrow("bound to another trial");

    const consumed = consumeReservedExpectedIdentityHelloTrialForPairOpenV1(
      capability,
      trial,
    );
    expect(consumed.activeCandidate).toBe(fixture.candidate);
    expect(consumed.recipientHybridKemSecretSeed).toEqual(
      fixture.receiverSecretSeed,
    );
    expect(consumed.roomRoot).toEqual(ROOM_ROOT);
    consumed.recipientHybridKemSecretSeed.fill(0);
    consumed.roomRoot.fill(0);
    expect(() => consumeReservedIdentityHelloOpenV1(capability, trial)).toThrow(
      "genuine unused reservation",
    );
  });
});
