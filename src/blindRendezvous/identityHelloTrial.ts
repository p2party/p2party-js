/**
 * Provenance-checked local custody and receiver trial for identity HELLO.
 *
 * Expensive local ownership and hybrid-key verification happen exactly once
 * when trusted room/key storage creates `LocalHelloReceiverCustodyV1`.
 * Per-candidate `ExpectedIdentityHelloTrialV1` construction is synchronous,
 * bounded, and cryptography-free. A later durable budget reservation binds
 * the exact opaque candidate and trial objects. The opener can additionally
 * assert the custody identity sealed inside that trial before it invokes the
 * explicitly internal one-use secret transfer below.
 *
 * This module deliberately does not reserve work, run HPKE, authorize a peer,
 * mutate a pair ledger, or publish a response. It is absent from the package
 * barrel.
 */

import { bytesEqual } from "./canonicalSchema";
import {
  decodeCoreRoomStateV1,
  snapshotActivePairOperationCandidate,
  snapshotHistoricalPairPresenceEvidence,
} from "./coreReduce";
import { consumeReservedIdentityHelloOpenV1 } from "./pairOpenReservation";
import { validatePresenceOwnershipV1 } from "./operationPayload";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";
import { PAIR_BOOTSTRAP_SUITE_V1 } from "./pairBootstrapSuite";
import { snapshotByteInput } from "../cryptography/byteInput";
import { createMlKem768X25519Backend } from "../cryptography/hybridKem";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { MlKem768X25519KeyPair } from "../cryptography/hybridKem";
import type {
  ActivePairOperationCandidateSnapshotV1,
  ActivePairOperationCandidateV1,
  VerifiedHistoricalPairPresenceEvidenceV1,
  VerifiedHistoricalPairPresenceSnapshotV1,
} from "./coreReduce";
import type { ReservedIdentityHelloOpenV1 } from "./pairOpenReservation";
import type { RoomPolicyV4 } from "./roomPolicyV4";

const U32_MAX = 0xffffffff;
const U64_MAX = 0xffffffffffffffffn;

declare const localHelloReceiverCustodyBrand: unique symbol;
declare const historicalIdentityHelloEvidenceViewBrand: unique symbol;
declare const expectedIdentityHelloTrialBrand: unique symbol;

/**
 * Opaque room-specific custody for one local presence receiver key.
 *
 * The current constructor is an interim trusted local-storage boundary:
 * `receiverKeyRecordRevision` and `roomRoot` have no independent storage
 * provenance yet. The future atomic room/key adapter must be their sole
 * caller. Their values never become caller-controlled trial inputs.
 */
export interface LocalHelloReceiverCustodyV1 {
  readonly [localHelloReceiverCustodyBrand]: true;
}

/**
 * Opaque bounded endpoint-evidence lookup for one exact HELLO-time Core view.
 *
 * It is not admission or topology authority. The trusted caller supplies the
 * locally selected subset; the later planner/explicit-state fence decides
 * whether an authenticated endpoint may receive a response.
 */
export interface HistoricalIdentityHelloEvidenceViewV1 {
  readonly [historicalIdentityHelloEvidenceViewBrand]: true;
}

/** Opaque, process-local, one-use candidate trial. */
export interface ExpectedIdentityHelloTrialV1 {
  readonly [expectedIdentityHelloTrialBrand]: true;
}

export interface CreateLocalHelloReceiverCustodyOptionsV1 {
  readonly module: LibCrypto;
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  /** Suite-1 MLKEM768-X25519 deterministic receiver seed. */
  readonly recipientHybridKemSecretSeed: Uint8Array;
  /** Exact room-specific HPKE PSK derived by trusted initialized-room state. */
  readonly roomRoot: Uint8Array;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly receiverKeyRecordRevision: bigint;
}

export interface LocalHelloReceiverCustodySnapshotV1 {
  readonly version: 1;
  readonly localPresenceOperationId: Uint8Array;
  readonly exactPresenceOperationBytes: Uint8Array;
  readonly sourceEvidenceCoreStateBytes: Uint8Array;
  readonly sourceEvidenceLogicalWindow: bigint;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly advertisedReceiverHybridKemPublicKey: Uint8Array;
  readonly receiverKeyValidThroughLogicalWindow: bigint;
  readonly receiverEvidenceRetainThroughLogicalWindow: bigint;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly receiverKeyRecordRevision: bigint;
}

export interface CreateHistoricalIdentityHelloEvidenceViewOptionsV1 {
  /**
   * A nonempty bounded subset of observed PRESENCE evidence from one genuine
   * HELLO-time Core result. Production supplies the Project-selected subset
   * needed by local receiver trials, never the whole raw overcapacity roster.
   */
  readonly historicalPresenceEvidence: readonly VerifiedHistoricalPairPresenceEvidenceV1[];
}

/**
 * Compact, deeply owned metadata for one bounded historical evidence view.
 *
 * Presence operation IDs are sufficient for deterministic membership and
 * lookup. Exact operation/prefix snapshots are resolved one at a time only
 * after a durable pair-open reservation has been consumed.
 */
export interface HistoricalIdentityHelloEvidenceViewSnapshotV1 {
  readonly version: 1;
  readonly exactCoreStateBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly helloLogicalWindow: bigint;
  readonly minimumRetainThroughLogicalWindow: bigint;
  readonly presenceOperationIds: readonly Uint8Array[];
}

export interface CreateExpectedIdentityHelloTrialOptionsV1 {
  readonly activeCandidate: ActivePairOperationCandidateV1;
  readonly receiverCustody: LocalHelloReceiverCustodyV1;
  readonly historicalEvidenceView: HistoricalIdentityHelloEvidenceViewV1;
  readonly trialOrdinal: number;
}

/**
 * Deeply owned non-secret view for durable reservation/CAS binding.
 *
 * `exactCoreStateBytes` is the current active-operation fence.
 * `exactEvidenceCoreStateBytes` is the potentially older, exact HELLO-window
 * presence-proof fence. They intentionally need not be equal.
 */
export interface ExpectedIdentityHelloTrialSnapshotV1 {
  readonly version: 1;
  readonly activeOperationId: Uint8Array;
  readonly exactCoreStateBytes: Uint8Array;
  readonly exactEvidenceCoreStateBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly helloLogicalWindow: bigint;
  readonly localPresenceOperationId: Uint8Array;
  readonly advertisedReceiverHybridKemPublicKey: Uint8Array;
  readonly receiverKeyValidThroughLogicalWindow: bigint;
  readonly receiverEvidenceRetainThroughLogicalWindow: bigint;
  readonly trialOrdinal: number;
  readonly receiverKeyRecordRevision: bigint;
  readonly activeCandidate: ActivePairOperationCandidateSnapshotV1;
  readonly receiverCustody: LocalHelloReceiverCustodySnapshotV1;
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceSnapshotV1;
  readonly historicalEvidenceView: HistoricalIdentityHelloEvidenceViewSnapshotV1;
}

/**
 * Small private-to-the-pair-kernel projection used before work is charged.
 *
 * It contains no decoded room roster, presence operation, author prefix,
 * receiver secret, RoomRoot, or caller-controlled coordinate.
 *
 * @internal
 */
export interface ExpectedIdentityHelloTrialReservationProjectionV1 {
  readonly version: 1;
  readonly activeOperationId: Uint8Array;
  readonly exactCurrentCoreStateBytes: Uint8Array;
  readonly exactEvidenceCoreStateBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly localPresenceOperationId: Uint8Array;
  readonly receiverKeyRecordRevision: bigint;
  readonly capturedReferenceWindow: bigint;
  readonly completeEnvelopeBytes: number;
}

/**
 * Internal one-use transfer returned only after consuming a genuine durable
 * reservation.
 *
 * Both returned secrets are fresh owned copies and MUST be wiped by the
 * consumer in a `finally` block. The reusable custody master remains live
 * until explicitly destroyed because concurrent HELLO trials may need it.
 *
 * @internal
 */
export interface ConsumedExpectedIdentityHelloTrialV1 {
  readonly snapshot: ExpectedIdentityHelloTrialSnapshotV1;
  readonly activeCandidate: ActivePairOperationCandidateV1;
  readonly receiverCustody: LocalHelloReceiverCustodyV1;
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  /**
   * Exact-ID lookup over the bounded fenced view. This function exists only
   * after the durable reservation is consumed; it returns an opaque genuine
   * evidence handle, never a caller-assembled structural proof.
   */
  readonly resolveHistoricalPresenceEvidence: (
    presenceOperationId: Uint8Array,
  ) => VerifiedHistoricalPairPresenceEvidenceV1 | null;
  readonly recipientHybridKemSecretSeed: Uint8Array;
  readonly roomRoot: Uint8Array;
}

export class IdentityHelloTrialError extends Error {
  override readonly name = "IdentityHelloTrialError";

  constructor(message: string) {
    super(`identityHelloTrial: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new IdentityHelloTrialError(message);
};

interface PrivateLocalHelloReceiverCustody {
  readonly localPresenceOperationId: Uint8Array;
  readonly exactPresenceOperationBytes: Uint8Array;
  readonly sourceEvidenceCoreStateBytes: Uint8Array;
  readonly sourceEvidenceLogicalWindow: bigint;
  readonly roomContextId: Uint8Array;
  readonly roomPolicyBytes: Uint8Array;
  readonly advertisedReceiverHybridKemPublicKey: Uint8Array;
  readonly receiverKeyValidThroughLogicalWindow: bigint;
  readonly receiverEvidenceRetainThroughLogicalWindow: bigint;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly recipientHybridKemSecretSeed: Uint8Array;
  readonly roomRoot: Uint8Array;
  readonly receiverKeyRecordRevision: bigint;
}

interface PrivateHistoricalIdentityHelloEvidenceEntry {
  readonly handle: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly presenceOperationId: Uint8Array;
  readonly exactPresenceOperationBytes: Uint8Array;
  readonly advertisedReceiverHybridKemPublicKey: Uint8Array;
  readonly retainThroughLogicalWindow: bigint;
}

interface PrivateHistoricalIdentityHelloEvidenceView {
  readonly entries: readonly PrivateHistoricalIdentityHelloEvidenceEntry[];
  readonly entriesByPresenceId: ReadonlyMap<
    string,
    PrivateHistoricalIdentityHelloEvidenceEntry
  >;
  readonly exactCoreStateBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicyBytes: Uint8Array;
  readonly helloLogicalWindow: bigint;
  readonly minimumRetainThroughLogicalWindow: bigint;
}

interface PrivateExpectedIdentityHelloTrial {
  readonly activeCandidate: ActivePairOperationCandidateV1;
  readonly receiverCustody: LocalHelloReceiverCustodyV1;
  readonly historicalEvidenceView: HistoricalIdentityHelloEvidenceViewV1;
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly trialOrdinal: number;
  readonly activeOperationId: Uint8Array;
  readonly exactCurrentCoreStateBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly capturedReferenceWindow: bigint;
  readonly completeEnvelopeBytes: number;
}

const custodyStates = new WeakMap<object, PrivateLocalHelloReceiverCustody>();
const genuineCustodies = new WeakSet<object>();
const evidenceViewStates = new WeakMap<
  object,
  PrivateHistoricalIdentityHelloEvidenceView
>();
const genuineEvidenceViews = new WeakSet<object>();
const trialStates = new WeakMap<object, PrivateExpectedIdentityHelloTrial>();
const genuineTrials = new WeakSet<object>();

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const bytesKey = (value: Uint8Array): string => {
  let output = "";
  for (const byte of value) output += byte.toString(16).padStart(2, "0");
  return output;
};

const requireU32 = (name: string, value: unknown): number => {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > U32_MAX
  )
    return fail(`${name} must be an unsigned 32-bit integer`);
  return value;
};

const requireU64 = (name: string, value: unknown): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return fail(`${name} must be an unsigned 64-bit integer`);
  return value;
};

const requireCustodyState = (
  custody: LocalHelloReceiverCustodyV1,
): PrivateLocalHelloReceiverCustody => {
  if (typeof custody !== "object" || custody === null)
    return fail("receiver custody must be a genuine live process-local handle");
  const state = custodyStates.get(custody);
  if (state === undefined)
    return fail("receiver custody must be a genuine live process-local handle");
  return state;
};

const requireEvidenceViewState = (
  view: HistoricalIdentityHelloEvidenceViewV1,
): PrivateHistoricalIdentityHelloEvidenceView => {
  if (typeof view !== "object" || view === null)
    return fail(
      "historical evidence view must be a genuine live process-local handle",
    );
  const state = evidenceViewStates.get(view);
  if (state === undefined)
    return fail(
      "historical evidence view must be a genuine live process-local handle",
    );
  return state;
};

const requireTrialState = (
  trial: ExpectedIdentityHelloTrialV1,
): PrivateExpectedIdentityHelloTrial => {
  if (typeof trial !== "object" || trial === null)
    return fail("trial must be a genuine live process-local capability");
  const state = trialStates.get(trial);
  if (state === undefined)
    return fail("trial must be a genuine live process-local capability");
  return state;
};

const copyCustodySnapshot = (
  state: PrivateLocalHelloReceiverCustody,
): LocalHelloReceiverCustodySnapshotV1 => ({
  version: 1,
  localPresenceOperationId: Uint8Array.from(state.localPresenceOperationId),
  exactPresenceOperationBytes: Uint8Array.from(
    state.exactPresenceOperationBytes,
  ),
  sourceEvidenceCoreStateBytes: Uint8Array.from(
    state.sourceEvidenceCoreStateBytes,
  ),
  sourceEvidenceLogicalWindow: state.sourceEvidenceLogicalWindow,
  roomContextId: Uint8Array.from(state.roomContextId),
  roomPolicy: decodeRoomPolicyV4(state.roomPolicyBytes),
  advertisedReceiverHybridKemPublicKey: Uint8Array.from(
    state.advertisedReceiverHybridKemPublicKey,
  ),
  receiverKeyValidThroughLogicalWindow:
    state.receiverKeyValidThroughLogicalWindow,
  receiverEvidenceRetainThroughLogicalWindow:
    state.receiverEvidenceRetainThroughLogicalWindow,
  localStableEd25519PublicKey: Uint8Array.from(
    state.localStableEd25519PublicKey,
  ),
  receiverKeyRecordRevision: state.receiverKeyRecordRevision,
});

const copyEvidenceViewSnapshot = (
  state: PrivateHistoricalIdentityHelloEvidenceView,
): HistoricalIdentityHelloEvidenceViewSnapshotV1 => ({
  version: 1,
  exactCoreStateBytes: Uint8Array.from(state.exactCoreStateBytes),
  roomContextId: Uint8Array.from(state.roomContextId),
  roomPolicy: decodeRoomPolicyV4(state.roomPolicyBytes),
  helloLogicalWindow: state.helloLogicalWindow,
  minimumRetainThroughLogicalWindow: state.minimumRetainThroughLogicalWindow,
  presenceOperationIds: state.entries.map((entry) =>
    Uint8Array.from(entry.presenceOperationId),
  ),
});

const validateEvidenceAtHelloWindow = (
  evidence: VerifiedHistoricalPairPresenceSnapshotV1,
  helloLogicalWindow: bigint,
  name: string,
): void => {
  if (evidence.provedAtLogicalWindow !== helloLogicalWindow)
    fail(`${name} was not proved at the exact HELLO logical window`);
  if (
    evidence.operation.logicalWindow > helloLogicalWindow ||
    helloLogicalWindow > evidence.presence.core.validThroughLogicalWindow
  )
    fail(`${name} presence was not valid at the HELLO logical window`);
  if (
    helloLogicalWindow >
    evidence.presence.core.receiverKeyValidThroughLogicalWindow
  )
    fail(`${name} receiver key was not valid at the HELLO logical window`);
  if (evidence.retainThroughLogicalWindow < helloLogicalWindow)
    fail(`${name} has an invalid retained receiver-key evidence horizon`);
};

const copyTrialSnapshot = (
  state: PrivateExpectedIdentityHelloTrial,
): ExpectedIdentityHelloTrialSnapshotV1 => {
  const activeCandidate = snapshotActivePairOperationCandidate(
    state.activeCandidate,
  );
  const receiverCustody = copyCustodySnapshot(
    requireCustodyState(state.receiverCustody),
  );
  const historicalEvidenceView = copyEvidenceViewSnapshot(
    requireEvidenceViewState(state.historicalEvidenceView),
  );
  const localPresenceEvidence = snapshotHistoricalPairPresenceEvidence(
    state.localPresenceEvidence,
  );
  return {
    version: 1,
    activeOperationId: Uint8Array.from(activeCandidate.operationId),
    exactCoreStateBytes: Uint8Array.from(activeCandidate.exactCoreStateBytes),
    exactEvidenceCoreStateBytes: Uint8Array.from(
      historicalEvidenceView.exactCoreStateBytes,
    ),
    roomContextId: Uint8Array.from(activeCandidate.roomContextId),
    // `activeCandidate` itself is already a fresh owned snapshot. Sharing its
    // policy object inside this one returned projection preserves one SSOT;
    // a later snapshot decodes fresh policy bytes again.
    roomPolicy: activeCandidate.roomPolicy,
    helloLogicalWindow: activeCandidate.operation.logicalWindow,
    localPresenceOperationId: Uint8Array.from(
      localPresenceEvidence.presenceOperationId,
    ),
    advertisedReceiverHybridKemPublicKey: Uint8Array.from(
      receiverCustody.advertisedReceiverHybridKemPublicKey,
    ),
    receiverKeyValidThroughLogicalWindow:
      receiverCustody.receiverKeyValidThroughLogicalWindow,
    receiverEvidenceRetainThroughLogicalWindow:
      localPresenceEvidence.retainThroughLogicalWindow,
    trialOrdinal: state.trialOrdinal,
    receiverKeyRecordRevision: receiverCustody.receiverKeyRecordRevision,
    activeCandidate,
    receiverCustody,
    localPresenceEvidence,
    historicalEvidenceView,
  };
};

const snapshotDenseEvidenceHandles = (
  input: readonly VerifiedHistoricalPairPresenceEvidenceV1[],
  maximumLength: number,
): readonly VerifiedHistoricalPairPresenceEvidenceV1[] => {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype)
    return fail(
      "historical presence evidence must be a plain bounded readonly array",
    );
  if (input.length < 1 || input.length > maximumLength)
    return fail(
      "historical presence evidence exceeds the bounded projected-view limit",
    );

  const captured: VerifiedHistoricalPairPresenceEvidenceV1[] = [];
  for (let index = 0; index < input.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (descriptor === undefined || !("value" in descriptor))
      return fail(
        "historical presence evidence must contain dense own data elements",
      );
    captured.push(descriptor.value as VerifiedHistoricalPairPresenceEvidenceV1);
  }
  return captured;
};

/**
 * Capture one bounded exact-Core evidence subset.
 *
 * The O(selected-member-count) provenance work and canonical Core decode
 * happen once here. Every later receiver-key trial reuses the opaque result
 * and performs no raw-roster walk. A view may omit an otherwise valid Core
 * presence because Project did not select it; a HELLO naming an omitted
 * endpoint is deferred and can never bypass later planner/admission fences.
 */
export const createHistoricalIdentityHelloEvidenceViewV1 = async (
  options: CreateHistoricalIdentityHelloEvidenceViewOptionsV1,
): Promise<HistoricalIdentityHelloEvidenceViewV1> => {
  const borrowedEvidence = options.historicalPresenceEvidence;
  if (
    !Array.isArray(borrowedEvidence) ||
    Object.getPrototypeOf(borrowedEvidence) !== Array.prototype ||
    borrowedEvidence.length < 1
  )
    return fail(
      "historical presence evidence must be a nonempty plain bounded readonly array",
    );
  const firstDescriptor = Object.getOwnPropertyDescriptor(
    borrowedEvidence,
    "0",
  );
  if (firstDescriptor === undefined || !("value" in firstDescriptor))
    return fail(
      "historical presence evidence must contain dense own data elements",
    );
  const first = snapshotHistoricalPairPresenceEvidence(
    firstDescriptor.value as VerifiedHistoricalPairPresenceEvidenceV1,
  );
  const evidenceHandles = snapshotDenseEvidenceHandles(
    borrowedEvidence,
    first.roomPolicy.maxRoomMembers,
  );
  /*
   * Capture every genuine evidence handle before the first await. Caller
   * mutation of the input array cannot change the view being proved.
   */
  const evidencePairs = evidenceHandles.map((handle) => ({
    handle,
    snapshot: snapshotHistoricalPairPresenceEvidence(handle),
  }));
  const exactCoreStateBytes = Uint8Array.from(first.exactCoreStateBytes);
  const roomContextId = Uint8Array.from(first.roomContextId);
  const roomPolicyBytes = encodeRoomPolicyV4(first.roomPolicy);
  const helloLogicalWindow = first.provedAtLogicalWindow;
  const presenceIds = new Set<string>();
  let minimumRetainThroughLogicalWindow = U64_MAX;

  for (let index = 0; index < evidencePairs.length; index++) {
    const evidence = evidencePairs[index].snapshot;
    const name = `historicalPresenceEvidence[${String(index)}]`;
    if (
      !bytesEqual(evidence.roomContextId, roomContextId) ||
      !bytesEqual(encodeRoomPolicyV4(evidence.roomPolicy), roomPolicyBytes)
    )
      fail(`${name} belongs to another room or policy`);
    if (evidence.provedAtLogicalWindow !== helloLogicalWindow)
      fail(`${name} belongs to another HELLO logical window`);
    if (!bytesEqual(evidence.exactCoreStateBytes, exactCoreStateBytes))
      fail(`${name} was not captured from the exact same Core snapshot`);
    validateEvidenceAtHelloWindow(evidence, helloLogicalWindow, name);
    const presenceId = bytesKey(evidence.presenceOperationId);
    if (presenceIds.has(presenceId))
      fail("historical presence evidence IDs must be unique");
    presenceIds.add(presenceId);
    if (evidence.retainThroughLogicalWindow < minimumRetainThroughLogicalWindow)
      minimumRetainThroughLogicalWindow = evidence.retainThroughLogicalWindow;
  }

  const core = await decodeCoreRoomStateV1(exactCoreStateBytes);
  if (core.referenceWindow !== helloLogicalWindow)
    fail("historical evidence Core view is not at the exact HELLO window");
  for (const evidence of evidencePairs) {
    if (
      !core.observedPresences.some((presence) =>
        bytesEqual(
          presence.presenceOperationId,
          evidence.snapshot.presenceOperationId,
        ),
      )
    )
      fail(
        "historical presence evidence is not observed in its exact Core view",
      );
  }

  evidencePairs.sort((left, right) =>
    compareBytes(
      left.snapshot.presenceOperationId,
      right.snapshot.presenceOperationId,
    ),
  );
  const entries = Object.freeze(
    evidencePairs.map(
      ({ handle, snapshot }): PrivateHistoricalIdentityHelloEvidenceEntry => ({
        handle,
        presenceOperationId: Uint8Array.from(snapshot.presenceOperationId),
        exactPresenceOperationBytes: Uint8Array.from(
          snapshot.exactPresenceOperationBytes,
        ),
        advertisedReceiverHybridKemPublicKey: Uint8Array.from(
          snapshot.presence.core.rendezvousHybridKemPublicKey,
        ),
        retainThroughLogicalWindow: snapshot.retainThroughLogicalWindow,
      }),
    ),
  );
  const entriesByPresenceId = new Map(
    entries.map((entry) => [bytesKey(entry.presenceOperationId), entry]),
  );
  const handle = Object.freeze({}) as HistoricalIdentityHelloEvidenceViewV1;
  genuineEvidenceViews.add(handle);
  evidenceViewStates.set(handle, {
    entries,
    entriesByPresenceId,
    exactCoreStateBytes,
    roomContextId,
    roomPolicyBytes,
    helloLogicalWindow,
    minimumRetainThroughLogicalWindow,
  });
  return handle;
};

/** Return fresh compact metadata, never per-presence operation snapshots. */
export const snapshotHistoricalIdentityHelloEvidenceViewV1 = (
  view: HistoricalIdentityHelloEvidenceViewV1,
): HistoricalIdentityHelloEvidenceViewSnapshotV1 =>
  copyEvidenceViewSnapshot(requireEvidenceViewState(view));

/**
 * Create reusable local receiver custody.
 *
 * All caller bytes and execution dependencies are captured before the first
 * await. Expensive verification occurs here once per persisted key record,
 * never once per attacker-supplied PAIR_STEP.
 */
export const createLocalHelloReceiverCustodyV1 = async (
  options: CreateLocalHelloReceiverCustodyOptionsV1,
): Promise<LocalHelloReceiverCustodyV1> => {
  let privateReceiverSeed: Uint8Array | undefined;
  let privateRoomRoot: Uint8Array | undefined;
  let derivedKeyPair: MlKem768X25519KeyPair | undefined;
  let transferred = false;

  try {
    const cryptoModule = options.module;
    const source = snapshotHistoricalPairPresenceEvidence(
      options.localPresenceEvidence,
    );
    privateReceiverSeed = snapshotByteInput(
      options.recipientHybridKemSecretSeed,
      "identityHelloTrial: recipient hybrid KEM secret seed",
      {
        exactLength: PAIR_BOOTSTRAP_SUITE_V1.hybridKem.secretKeyBytes,
      },
    );
    privateRoomRoot = snapshotByteInput(
      options.roomRoot,
      "identityHelloTrial: RoomRoot",
      { exactLength: PAIR_BOOTSTRAP_SUITE_V1.hpke.pskBytes },
    );
    const localStableEd25519PublicKey = snapshotByteInput(
      options.localStableEd25519PublicKey,
      "identityHelloTrial: local stable Ed25519 public key",
      { exactLength: 32 },
    );
    const receiverKeyRecordRevision = requireU64(
      "receiverKeyRecordRevision",
      options.receiverKeyRecordRevision,
    );

    if (
      source.operation.logicalWindow > source.provedAtLogicalWindow ||
      source.provedAtLogicalWindow >
        source.presence.core.validThroughLogicalWindow
    )
      fail("custody source presence was not valid at its proof window");
    if (
      source.provedAtLogicalWindow >
      source.presence.core.receiverKeyValidThroughLogicalWindow
    )
      fail("custody source receiver-key horizon does not cover its proof");

    await validatePresenceOwnershipV1(
      source.operation,
      source.presence,
      localStableEd25519PublicKey,
      {
        roomContextId: source.roomContextId,
        roomPolicy: source.roomPolicy,
      },
      cryptoModule,
    );

    derivedKeyPair =
      await createMlKem768X25519Backend(cryptoModule).deriveKeyPair(
        privateReceiverSeed,
      );
    if (
      !bytesEqual(
        derivedKeyPair.publicKey,
        source.presence.core.rendezvousHybridKemPublicKey,
      )
    )
      fail(
        "recipient hybrid KEM secret seed does not match the local presence",
      );

    const handle = Object.freeze({}) as LocalHelloReceiverCustodyV1;
    genuineCustodies.add(handle);
    custodyStates.set(handle, {
      localPresenceOperationId: Uint8Array.from(source.presenceOperationId),
      exactPresenceOperationBytes: Uint8Array.from(
        source.exactPresenceOperationBytes,
      ),
      sourceEvidenceCoreStateBytes: Uint8Array.from(source.exactCoreStateBytes),
      sourceEvidenceLogicalWindow: source.provedAtLogicalWindow,
      roomContextId: Uint8Array.from(source.roomContextId),
      roomPolicyBytes: encodeRoomPolicyV4(source.roomPolicy),
      advertisedReceiverHybridKemPublicKey: Uint8Array.from(
        derivedKeyPair.publicKey,
      ),
      receiverKeyValidThroughLogicalWindow:
        source.presence.core.receiverKeyValidThroughLogicalWindow,
      receiverEvidenceRetainThroughLogicalWindow:
        source.retainThroughLogicalWindow,
      localStableEd25519PublicKey,
      recipientHybridKemSecretSeed: privateReceiverSeed,
      roomRoot: privateRoomRoot,
      receiverKeyRecordRevision,
    });
    transferred = true;
    return handle;
  } finally {
    derivedKeyPair?.destroy();
    if (!transferred) {
      privateReceiverSeed?.fill(0);
      privateRoomRoot?.fill(0);
    }
  }
};

/** Return a fresh non-secret custody projection. */
export const snapshotLocalHelloReceiverCustodyV1 = (
  custody: LocalHelloReceiverCustodyV1,
): LocalHelloReceiverCustodySnapshotV1 =>
  copyCustodySnapshot(requireCustodyState(custody));

/**
 * Create one cheap expected trial from already-verified local custody.
 *
 * This function is intentionally synchronous and performs no signature, KEM,
 * KDF, AEAD, or storage work.
 */
export const createExpectedIdentityHelloTrialV1 = (
  options: CreateExpectedIdentityHelloTrialOptionsV1,
): ExpectedIdentityHelloTrialV1 => {
  const activeCandidate = options.activeCandidate;
  const receiverCustody = options.receiverCustody;
  const historicalEvidenceView = options.historicalEvidenceView;
  const active = snapshotActivePairOperationCandidate(activeCandidate);
  const custody = requireCustodyState(receiverCustody);
  const evidenceView = requireEvidenceViewState(historicalEvidenceView);
  const trialOrdinal = requireU32("trialOrdinal", options.trialOrdinal);

  if (
    active.operation.kind !== "PAIR_STEP" ||
    active.operation.operationPayloadClass !== 0 ||
    active.envelope.bootstrapHeader === null ||
    active.envelope.nonce !== null
  )
    fail("active candidate is not a class-0 bootstrap PAIR_STEP");

  const candidatePolicyBytes = encodeRoomPolicyV4(active.roomPolicy);
  if (
    !bytesEqual(active.roomContextId, custody.roomContextId) ||
    !bytesEqual(candidatePolicyBytes, custody.roomPolicyBytes)
  )
    fail("receiver custody belongs to another room or policy");
  if (
    !bytesEqual(active.roomContextId, evidenceView.roomContextId) ||
    !bytesEqual(candidatePolicyBytes, evidenceView.roomPolicyBytes)
  )
    fail("historical evidence view belongs to another room or policy");

  const helloLogicalWindow = active.operation.logicalWindow;
  if (helloLogicalWindow !== evidenceView.helloLogicalWindow)
    fail("historical evidence view belongs to another HELLO logical window");
  if (active.referenceWindow < helloLogicalWindow)
    fail("active Core reference precedes the HELLO logical window");
  if (active.referenceWindow > evidenceView.minimumRetainThroughLogicalWindow)
    fail("historical evidence view is beyond its retained evidence horizon");

  const localEntry = evidenceView.entriesByPresenceId.get(
    bytesKey(custody.localPresenceOperationId),
  );
  const exactLocalEntry =
    localEntry ??
    fail("historical evidence view does not include the custody presence");
  if (
    !bytesEqual(
      exactLocalEntry.exactPresenceOperationBytes,
      custody.exactPresenceOperationBytes,
    )
  )
    fail("local presence ID does not match the custody operation bytes");
  if (helloLogicalWindow > custody.receiverKeyValidThroughLogicalWindow)
    fail("local receiver-key horizon does not cover the HELLO window");
  if (
    !bytesEqual(
      exactLocalEntry.advertisedReceiverHybridKemPublicKey,
      custody.advertisedReceiverHybridKemPublicKey,
    )
  )
    fail("local HELLO-window evidence does not match receiver-key custody");

  const handle = Object.freeze({}) as ExpectedIdentityHelloTrialV1;
  genuineTrials.add(handle);
  trialStates.set(handle, {
    activeCandidate,
    receiverCustody,
    historicalEvidenceView,
    localPresenceEvidence: exactLocalEntry.handle,
    trialOrdinal,
    activeOperationId: Uint8Array.from(active.operationId),
    exactCurrentCoreStateBytes: Uint8Array.from(active.exactCoreStateBytes),
    roomContextId: Uint8Array.from(active.roomContextId),
    capturedReferenceWindow: active.referenceWindow,
    completeEnvelopeBytes: active.operation.fixedPayload.length,
  });
  return handle;
};

/** Return a fresh, independently owned, non-secret trial snapshot. */
export const snapshotExpectedIdentityHelloTrialV1 = (
  trial: ExpectedIdentityHelloTrialV1,
): ExpectedIdentityHelloTrialSnapshotV1 =>
  copyTrialSnapshot(requireTrialState(trial));

/**
 * Return the only pre-budget projection used by reservation.
 *
 * All fields were captured once when the trial was constructed. In
 * particular, this function performs no Core decode, roster walk, evidence
 * snapshot, operation decode, signature work, KEM work, or secret copy.
 *
 * @internal
 */
export const snapshotExpectedIdentityHelloTrialReservationProjectionV1 = (
  trial: ExpectedIdentityHelloTrialV1,
  activeCandidate: ActivePairOperationCandidateV1,
): ExpectedIdentityHelloTrialReservationProjectionV1 => {
  const state = requireTrialState(trial);
  if (state.activeCandidate !== activeCandidate)
    fail("trial is bound to another active candidate capability");
  const custody = requireCustodyState(state.receiverCustody);
  const evidenceView = requireEvidenceViewState(state.historicalEvidenceView);
  return {
    version: 1,
    activeOperationId: Uint8Array.from(state.activeOperationId),
    exactCurrentCoreStateBytes: Uint8Array.from(
      state.exactCurrentCoreStateBytes,
    ),
    exactEvidenceCoreStateBytes: Uint8Array.from(
      evidenceView.exactCoreStateBytes,
    ),
    roomContextId: Uint8Array.from(state.roomContextId),
    localPresenceOperationId: Uint8Array.from(custody.localPresenceOperationId),
    receiverKeyRecordRevision: custody.receiverKeyRecordRevision,
    capturedReferenceWindow: state.capturedReferenceWindow,
    completeEnvelopeBytes: state.completeEnvelopeBytes,
  };
};

/**
 * Recheck all opaque dependencies without materializing structural data.
 *
 * @internal
 */
export const assertExpectedIdentityHelloTrialReservationLivenessV1 = (
  trial: ExpectedIdentityHelloTrialV1,
  activeCandidate: ActivePairOperationCandidateV1,
): void => {
  const state = requireTrialState(trial);
  if (state.activeCandidate !== activeCandidate)
    fail("trial is bound to another active candidate capability");
  requireCustodyState(state.receiverCustody);
  requireEvidenceViewState(state.historicalEvidenceView);
};

/**
 * Bind reservation to the exact opaque active-candidate object.
 *
 * Custody is deliberately not a reservation input: its identity is sealed
 * inside the trial, so the reservation caller cannot substitute one.
 *
 * @internal
 */
export const assertExpectedIdentityHelloTrialCandidateBindingV1 = (
  trial: ExpectedIdentityHelloTrialV1,
  activeCandidate: ActivePairOperationCandidateV1,
): void => {
  assertExpectedIdentityHelloTrialReservationLivenessV1(trial, activeCandidate);
};

/**
 * Bind the future opener to the exact opaque candidate and custody objects.
 *
 * Matching structural bytes are insufficient.
 *
 * @internal
 */
export const assertExpectedIdentityHelloTrialBindingsV1 = (
  trial: ExpectedIdentityHelloTrialV1,
  activeCandidate: ActivePairOperationCandidateV1,
  receiverCustody: LocalHelloReceiverCustodyV1,
): void => {
  assertExpectedIdentityHelloTrialCandidateBindingV1(trial, activeCandidate);
  const state = requireTrialState(trial);
  if (state.receiverCustody !== receiverCustody)
    fail("trial is bound to another receiver custody capability");
  requireCustodyState(receiverCustody);
};

/**
 * Transfer fresh receiver-seed and RoomRoot copies exactly once.
 *
 * The future caller must first consume a durable work capability bound to the
 * same trial/candidate identities; the opener then uses the sealed custody
 * identity. Both returned secrets must be wiped in `finally`.
 *
 */
const consumeExpectedIdentityHelloTrialForPairOpenV1 = (
  trial: ExpectedIdentityHelloTrialV1,
): ConsumedExpectedIdentityHelloTrialV1 => {
  const state = requireTrialState(trial);
  const custody = requireCustodyState(state.receiverCustody);
  requireEvidenceViewState(state.historicalEvidenceView);
  let receiverSeedCopy: Uint8Array | undefined;
  let roomRootCopy: Uint8Array | undefined;
  try {
    const snapshot = copyTrialSnapshot(state);
    receiverSeedCopy = Uint8Array.from(custody.recipientHybridKemSecretSeed);
    roomRootCopy = Uint8Array.from(custody.roomRoot);
    const consumed: ConsumedExpectedIdentityHelloTrialV1 = {
      snapshot,
      activeCandidate: state.activeCandidate,
      receiverCustody: state.receiverCustody,
      localPresenceEvidence: state.localPresenceEvidence,
      resolveHistoricalPresenceEvidence: (
        presenceOperationId: Uint8Array,
      ): VerifiedHistoricalPairPresenceEvidenceV1 | null => {
        const ownedPresenceOperationId = snapshotByteInput(
          presenceOperationId,
          "identityHelloTrial: historical presence lookup operation ID",
          { exactLength: 32 },
        );
        const evidenceView = requireEvidenceViewState(
          state.historicalEvidenceView,
        );
        const entry = evidenceView.entriesByPresenceId.get(
          bytesKey(ownedPresenceOperationId),
        );
        if (
          entry === undefined ||
          !bytesEqual(entry.presenceOperationId, ownedPresenceOperationId)
        )
          return null;
        return entry.handle;
      },
      recipientHybridKemSecretSeed: receiverSeedCopy,
      roomRoot: roomRootCopy,
    };
    trialStates.delete(trial);
    receiverSeedCopy = undefined;
    roomRootCopy = undefined;
    return consumed;
  } finally {
    receiverSeedCopy?.fill(0);
    roomRootCopy?.fill(0);
  }
};

/**
 * Consume one genuine committed reservation, then transfer trial secrets.
 *
 * The reservation capability is deleted before this function can copy either
 * secret. Its privately bound candidate must be the exact candidate sealed
 * inside the trial; no caller-supplied candidate participates in this check.
 *
 * This explicit import creates a narrow cycle with `pairOpenReservation.ts`.
 * Neither module performs top-level work, so the cycle contains bindings only.
 *
 * @internal
 */
export const consumeReservedExpectedIdentityHelloTrialForPairOpenV1 = (
  capability: ReservedIdentityHelloOpenV1,
  trial: ExpectedIdentityHelloTrialV1,
): ConsumedExpectedIdentityHelloTrialV1 => {
  const state = requireTrialState(trial);
  const reservedCandidate = consumeReservedIdentityHelloOpenV1(
    capability,
    trial,
  );
  if (reservedCandidate !== state.activeCandidate)
    fail("reserved open is bound to another active candidate capability");
  return consumeExpectedIdentityHelloTrialForPairOpenV1(trial);
};

/** Invalidate one unused trial. Idempotent for a genuine handle. */
export const destroyExpectedIdentityHelloTrialV1 = (
  trial: ExpectedIdentityHelloTrialV1,
): void => {
  if (typeof trial !== "object" || trial === null || !genuineTrials.has(trial))
    return fail("trial must be a genuine process-local capability");
  trialStates.delete(trial);
};

/**
 * Invalidate one reusable historical evidence view.
 *
 * Destruction is idempotent for a genuine handle. Any dependent unconsumed
 * trial subsequently fails closed at reservation or consumption.
 */
export const destroyHistoricalIdentityHelloEvidenceViewV1 = (
  view: HistoricalIdentityHelloEvidenceViewV1,
): void => {
  if (
    typeof view !== "object" ||
    view === null ||
    !genuineEvidenceViews.has(view)
  )
    return fail(
      "historical evidence view must be a genuine process-local handle",
    );
  evidenceViewStates.delete(view);
};

/**
 * Wipe reusable receiver custody after its key record is retired.
 *
 * Destruction is idempotent for a genuine handle.
 */
export const destroyLocalHelloReceiverCustodyV1 = (
  custody: LocalHelloReceiverCustodyV1,
): void => {
  if (
    typeof custody !== "object" ||
    custody === null ||
    !genuineCustodies.has(custody)
  )
    return fail("receiver custody must be a genuine process-local handle");
  const state = custodyStates.get(custody);
  if (state === undefined) return;
  state.recipientHybridKemSecretSeed.fill(0);
  state.roomRoot.fill(0);
  custodyStates.delete(custody);
};
