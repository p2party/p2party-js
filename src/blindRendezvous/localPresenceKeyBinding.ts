/**
 * Process-local custody for a room/window author epoch and a verified binding
 * from one exact local PRESENCE to its live local key records.
 *
 * `VerifiedLocalPresenceKeyBindingV1` is intentionally only a per-presence key
 * binding. It proves neither a complete/non-omitted local-presence set nor a
 * current Core view, and it grants no topology, admission, lease, persistence,
 * publication, or signaling authority. This internal module is absent from the
 * package barrel.
 */

import { snapshotByteInput } from "../cryptography/byteInput";
import { bytesEqual } from "./canonicalSchema";
import { snapshotHistoricalPairPresenceEvidence } from "./coreReduce";
import {
  captureConsistentEd25519KeyMaterial,
  wipeOwnedEd25519KeyMaterial,
} from "../cryptography/ownedEd25519KeyMaterial";
import { snapshotLocalHelloReceiverCustodyV1 } from "./identityHelloTrial";
import { snapshotOperationValidationContext } from "./operation";
import { validatePresenceOwnershipV1 } from "./operationPayload";
import { decodeRoomPolicyV4, encodeRoomPolicyV4 } from "./roomPolicyV4";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { VerifiedHistoricalPairPresenceEvidenceV1 } from "./coreReduce";
import type { LocalHelloReceiverCustodyV1 } from "./identityHelloTrial";
import type { OwnedEd25519KeyMaterial } from "../cryptography/ownedEd25519KeyMaterial";
import type { OperationValidationContext } from "./operation";
import type { AuthenticatedRoomOperationV1 } from "./operation";
import type { PresenceV1 } from "./operationPayload";
import type { RoomPolicyV4 } from "./roomPolicyV4";

const U64_MAX = 0xffffffffffffffffn;

declare const localAuthorEpochCustodyBrand: unique symbol;
declare const verifiedLocalPresenceKeyBindingBrand: unique symbol;

/**
 * Opaque live custody for one exact room/window author epoch key record.
 *
 * This capability is runtime-distinct from stable-identity custody. Possessing
 * either handle can never be substituted for the other, even by a type cast.
 */
export interface LocalAuthorEpochCustodyV1 {
  readonly [localAuthorEpochCustodyBrand]: true;
}

export interface CreateLocalAuthorEpochCustodyOptionsV1 {
  readonly module: LibCrypto;
  readonly authorEpochEd25519SecretKey: Uint8Array;
  /** Non-reused revision of the persisted author-epoch key record. */
  readonly authorEpochKeyRecordRevision: bigint;
  readonly roomContextId: Uint8Array;
  readonly logicalWindow: bigint;
}

export interface LocalAuthorEpochCustodySnapshotV1 {
  readonly version: 1;
  readonly authorEpochEd25519PublicKey: Uint8Array;
  readonly authorEpochKeyRecordRevision: bigint;
  readonly roomContextId: Uint8Array;
  readonly logicalWindow: bigint;
}

/**
 * Opaque proof that one genuine retained local PRESENCE matches live local
 * stable-identity, receiver-key, and author-epoch custody.
 *
 * The handle is not a roster/set ownership proof. In particular, it says
 * nothing about omitted presences, a current Core snapshot, or authorization.
 */
export interface VerifiedLocalPresenceKeyBindingV1 {
  readonly [verifiedLocalPresenceKeyBindingBrand]: true;
}

export interface CreateVerifiedLocalPresenceKeyBindingOptionsV1 {
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly receiverCustody: LocalHelloReceiverCustodyV1;
  readonly authorEpochCustody: LocalAuthorEpochCustodyV1;
  readonly initializedRoom: OperationValidationContext;
}

export interface VerifiedLocalPresenceKeyBindingSnapshotV1 {
  readonly version: 1;
  readonly localPresenceOperationId: Uint8Array;
  readonly exactPresenceOperationBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicy: RoomPolicyV4;
  readonly presenceLogicalWindow: bigint;
  readonly provedAtLogicalWindow: bigint;
  readonly authorEpochEd25519PublicKey: Uint8Array;
  readonly authorEpochKeyRecordRevision: bigint;
  readonly advertisedReceiverHybridKemPublicKey: Uint8Array;
  readonly receiverKeyValidThroughLogicalWindow: bigint;
  readonly receiverKeyRecordRevision: bigint;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly localIdentityKeyRecordRevision: bigint;
}

export class LocalPresenceKeyBindingError extends Error {
  override readonly name = "LocalPresenceKeyBindingError";

  constructor(message: string) {
    super(`localPresenceKeyBinding: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new LocalPresenceKeyBindingError(message);
};

interface PrivateLocalAuthorEpochCustody {
  readonly module: LibCrypto;
  readonly keyMaterial: OwnedEd25519KeyMaterial;
  readonly authorEpochKeyRecordRevision: bigint;
  readonly roomContextId: Uint8Array;
  readonly logicalWindow: bigint;
}

interface PrivateVerifiedLocalPresenceKeyBinding {
  readonly localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1;
  readonly receiverCustody: LocalHelloReceiverCustodyV1;
  readonly authorEpochCustody: LocalAuthorEpochCustodyV1;
  readonly initializedRoom: OperationValidationContext;
  readonly facts: PrivateLocalPresenceKeyBindingFacts;
}

interface PrivateLocalPresenceKeyBindingFacts {
  readonly localPresenceOperationId: Uint8Array;
  readonly exactPresenceOperationBytes: Uint8Array;
  readonly roomContextId: Uint8Array;
  readonly roomPolicyBytes: Uint8Array;
  readonly presenceLogicalWindow: bigint;
  readonly provedAtLogicalWindow: bigint;
  readonly operation: AuthenticatedRoomOperationV1;
  readonly presence: PresenceV1;
  readonly authorEpochEd25519PublicKey: Uint8Array;
  readonly authorEpochKeyRecordRevision: bigint;
  readonly advertisedReceiverHybridKemPublicKey: Uint8Array;
  readonly receiverKeyValidThroughLogicalWindow: bigint;
  readonly receiverEvidenceRetainThroughLogicalWindow: bigint;
  readonly receiverKeyRecordRevision: bigint;
  readonly localStableEd25519PublicKey: Uint8Array;
  readonly localIdentityKeyRecordRevision: bigint;
  readonly module: LibCrypto;
}

const authorCustodyStates = new WeakMap<
  object,
  PrivateLocalAuthorEpochCustody
>();
const genuineAuthorCustodies = new WeakSet<object>();
const bindingStates = new WeakMap<
  object,
  PrivateVerifiedLocalPresenceKeyBinding
>();
const genuineBindings = new WeakSet<object>();

const requireU64 = (name: string, value: unknown): bigint => {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX)
    return fail(`${name} must be an unsigned 64-bit integer`);
  return value;
};

const requireAuthorCustodyState = (
  custody: LocalAuthorEpochCustodyV1,
): PrivateLocalAuthorEpochCustody => {
  if (typeof custody !== "object" || custody === null)
    return fail(
      "author-epoch custody must be a genuine live process-local handle",
    );
  const state = authorCustodyStates.get(custody);
  if (state === undefined)
    return fail(
      "author-epoch custody must be a genuine live process-local handle",
    );
  return state;
};

const copyAuthorCustodySnapshot = (
  state: PrivateLocalAuthorEpochCustody,
): LocalAuthorEpochCustodySnapshotV1 => ({
  version: 1,
  authorEpochEd25519PublicKey: Uint8Array.from(state.keyMaterial.publicKey),
  authorEpochKeyRecordRevision: state.authorEpochKeyRecordRevision,
  roomContextId: Uint8Array.from(state.roomContextId),
  logicalWindow: state.logicalWindow,
});

/**
 * Capture and validate one room/window author secret before minting custody.
 */
export const createLocalAuthorEpochCustodyV1 = async (
  options: CreateLocalAuthorEpochCustodyOptionsV1,
): Promise<LocalAuthorEpochCustodyV1> => {
  let keyMaterial: OwnedEd25519KeyMaterial | undefined;
  let transferred = false;

  try {
    const module = options.module;
    const roomContextId = snapshotByteInput(
      options.roomContextId,
      "localPresenceKeyBinding: author room context ID",
      { exactLength: 32 },
    );
    const logicalWindow = requireU64("logicalWindow", options.logicalWindow);
    const authorEpochKeyRecordRevision = requireU64(
      "authorEpochKeyRecordRevision",
      options.authorEpochKeyRecordRevision,
    );
    keyMaterial = await captureConsistentEd25519KeyMaterial({
      module,
      secretKey: options.authorEpochEd25519SecretKey,
      inputLabel: "localPresenceKeyBinding: author-epoch Ed25519 secret key",
      rejectInconsistentSecretKey: () =>
        fail("author-epoch Ed25519 secret key is inconsistent with its seed"),
    });

    const handle = Object.freeze({}) as LocalAuthorEpochCustodyV1;
    genuineAuthorCustodies.add(handle);
    authorCustodyStates.set(handle, {
      module,
      keyMaterial,
      authorEpochKeyRecordRevision,
      roomContextId,
      logicalWindow,
    });
    transferred = true;
    return handle;
  } finally {
    if (!transferred && keyMaterial !== undefined)
      wipeOwnedEd25519KeyMaterial(keyMaterial);
  }
};

/** Return a fresh non-secret projection and assert that custody is live. */
export const snapshotLocalAuthorEpochCustodyV1 = (
  custody: LocalAuthorEpochCustodyV1,
): LocalAuthorEpochCustodySnapshotV1 =>
  copyAuthorCustodySnapshot(requireAuthorCustodyState(custody));

/**
 * Wipe author-epoch custody after the corresponding local key record retires.
 *
 * Destruction is idempotent for a genuine handle. It neither owns nor retires
 * the historical receiver or stable-identity custody used by a binding.
 */
export const destroyLocalAuthorEpochCustodyV1 = (
  custody: LocalAuthorEpochCustodyV1,
): void => {
  if (
    typeof custody !== "object" ||
    custody === null ||
    !genuineAuthorCustodies.has(custody)
  )
    return fail("author-epoch custody must be a genuine process-local handle");
  const state = authorCustodyStates.get(custody);
  if (state === undefined) return;
  wipeOwnedEd25519KeyMaterial(state.keyMaterial);
  authorCustodyStates.delete(custody);
};

const captureAndValidateBindingFacts = (
  localPresenceEvidence: VerifiedHistoricalPairPresenceEvidenceV1,
  receiverCustody: LocalHelloReceiverCustodyV1,
  authorEpochCustody: LocalAuthorEpochCustodyV1,
  initializedRoom: OperationValidationContext,
): PrivateLocalPresenceKeyBindingFacts => {
  const evidence = snapshotHistoricalPairPresenceEvidence(
    localPresenceEvidence,
  );
  const receiver = snapshotLocalHelloReceiverCustodyV1(receiverCustody);
  const authorState = requireAuthorCustodyState(authorEpochCustody);
  const author = copyAuthorCustodySnapshot(authorState);
  const room = snapshotOperationValidationContext(initializedRoom);
  const roomPolicyBytes = encodeRoomPolicyV4(room.roomPolicy);

  if (
    !bytesEqual(evidence.roomContextId, room.roomContextId) ||
    !bytesEqual(receiver.roomContextId, room.roomContextId) ||
    !bytesEqual(author.roomContextId, room.roomContextId)
  )
    fail("presence and local custody must belong to the initialized room");
  if (
    !bytesEqual(encodeRoomPolicyV4(evidence.roomPolicy), roomPolicyBytes) ||
    !bytesEqual(encodeRoomPolicyV4(receiver.roomPolicy), roomPolicyBytes)
  )
    fail("presence and receiver custody must use the initialized room policy");
  if (evidence.provedAtLogicalWindow !== room.referenceWindow)
    fail(
      "presence evidence was not proved at the initialized reference window",
    );
  if (evidence.operation.logicalWindow !== author.logicalWindow)
    fail("author-epoch custody belongs to another logical window");
  if (
    !bytesEqual(
      evidence.operation.authorEpochEd25519Key,
      author.authorEpochEd25519PublicKey,
    )
  )
    fail("author-epoch custody does not match the PRESENCE author");
  if (
    !bytesEqual(
      evidence.presenceOperationId,
      receiver.localPresenceOperationId,
    ) ||
    !bytesEqual(
      evidence.exactPresenceOperationBytes,
      receiver.exactPresenceOperationBytes,
    )
  )
    fail("receiver custody is bound to another exact PRESENCE");
  if (
    !bytesEqual(
      evidence.presence.core.rendezvousHybridKemPublicKey,
      receiver.advertisedReceiverHybridKemPublicKey,
    ) ||
    evidence.presence.core.receiverKeyValidThroughLogicalWindow !==
      receiver.receiverKeyValidThroughLogicalWindow ||
    evidence.retainThroughLogicalWindow !==
      receiver.receiverEvidenceRetainThroughLogicalWindow
  )
    fail("receiver custody does not match the PRESENCE receiver key");

  return {
    localPresenceOperationId: Uint8Array.from(evidence.presenceOperationId),
    exactPresenceOperationBytes: Uint8Array.from(
      evidence.exactPresenceOperationBytes,
    ),
    roomContextId: Uint8Array.from(room.roomContextId),
    roomPolicyBytes,
    presenceLogicalWindow: evidence.operation.logicalWindow,
    provedAtLogicalWindow: evidence.provedAtLogicalWindow,
    operation: evidence.operation,
    presence: evidence.presence,
    authorEpochEd25519PublicKey: Uint8Array.from(
      author.authorEpochEd25519PublicKey,
    ),
    authorEpochKeyRecordRevision: author.authorEpochKeyRecordRevision,
    advertisedReceiverHybridKemPublicKey: Uint8Array.from(
      receiver.advertisedReceiverHybridKemPublicKey,
    ),
    receiverKeyValidThroughLogicalWindow:
      receiver.receiverKeyValidThroughLogicalWindow,
    receiverEvidenceRetainThroughLogicalWindow:
      receiver.receiverEvidenceRetainThroughLogicalWindow,
    receiverKeyRecordRevision: receiver.receiverKeyRecordRevision,
    localStableEd25519PublicKey: Uint8Array.from(
      receiver.localStableEd25519PublicKey,
    ),
    localIdentityKeyRecordRevision: receiver.localIdentityKeyRecordRevision,
    module: authorState.module,
  };
};

const sameFacts = (
  left: PrivateLocalPresenceKeyBindingFacts,
  right: PrivateLocalPresenceKeyBindingFacts,
): boolean =>
  bytesEqual(left.localPresenceOperationId, right.localPresenceOperationId) &&
  bytesEqual(
    left.exactPresenceOperationBytes,
    right.exactPresenceOperationBytes,
  ) &&
  bytesEqual(left.roomContextId, right.roomContextId) &&
  bytesEqual(left.roomPolicyBytes, right.roomPolicyBytes) &&
  left.presenceLogicalWindow === right.presenceLogicalWindow &&
  left.provedAtLogicalWindow === right.provedAtLogicalWindow &&
  bytesEqual(
    left.authorEpochEd25519PublicKey,
    right.authorEpochEd25519PublicKey,
  ) &&
  left.authorEpochKeyRecordRevision === right.authorEpochKeyRecordRevision &&
  bytesEqual(
    left.advertisedReceiverHybridKemPublicKey,
    right.advertisedReceiverHybridKemPublicKey,
  ) &&
  left.receiverKeyValidThroughLogicalWindow ===
    right.receiverKeyValidThroughLogicalWindow &&
  left.receiverEvidenceRetainThroughLogicalWindow ===
    right.receiverEvidenceRetainThroughLogicalWindow &&
  left.receiverKeyRecordRevision === right.receiverKeyRecordRevision &&
  bytesEqual(
    left.localStableEd25519PublicKey,
    right.localStableEd25519PublicKey,
  ) &&
  left.localIdentityKeyRecordRevision ===
    right.localIdentityKeyRecordRevision &&
  left.module === right.module;

const requireBindingState = (
  binding: VerifiedLocalPresenceKeyBindingV1,
): PrivateVerifiedLocalPresenceKeyBinding => {
  if (typeof binding !== "object" || binding === null)
    return fail("binding must be a genuine live process-local handle");
  const state = bindingStates.get(binding);
  if (state === undefined)
    return fail("binding must be a genuine live process-local handle");
  const liveFacts = captureAndValidateBindingFacts(
    state.localPresenceEvidence,
    state.receiverCustody,
    state.authorEpochCustody,
    state.initializedRoom,
  );
  if (!sameFacts(state.facts, liveFacts))
    return fail("retained local presence key binding changed");
  return state;
};

const copyBindingSnapshot = (
  facts: PrivateLocalPresenceKeyBindingFacts,
): VerifiedLocalPresenceKeyBindingSnapshotV1 => ({
  version: 1,
  localPresenceOperationId: Uint8Array.from(facts.localPresenceOperationId),
  exactPresenceOperationBytes: Uint8Array.from(
    facts.exactPresenceOperationBytes,
  ),
  roomContextId: Uint8Array.from(facts.roomContextId),
  roomPolicy: decodeRoomPolicyV4(facts.roomPolicyBytes),
  presenceLogicalWindow: facts.presenceLogicalWindow,
  provedAtLogicalWindow: facts.provedAtLogicalWindow,
  authorEpochEd25519PublicKey: Uint8Array.from(
    facts.authorEpochEd25519PublicKey,
  ),
  authorEpochKeyRecordRevision: facts.authorEpochKeyRecordRevision,
  advertisedReceiverHybridKemPublicKey: Uint8Array.from(
    facts.advertisedReceiverHybridKemPublicKey,
  ),
  receiverKeyValidThroughLogicalWindow:
    facts.receiverKeyValidThroughLogicalWindow,
  receiverKeyRecordRevision: facts.receiverKeyRecordRevision,
  localStableEd25519PublicKey: Uint8Array.from(
    facts.localStableEd25519PublicKey,
  ),
  localIdentityKeyRecordRevision: facts.localIdentityKeyRecordRevision,
});

/**
 * Verify one exact local PRESENCE/key relation and mint an empty opaque handle.
 *
 * Every caller-controlled byte is captured through genuine handles before the
 * ownership-signature await. The exact handles are then re-read, so retiring a
 * nested author, receiver, or stable key during verification fails closed.
 */
export const createVerifiedLocalPresenceKeyBindingV1 = async (
  options: CreateVerifiedLocalPresenceKeyBindingOptionsV1,
): Promise<VerifiedLocalPresenceKeyBindingV1> => {
  const localPresenceEvidence = options.localPresenceEvidence;
  const receiverCustody = options.receiverCustody;
  const authorEpochCustody = options.authorEpochCustody;
  const initializedRoom = options.initializedRoom;
  const facts = captureAndValidateBindingFacts(
    localPresenceEvidence,
    receiverCustody,
    authorEpochCustody,
    initializedRoom,
  );

  await validatePresenceOwnershipV1(
    facts.operation,
    facts.presence,
    facts.localStableEd25519PublicKey,
    {
      roomContextId: facts.roomContextId,
      roomPolicy: decodeRoomPolicyV4(facts.roomPolicyBytes),
    },
    facts.module,
  );

  const liveFacts = captureAndValidateBindingFacts(
    localPresenceEvidence,
    receiverCustody,
    authorEpochCustody,
    initializedRoom,
  );
  if (!sameFacts(facts, liveFacts))
    return fail("local key custody changed during presence verification");

  const handle = Object.freeze({}) as VerifiedLocalPresenceKeyBindingV1;
  genuineBindings.add(handle);
  bindingStates.set(handle, {
    localPresenceEvidence,
    receiverCustody,
    authorEpochCustody,
    initializedRoom,
    facts,
  });
  return handle;
};

/** Return fresh non-secret facts while every retained handle remains live. */
export const snapshotVerifiedLocalPresenceKeyBindingV1 = (
  binding: VerifiedLocalPresenceKeyBindingV1,
): VerifiedLocalPresenceKeyBindingSnapshotV1 =>
  copyBindingSnapshot(requireBindingState(binding).facts);

/**
 * Invalidate one binding without dereferencing its nested custody handles.
 *
 * This remains safe and idempotent after author, receiver, or stable custody
 * has already been retired and wiped.
 */
export const destroyVerifiedLocalPresenceKeyBindingV1 = (
  binding: VerifiedLocalPresenceKeyBindingV1,
): void => {
  if (
    typeof binding !== "object" ||
    binding === null ||
    !genuineBindings.has(binding)
  )
    return fail("binding must be a genuine process-local handle");
  bindingStates.delete(binding);
};
