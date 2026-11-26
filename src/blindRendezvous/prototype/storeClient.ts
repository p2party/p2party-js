/**
 * The browser-side client of one prototype store (design doc §4.4, §8).
 *
 * This is the verifying half of the carrier. The store is assumed hostile: it
 * may withhold an object it signed a receipt for, serve one window to this
 * client and another to somebody else, or answer with bytes that decode but
 * commit to nothing. Every claim it makes therefore arrives signed, and this
 * file checks each signature against the key pinned at `connect` before any
 * field of the value is read.
 *
 * Three properties this adapter is responsible for:
 *
 * - **Nothing room-derived leaves.** Every request names a delivery-profile
 *   hash, an ingress window, a size class, two ordinals, an ephemeral
 *   allocation key and opaque fixed-length bytes. There is no room, member,
 *   peer or invitation value in any path or body, which is what lets unrelated
 *   rooms share a bucket and cover for each other.
 * - **A scan never throws, and never waits forever.** A store that is
 *   unreachable, malformed, or lying must degrade one event for one store, not
 *   abort the caller's whole window. Faults are recorded and the scan answers
 *   `unreachable`. Every request also carries a deadline (see
 *   `requestDeadlineMs`), so a store that accepts the connection and then
 *   answers nothing degrades exactly the way one that refused the connection
 *   does — otherwise it would hold the carrier runtime's union open and stall
 *   the *other* store's objects with its own.
 * - **Blame is separated from absence.** `chain-fault`, `root-mismatch` and
 *   `custody-breach` mark the store **inert** — its objects are still returned
 *   so the caller can union every observed branch, but it is out of the
 *   availability set. An unreachable route, a gap in the observed chain, and a
 *   window below the chain start are none of those and mark nothing.
 *
 * Browser-safe by construction: it imports no `store/` module (those reach for
 * `node:fs` and `bun:sqlite`) and nothing Node-only. The route strings come
 * from `storeRoutes.ts`, which both halves share.
 *
 * Status: PROTOTYPE. This is the `prototype-v1` route family, not a frozen
 * registry, and nothing here is a v0.4 release artifact.
 */

import { sign, verify } from "../../cryptography/ed25519";
import {
  PROTOTYPE_READ_BACK_WINDOWS,
  PROTOTYPE_STORE_ADMISSION_TOKEN_BYTES,
  PROTOTYPE_STORE_CLIENT_MAX_IN_FLIGHT_APPENDS,
  PROTOTYPE_STORE_CLIENT_MAX_SCANNED_WINDOWS,
} from "../../utils/constants";
import { bytesEqual } from "../canonicalSchema";
import {
  allocationAppendSignedMessage,
  allocationTokenIssueResultSignedMessage,
  deliveryProfileHash,
  prototypeStoreCompatibilityHash,
  publicAllocationLeaseSignedMessage,
  publicAllocationStatusSignedMessage,
  publicAppendRequestHash,
  publicAppendResultSignedMessage,
  publicCheckpointStatusSigningHash,
  publicChunkStatusSigningHash,
  sha256,
} from "../derivations";
import {
  ZERO32,
  appendSlotCoordinates,
  checkpointLeafEntries,
  ingressWindow,
  ingressWindowStartMs,
  profileFinalizedChunkCount,
  publicChunkHash,
  publicChunkSigningHash,
  publicStoreCheckpointHash,
  publicStoreCheckpointSigningHash,
  rfc9162MerkleTreeHash,
  structurallyValidCheckpoint,
  verifyStoreCheckpointChain,
} from "../publicWindow";
import {
  descriptorChainStart,
  descriptorHash as computeDescriptorHash,
  descriptorSupportsProfile,
  publicCarrierContextId,
  storeDescriptorAuthentic,
  storeId as computeStoreId,
  validateStoreDescriptor,
  validateStoreRoute,
} from "../storeDescriptor";
import {
  PROTOTYPE_STORE_PROTOCOL,
  carrierObjectWireBytes,
  profileGeometry,
} from "./profile";
import {
  PROTOTYPE_STORE_MEDIA_TYPES,
  PROTOTYPE_STORE_ROUTES,
} from "./storeRoutes";
import {
  decodeAllocationTokenIssueResultV1,
  decodePrototypeStoreDescriptorDocumentV1,
  decodePublicAllocationResultV1,
  decodePublicAppendResultV1,
  decodePublicChunkReadV1,
  decodePublicStoreCheckpointReadV1,
  decodeStoreWitnessRecordsV1,
  encodeAllocationTokenIssueRequestV1,
  encodePublicAllocationRequestV1,
  encodePublicAppendRequestV1,
  encodeStoreWitnessRecordV1,
} from "./storeWire";

import type { LibCrypto } from "../../cryptography/libcrypto";
import type {
  ObservedStoreCheckpoint,
  PublicChunkV1,
  PublicProfileGeometry,
  PublicStoreCheckpointV1,
} from "../publicWindow";
import type { StoreDescriptorV1 } from "../storeDescriptor";
import type { DeliveryProfileV1 } from "./profile";
import type {
  PrototypeStoreDescriptorDocumentV1,
  PublicAllocationLeaseV1,
  PublicAppendAdmissionV1,
  PublicAppendRequestV1,
  PublicAppendResultV1,
  PublicChunkStatusBodyV1,
  PublicChunkStatusKindV1,
  PublicStoreCheckpointStatusBodyV1,
  PublicStoreCheckpointStatusKindV1,
  StoreWitnessRecordV1,
} from "./storeWire";

/** The routes a store may gate behind its admission hook. */
export type StoreAdmissionRoute = "allocation" | "append" | "witness";

/** What a token provider is asked for: one token, for one request. */
export interface StoreAdmissionTokenRequest {
  /** The identity this client pinned at `connect`: the token's audience. */
  readonly storeId: Uint8Array;
  readonly origin: string;
  readonly route: StoreAdmissionRoute;
  readonly ingressWindow: bigint;
}

export interface StoreAdmissionToken {
  /**
   * The store this token was issued for. The client presents it to that store
   * and no other: a token naming another identity fails the request.
   */
  readonly storeId: Uint8Array;
  /** Exactly 32 bytes. */
  readonly token: Uint8Array;
}

export type StoreAdmissionTokenProvider = (
  request: StoreAdmissionTokenRequest,
) => StoreAdmissionToken | Promise<StoreAdmissionToken>;

export interface StoreClientOptions {
  readonly origin: string;
  readonly profile: DeliveryProfileV1;
  readonly profileHash: Uint8Array;
  readonly module: LibCrypto;
  /** Injected so a test, a worker or a proxy can supply its own transport. */
  readonly fetch?: typeof fetch;
  readonly nowMs: () => bigint;
  /**
   * Admission tokens for a store that gates its routes. Absent, the client
   * runs open admission: 32 zero bytes in the allocation body and no
   * `authorization` header. Present, every allocation, append and witness
   * offer asks it first and presents what it returns — in the allocation
   * body's `privacyPassToken`, and as `authorization: Bearer <hex>` on append
   * and witness. A provider that fails, or returns a token issued for another
   * store or of the wrong length, fails that request with
   * `StoreAdmissionTokenError` before anything is sent; it never falls back
   * to an unauthenticated request.
   */
  readonly admissionTokens?: StoreAdmissionTokenProvider;
}

/**
 * What a scan or request found wrong with one store's answer.
 *
 * `unreachable` is a transport failure: a fetch that was rejected outright, a
 * request that outlived its own deadline (`requestDeadlineMs`), a non-200
 * status, a missing or wrong `x-p2party-store` header, or bytes that
 * do not even decode as the expected canonical type. None of these yields a
 * signature this client could check, so none of them says anything about
 * whether the store is honest — only that this attempt produced no usable
 * answer, which a store that is merely switched off produces exactly as
 * reliably as one that is actively cheating. It is therefore never grounds
 * for `inert`: the store may come back.
 *
 * The next four are blame, and each is decided from the store's signed
 * statements alone, never from this client's clock and whatever the validity
 * of the descriptor: the record's `evidence` (the signed answers) with its
 * `descriptor` (the one they name by hash) proves the fault to anyone
 * (`signedStatusProvesFault`). Each sets `inert`. `judgeSignedRefusal` holds
 * the order they are decided in.
 *
 * `retention-breach`: the store signed `out-of-range` for a window at or
 * after its chain start, and the answer's own signed current window puts that
 * window inside the retention the store's signed descriptor states. The same
 * answer for a window the store's own window puts past that retention is
 * expiry, not blame: the scan says `beyond-retention`.
 *
 * `finalization-breach`: the store signed `not-final` for a window at or
 * after its chain start when its own signed window began at or after that
 * window's finalization instant (`chunkFinalizationOffsetMs` into it), the
 * instant from which the store's rule (`#closedOnClock`) no longer lets it
 * say so.
 *
 * `chain-denial-breach`: the store signed `chain-unavailable` for a profile
 * its descriptor declares a chain for. A store signs that status only for a
 * profile it does not serve, so no window and no clock makes it true.
 *
 * `chunk-denial-breach`: the store signed `no-such-chunk` for a chunk the
 * profile defines, in a window it signed a checkpoint for. The checkpoint
 * commits to every chunk of the profile, so the two statements contradict
 * each other; the record keeps both, the checkpoint read first.
 *
 * `store-clock-disagreement` is a report: a signed refusal that proves no
 * fault, and that no store whose clock is within the profile's
 * `maxScheduleSkewMs` of this client's could honestly have signed while the
 * request was out. Either the window the store states is one no such clock
 * showed (`storeWindowWithinSkewOfRead`), or the status is `not-final` and
 * the request left at or after the window's finalization instant plus the
 * skew. Expiry or "not yet" cannot then be told from a store lying about its
 * time, and a third party cannot check when the answer was given, so it is no
 * blame: the scan says `clock-disagreement`, the window is not read at this
 * store this time, and the store is asked again on later reads (an honest
 * store whose clock is set right recovers).
 *
 * `descriptor-out-of-validity` is a report: the descriptor this client pinned
 * does not cover the read. Either a signed refusal states a store window
 * that is not wholly inside the descriptor's validity, or this client's own
 * clock was outside that validity while the request was out. A refusal that
 * proves a fault is blamed first; nothing else from such a read is believed
 * or served, and the scan says `descriptor-out-of-validity`.
 *
 * `custody-unchecked` is a report: receipts for a window this client could not
 * read back (expired or withheld) were not checked, rather than dropped
 * without a word.
 *
 * `custody-unacknowledged` is a report, not blame: an append with a lease was
 * still unanswered when this client read its window. It never sets `inert`.
 * If the store later signs `stored` for it, that receipt is judged against the
 * read already made, and a slot that did not hold the object is a
 * `custody-breach` however late the promise arrived.
 *
 * `signature-invalid` is reserved for an answer this client *could* judge:
 * bytes that decoded as the expected type, carrying a signature, which either
 * does not verify under the pinned descriptor key or verifies but names the
 * wrong store, profile, window or version — a well-formed, signed answer to a
 * different question than the one this client asked. A response that decodes
 * and verifies but names the wrong coordinates is deliberately kept here
 * rather than folded into `unreachable`: the store was reachable and spent a
 * real signature over real bytes, which is closer to "signed something
 * false" than to absence, even when the mistake reads as a mismatch rather
 * than an outright forgery. What must never happen is the reverse — a store
 * that said nothing at all ending up in the same bucket as one that signed a
 * lie.
 */
export type StoreFaultKind =
  | "unreachable"
  | "descriptor-invalid"
  | "signature-invalid"
  | "chain-fault"
  | "root-mismatch"
  | "custody-breach"
  | "retention-breach"
  | "finalization-breach"
  | "chain-denial-breach"
  | "chunk-denial-breach"
  | "store-clock-disagreement"
  | "descriptor-out-of-validity"
  | "custody-unacknowledged"
  | "custody-unchecked"
  | "checkpoint-split-view-hint";

export interface StoreFaultRecord {
  readonly storeIdHex: string;
  readonly kind: StoreFaultKind;
  readonly window: bigint | null;
  readonly detail: string;
  /**
   * The store's own signed answers, canonical bytes, that prove the fault:
   * one status for a `retention-breach`, `finalization-breach` or
   * `chain-denial-breach`; the finalized checkpoint read and then the chunk
   * status that denies one of its chunks for a `chunk-denial-breach`. It is
   * the `evidence` argument of `signedStatusProvesFault`, as it stands.
   */
  readonly evidence?: readonly Uint8Array[];
  /**
   * The descriptor the answers name by `descriptorHash`, kept with them so the
   * evidence is checkable without anything this client might later drop. The
   * delivery profile is not kept: the signed answers name it by hash, and the
   * verifier refuses any other.
   */
  readonly descriptor?: StoreDescriptorV1;
}

/** Faults that make a store inert; they never compete with reports for room. */
const BLAME_FAULT_KINDS: ReadonlySet<StoreFaultKind> = new Set([
  "chain-fault",
  "root-mismatch",
  "custody-breach",
  "retention-breach",
  "finalization-breach",
  "chain-denial-breach",
  "chunk-denial-breach",
]);

/**
 * What one fixed scan of one window came back with.
 *
 * `status` is deliberately **not** the `StoreFaultKind` taxonomy, and the two
 * are not in one-to-one correspondence. `unreachable` here means only "this
 * scan produced no usable window", and it is what a switched-off store, a
 * stalled store, a malformed answer *and* a proved `root-mismatch` breach all
 * come back as — see the `#breach` call in `scanWindow`. The `f1f5aa4` split
 * between absence and blame lives in `StoreFaultKind` and in `inert`, which is
 * where every consumer reads it: a breach records `root-mismatch` and sets
 * `inert` permanently, while absence records `unreachable` and sets nothing.
 * Nothing in the tree branches on this field to decide blame — the carrier
 * runtime uses it as `status === "finalized"` to count usable carriers and to
 * gate a witness post, and to say why a window was missed at a store — so a
 * status for a breach would add a value with no reader. Recorded here rather
 * than fixed, because a taxonomy documented in one place and contradicted in
 * another is the defect; if a consumer ever does need to tell a breached
 * window from an absent one, it should read `inert` and the fault list, not
 * this string.
 *
 * The statuses a signed refusal can end in are the ones `judgeSignedRefusal`
 * names: `beyond-retention` and `not-final` are the two benign ones, and
 * `clock-disagreement` and `descriptor-out-of-validity` each come with a
 * fault record of the matching kind. `out-of-range` is never a store's
 * answer: it is this client's own word for a window below the chain start,
 * for which no request is made. `descriptor-out-of-validity` is also what a
 * window that was served whole comes back as when this client's clock was
 * outside the pinned descriptor's validity during the read.
 */
export interface WindowScan {
  readonly window: bigint;
  readonly status:
    | "finalized"
    | "not-final"
    | "out-of-range"
    | "beyond-retention"
    | "clock-disagreement"
    | "descriptor-out-of-validity"
    | "unreachable";
  readonly objects: readonly Uint8Array[];
  readonly checkpointHash: Uint8Array | null;
}

/**
 * What this client appended and the store signed for, kept until the window it
 * names is scanned. It is the whole input to the custody check: without the
 * lease's ordinal there is no slot to look in, and without `objectHash` there
 * is nothing to compare the slot's contents against.
 */
export interface AppendReceipt {
  readonly window: bigint;
  readonly sizeClass: number;
  readonly lease: PublicAllocationLeaseV1;
  readonly objectOrdinal: number;
  readonly objectHash: Uint8Array;
  readonly result: PublicAppendResultV1;
}

export class StoreClientError extends Error {
  // Widened to `string` so `StoreAdmissionTokenError` can narrow it.
  override readonly name: string = "StoreClientError";

  constructor(message: string) {
    super(`storeClient: ${message}`);
  }
}

/**
 * A request this client refused to send because its admission token could
 * not be had: the provider failed, or returned a token for another store or of
 * the wrong length. The message never quotes a token.
 */
export class StoreAdmissionTokenError extends StoreClientError {
  override readonly name = "StoreAdmissionTokenError";
}

/**
 * The store speaks another version of the prototype protocol: its answer
 * carries an `x-p2party-store` value other than this client's
 * `PROTOTYPE_STORE_PROTOCOL`. `connect` refuses it before reading anything
 * the store signed, since every route, media type and signed body of another
 * version differs from this one's. A store of the previous version answers
 * this client's descriptor path with its own 404, which is how this is met
 * in practice.
 */
export class StoreVersionError extends StoreClientError {
  override readonly name = "StoreVersionError";
  /** The version the store's answer names. */
  readonly storeProtocol: string;
  /** The version this client speaks. */
  readonly clientProtocol: string = PROTOTYPE_STORE_PROTOCOL;

  constructor(storeProtocol: string) {
    super(
      `the store speaks ${storeProtocol}, and this client speaks ${PROTOTYPE_STORE_PROTOCOL}`,
    );
    this.storeProtocol = storeProtocol;
  }
}

/**
 * The store's signed descriptor states a retention shorter than this client
 * reads back (`PROTOTYPE_READ_BACK_WINDOWS`). A client that used it would ask
 * for windows the store has let expire, so `connect` refuses it.
 */
export class StoreRetentionError extends StoreClientError {
  override readonly name = "StoreRetentionError";
}

const fail: (message: string) => never = (message) => {
  throw new StoreClientError(message);
};

/**
 * How many faults one client remembers, of each of two kinds.
 *
 * The earliest faults are the evidence — every one that matters is acted on
 * (`inert`) the instant it is recorded — so each cap keeps the first ones and
 * drops later repetitions rather than the other way round. A browser tab that
 * scans a store for hours must not accumulate one record per failed fetch.
 * Blame (`BLAME_FAULT_KINDS`) and reports have separate caps, so no number of
 * reports — a slow honest store's `custody-unacknowledged`, a flaky network's
 * `unreachable` — can crowd out a breach.
 */
const MAX_RECORDED_FAULTS = 512;

/**
 * How many checkpoint observations this client keeps for the chain verifier.
 *
 * A scan checks only what its own checkpoint adds to the verified run (see
 * `#verifyChain`), and `verifyStoreCheckpointChain` re-verifies every kept
 * observation only when the run has to be rebuilt, so this bounds memory and
 * the cost of a rebuild. Dropping the oldest cannot hide a fault: a conflict
 * or a breach is detected by the scan that first observes it and `inert` is
 * permanent from that moment.
 */
const MAX_OBSERVED_CHECKPOINTS = 256;

/** Receipts are consumed by the scan of their window; this bounds the rest. */
const MAX_PENDING_RECEIPTS = 1_024;

/** Appends with a lease still waiting for their answer. */
const MAX_IN_FLIGHT_APPENDS = PROTOTYPE_STORE_CLIENT_MAX_IN_FLIGHT_APPENDS;

/**
 * Scanned windows whose slot hashes are kept for receipts that arrive after
 * the scan. An answer can arrive at most one request deadline (one window)
 * after its append was sent, and a window is read the window after it, so a
 * receipt is late by a couple of windows at most; sixteen is margin, at about
 * 1.3 KB a window in the pinned profile. The same bound applies to the windows
 * remembered as unreadable, whose late receipts are reported unchecked.
 */
const MAX_SCANNED_WINDOWS = PROTOTYPE_STORE_CLIENT_MAX_SCANNED_WINDOWS;

const ADMISSION_TOKEN_BYTES = PROTOTYPE_STORE_ADMISSION_TOKEN_BYTES;

/**
 * `IngressWindowStart(window) + chunkFinalizationOffsetMs`: the instant from
 * which a window is final. It is the store's own bound (`#closedOnClock` in
 * the store core signs `not-final` only before it), and the one instant every
 * judgment of a `not-final` here is taken from.
 */
export const windowFinalizationInstantMs = (
  window: bigint,
  profile: DeliveryProfileV1,
): bigint =>
  ingressWindowStartMs(window, profile.deliveryWindowMs) +
  profile.chunkFinalizationOffsetMs;

/**
 * This client's clock while one read was out: when its requests left, and
 * when the last of their answers was in. The store signed each answer at some
 * instant between the two.
 */
export interface StoreReadSpan {
  readonly sentMs: bigint;
  readonly receivedMs: bigint;
}

/**
 * Whether a store whose clock is within the profile's `maxScheduleSkewMs` of
 * this client's could have read `storeWindow` off it while the request was
 * out: some instant from `sentMs - skew` to `receivedMs + skew` lies in that
 * window. Counted in milliseconds, not whole windows: at the pinned profile
 * (200 ms of skew against a 4,000 ms window) a store may state the window
 * next to this client's only within 200 ms of the edge between them.
 */
export const storeWindowWithinSkewOfRead = (
  storeWindow: bigint,
  read: StoreReadSpan,
  profile: DeliveryProfileV1,
): boolean => {
  const skew = profile.maxScheduleSkewMs;
  const earliestMs = read.sentMs > skew ? read.sentMs - skew : 0n;
  return (
    ingressWindow(profile.deliveryWindowMs, earliestMs) <= storeWindow &&
    storeWindow <=
      ingressWindow(profile.deliveryWindowMs, read.receivedMs + skew)
  );
};

/**
 * Whether a signed `out-of-range` for `window`, given when the store's own
 * current window was `storeWindow`, contradicts what the store states about
 * itself: a window at or after its chain start is served while it is not
 * yet past (`window > storeWindow`) and through the end of
 * `window + retentionWindows`, as `bucketIsReadable` defines it.
 */
export const outOfRangeContradictsRetention = (
  window: bigint,
  storeWindow: bigint,
  chainStart: bigint,
  retentionWindows: number,
): boolean =>
  window >= chainStart &&
  (window > storeWindow || storeWindow - window <= BigInt(retentionWindows));

/**
 * Whether a signed `not-final` for `window`, given when the store's own
 * current window was `storeWindow`, contradicts the store's rule for it: a
 * window at or after the chain start is final from
 * `windowFinalizationInstantMs`, and a store whose window has begun at or
 * after that instant has no moment left in it at which `not-final` was true.
 * At the pinned profile that is any `storeWindow` past `window`.
 */
export const notFinalContradictsFinalization = (
  window: bigint,
  storeWindow: bigint,
  chainStart: bigint,
  profile: DeliveryProfileV1,
): boolean =>
  window >= chainStart &&
  ingressWindowStartMs(storeWindow, profile.deliveryWindowMs) >=
    windowFinalizationInstantMs(window, profile);

/**
 * Whether `descriptor` was valid at every instant of `window`, so at
 * whichever one a store signed an answer stating that window. Validity is
 * half-open, `[notBeforeUnixMs, notAfterUnixMs)`, as `storeDescriptorActiveAt`
 * decides it.
 */
export const descriptorValidThroughWindow = (
  descriptor: StoreDescriptorV1,
  window: bigint,
  deliveryWindowMs: bigint,
): boolean =>
  descriptor.notBeforeUnixMs <=
    ingressWindowStartMs(window, deliveryWindowMs) &&
  ingressWindowStartMs(window + 1n, deliveryWindowMs) <=
    descriptor.notAfterUnixMs;

/**
 * Whether `descriptor` was valid on this client's clock for the whole time a
 * read was out, by the same half-open rule.
 */
export const descriptorValidThroughRead = (
  descriptor: StoreDescriptorV1,
  read: StoreReadSpan,
): boolean =>
  descriptor.notBeforeUnixMs <= read.sentMs &&
  read.receivedMs < descriptor.notAfterUnixMs;

/** The faults a store's own signed answers can prove against it. */
export type StoreEvidenceFaultKind =
  | "retention-breach"
  | "finalization-breach"
  | "chain-denial-breach"
  | "chunk-denial-breach";

interface SignedStoreStatusWindows {
  readonly deliveryProfileHash: Uint8Array;
  /** The window the status is about. */
  readonly window: bigint;
  /** The store's own current window when it signed. */
  readonly storeWindow: bigint;
}

/** What a signed status states, read after its signature verified. */
export type SignedStoreStatusStatement =
  | (SignedStoreStatusWindows & {
      readonly route: "checkpoint";
      readonly status: PublicStoreCheckpointStatusKindV1;
    })
  | (SignedStoreStatusWindows & {
      readonly route: "chunk";
      readonly status: PublicChunkStatusKindV1;
      readonly sizeClass: number;
      readonly chunkIndex: bigint;
    });

/** Whether `profile` defines chunk `chunkIndex` of class `sizeClass`. */
const profileDefinesChunk = (
  profile: DeliveryProfileV1,
  sizeClass: number,
  chunkIndex: bigint,
): boolean => {
  const found = profile.sizeClasses.find(
    (candidate) => candidate.id === sizeClass,
  );
  return (
    found !== undefined && chunkIndex < BigInt(found.publicChunksPerWindow)
  );
};

/**
 * The fault a verified status proves against the descriptor it names, or
 * `null`. One rule for this client's own judgment and for
 * `signedStatusProvesFault`, so the client never blames what a third party
 * would not.
 *
 * The descriptor's validity is not consulted: the statement names its
 * descriptor by hash, so it is judged under that descriptor wherever its
 * stated window lies, and a store cannot excuse a refusal by stating a window
 * its descriptor does not cover. No honest store is blamed for that. The
 * store core signs `out-of-range` only for a window outside the retention of
 * the descriptor it names, `not-final` only before the window's finalization
 * instant, `chain-unavailable` only for a profile that descriptor does not
 * declare, and `no-such-chunk` only for coordinates its profile does not
 * define, whatever its clock reads.
 *
 * `profile` must be the profile `statement.deliveryProfileHash` names (the
 * client pins it; the verifier checks it). `checkpointCommitsWindow` says the
 * caller holds a checkpoint this store signed for the statement's window and
 * profile, which is what turns a `no-such-chunk` into a contradiction.
 */
export const signedStatusContradiction = (
  statement: SignedStoreStatusStatement,
  descriptor: StoreDescriptorV1,
  profile: DeliveryProfileV1,
  checkpointCommitsWindow = false,
): StoreEvidenceFaultKind | null => {
  const chainStart = descriptorChainStart(
    descriptor,
    statement.deliveryProfileHash,
  );
  // No chain declared for this profile: `chain-unavailable` is then the
  // truth, and no other status says anything this descriptor contradicts.
  if (chainStart === null) return null;
  switch (statement.status) {
    case "chain-unavailable":
      return "chain-denial-breach";
    case "out-of-range":
      return outOfRangeContradictsRetention(
        statement.window,
        statement.storeWindow,
        chainStart,
        descriptor.retentionWindows,
      )
        ? "retention-breach"
        : null;
    case "not-final":
      return notFinalContradictsFinalization(
        statement.window,
        statement.storeWindow,
        chainStart,
        profile,
      )
        ? "finalization-breach"
        : null;
    case "no-such-chunk":
      return checkpointCommitsWindow &&
        statement.route === "chunk" &&
        profileDefinesChunk(profile, statement.sizeClass, statement.chunkIndex)
        ? "chunk-denial-breach"
        : null;
  }
};

/** Where `judgeSignedRefusal` ended, and in what. */
export type SignedRefusalJudgment =
  | { readonly step: 3; readonly outcome: StoreEvidenceFaultKind }
  | { readonly step: 4 | 6; readonly outcome: "store-clock-disagreement" }
  | { readonly step: 5; readonly outcome: "descriptor-out-of-validity" }
  | {
      readonly step: 7;
      readonly outcome: "beyond-retention" | "not-final" | "no-benign-meaning";
    };

/**
 * The one decision order for every signed refusal a read can be answered
 * with: both routes (`checkpoint` and `chunk`), every status, a
 * scheduled read and a catch-up read alike. `PrototypeStoreClient` does
 * steps 1 and 2 (`#judgeSignedRefusal`) and then calls this for the rest.
 *
 * 1. The answer decodes, is version 1, verifies under the pinned key, and
 *    names this store, profile and window (and, for a chunk, the class and
 *    index asked for). Otherwise `signature-invalid`, a report.
 * 2. It names the pinned descriptor by hash. Otherwise `signature-invalid`,
 *    a report: a descriptor this client does not hold could state anything.
 * 3. It contradicts the store's own signed statements
 *    (`signedStatusContradiction`). Blame under the fault's own name, the
 *    evidence kept with the descriptor, the store inert. Decided before any
 *    clock or validity is looked at, so neither can excuse it.
 * 4. The window it states is one no clock within the profile's skew of this
 *    client's showed while the request was out
 *    (`storeWindowWithinSkewOfRead`). `store-clock-disagreement`: a report,
 *    the window missed at this store this time.
 * 5. The pinned descriptor does not cover the whole stated window
 *    (`descriptorValidThroughWindow`), or was not valid on this client's
 *    clock while the request was out (`descriptorValidThroughRead`).
 *    `descriptor-out-of-validity`: a report, the window missed at this store.
 * 6. This client's own clock rules the status out. `not-final`: the request
 *    left at or after `windowFinalizationInstantMs + maxScheduleSkewMs`, so a
 *    store within the skew read its clock at or after the finalization
 *    instant and could not sign it. `store-clock-disagreement`, as in step 4.
 *    `out-of-range` has no such step: after 3 and 4 the stated window is past
 *    the retention and is one a store within the skew could have read.
 * 7. Only then the status's own meaning.
 *
 * Which step can end each status, and in what (W the window asked for, S the
 * window the store states, R and the chain start from the descriptor):
 *
 * | status              | route      | 3 blame                                   | 4 | 5 | 6                              | 7 benign           |
 * | ------------------- | ---------- | ----------------------------------------- | - | - | ------------------------------ | ------------------ |
 * | `out-of-range`      | both       | `retention-breach` if W > S or S - W <= R | x | x | none                           | `beyond-retention` |
 * | `not-final`         | both       | `finalization-breach` if                  | x | x | `store-clock-disagreement` if  | `not-final`        |
 * |                     |            | start(S) >= fin(W)                        |   |   | sent >= fin(W) + skew          |                    |
 * | `chain-unavailable` | checkpoint | `chain-denial-breach`, always             | - | - | -                              | none               |
 * | `no-such-chunk`     | chunk      | `chunk-denial-breach`, always             | - | - | -                              | none               |
 *
 * `x`: the step applies (4 ends in `store-clock-disagreement`, 5 in
 * `descriptor-out-of-validity`). `-`: never reached, because step 3 always
 * ends the status for a read this client makes: every window it asks for is
 * at or after the chain start of a profile the pinned descriptor declares,
 * every chunk it asks for is one the profile defines, and a chunk status is
 * judged only after the same scan verified that window's checkpoint. For any
 * other input the last row holds too: a status with no benign meaning ends
 * in `no-benign-meaning`, which the client records as `signature-invalid`.
 *
 * The benign outcomes are exactly the answers an honest store whose clock is
 * within the skew of this client's can sign while the request is out, under
 * a descriptor valid then: `out-of-range` iff its window S is past W + R, and
 * `not-final` iff its clock reads before fin(W), which needs S's start before
 * fin(W) (step 3) and the request sent before fin(W) + skew (step 6). So such
 * a store is never blamed and never reported, at any read time. At a read the
 * carrier runtime makes, `not-final` is never benign: the profile's rule
 * `chunkFinalizationOffsetMs + maxScheduleSkewMs < deliveryWindowMs +
 * publicReadOffsetMs` puts every read of W after fin(W) + skew.
 */
export const judgeSignedRefusal = (
  statement: SignedStoreStatusStatement,
  descriptor: StoreDescriptorV1,
  profile: DeliveryProfileV1,
  read: StoreReadSpan,
  checkpointCommitsWindow: boolean,
): SignedRefusalJudgment => {
  const fault = signedStatusContradiction(
    statement,
    descriptor,
    profile,
    checkpointCommitsWindow,
  );
  if (fault !== null) return { step: 3, outcome: fault };

  if (!storeWindowWithinSkewOfRead(statement.storeWindow, read, profile))
    return { step: 4, outcome: "store-clock-disagreement" };

  if (
    !descriptorValidThroughWindow(
      descriptor,
      statement.storeWindow,
      profile.deliveryWindowMs,
    ) ||
    !descriptorValidThroughRead(descriptor, read)
  )
    return { step: 5, outcome: "descriptor-out-of-validity" };

  if (
    statement.status === "not-final" &&
    read.sentMs >=
      windowFinalizationInstantMs(statement.window, profile) +
        profile.maxScheduleSkewMs
  )
    return { step: 6, outcome: "store-clock-disagreement" };

  // A profile the descriptor declares no chain for has no window to expire
  // or to be not yet final.
  const declared =
    descriptorChainStart(descriptor, statement.deliveryProfileHash) !== null;
  if (declared && statement.status === "out-of-range")
    return { step: 7, outcome: "beyond-retention" };
  if (declared && statement.status === "not-final")
    return { step: 7, outcome: "not-final" };
  return { step: 7, outcome: "no-benign-meaning" };
};

/**
 * A signed status read out of evidence bytes, with what its signature is
 * over. `null` when the bytes are neither status, or are not version 1.
 */
const decodeStatusEvidence = async (
  bytes: Uint8Array,
): Promise<{
  readonly statement: SignedStoreStatusStatement;
  /** The store the status names; a chunk status names none. */
  readonly storeId: Uint8Array | null;
  readonly descriptorHash: Uint8Array;
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
} | null> => {
  try {
    const read = decodePublicStoreCheckpointReadV1(bytes);
    if (read.kind !== "status" || read.value.version !== 1) return null;
    return {
      statement: {
        route: "checkpoint",
        status: read.value.status,
        deliveryProfileHash: read.value.deliveryProfileHash,
        window: read.value.ingressWindow,
        storeWindow: read.value.storeIngressWindow,
      },
      storeId: read.value.storeId,
      descriptorHash: read.value.descriptorHash,
      message: await publicCheckpointStatusSigningHash(read.value),
      signature: read.storeSignature,
    };
  } catch {
    // Not a checkpoint read: a chunk read, or nothing.
  }
  try {
    const read = decodePublicChunkReadV1(bytes);
    if (read.kind !== "status" || read.value.version !== 1) return null;
    return {
      statement: {
        route: "chunk",
        status: read.value.status,
        deliveryProfileHash: read.value.bucket.deliveryProfileHash,
        window: read.value.bucket.ingressWindow,
        storeWindow: read.value.storeIngressWindow,
        sizeClass: read.value.bucket.sizeClass,
        chunkIndex: read.value.chunkIndex,
      },
      storeId: null,
      descriptorHash: read.value.descriptorHash,
      message: await publicChunkStatusSigningHash(read.value),
      signature: read.storeSignature,
    };
  } catch {
    return null;
  }
};

/**
 * Check a fault record's `evidence` with nothing but the `descriptor` kept
 * beside it and the delivery profile. Returns the fault proved, or `null`.
 * No clock is consulted and the descriptor's validity is not a condition, so
 * the verdict is the same for anyone, at any time.
 *
 * `evidence` is one signed status, or a finalized checkpoint read and then a
 * chunk status. It proves a fault when:
 *
 * - the descriptor is authentic;
 * - `profile` is the profile the signed answers name. Every status and
 *   checkpoint carries `deliveryProfileHash` inside its signed body, and this
 *   recomputes `DeliveryProfileHash(profile)` and refuses any other profile,
 *   which is why a fault record does not need to hold one;
 * - the status is version 1, names this descriptor by hash (and, for a
 *   checkpoint status, this descriptor's store), names a chunk the profile
 *   defines if it is a chunk status, and verifies under the descriptor's key;
 * - a checkpoint beside it is version 1, names this store, this profile, the
 *   status's window and the profile's fixed chunk count, and verifies under
 *   the same key. It may name an earlier descriptor of the same store: the
 *   contradiction is between two statements of one key about one window;
 * - `signedStatusContradiction` holds: `retention-breach`,
 *   `finalization-breach` and `chain-denial-breach` from the status alone,
 *   `chunk-denial-breach` from a `no-such-chunk` with its checkpoint.
 */
export const signedStatusProvesFault = async (
  descriptor: StoreDescriptorV1,
  profile: DeliveryProfileV1,
  evidence: readonly Uint8Array[],
  module: LibCrypto,
): Promise<StoreEvidenceFaultKind | null> => {
  if (evidence.length !== 1 && evidence.length !== 2) return null;
  if (!(await storeDescriptorAuthentic(descriptor, module)).valid) return null;
  const profileHashBytes = await deliveryProfileHash(profile);
  const descriptorHashBytes = await computeDescriptorHash(descriptor);
  const storeIdBytes = await computeStoreId(descriptor.storeIdentityEd25519Key);

  const status = await decodeStatusEvidence(evidence[evidence.length - 1]);
  if (status === null) return null;
  const { statement } = status;
  if (
    !bytesEqual(statement.deliveryProfileHash, profileHashBytes) ||
    !bytesEqual(status.descriptorHash, descriptorHashBytes) ||
    (status.storeId !== null && !bytesEqual(status.storeId, storeIdBytes))
  )
    return null;
  // A chunk the profile does not define is never withheld, whatever the
  // store calls its absence.
  if (
    statement.route === "chunk" &&
    !profileDefinesChunk(profile, statement.sizeClass, statement.chunkIndex)
  )
    return null;
  if (
    !(await verify(
      status.message,
      status.signature,
      descriptor.storeIdentityEd25519Key,
      module,
    ))
  )
    return null;

  let checkpointCommitsWindow = false;
  if (evidence.length === 2) {
    // Only a chunk status stands beside a checkpoint.
    if (statement.route !== "chunk") return null;
    let read: ReturnType<typeof decodePublicStoreCheckpointReadV1>;
    try {
      read = decodePublicStoreCheckpointReadV1(evidence[0]);
    } catch {
      return null;
    }
    if (read.kind !== "finalized") return null;
    const { storeSignature, ...body } = read.checkpoint;
    if (
      body.version !== 1 ||
      !bytesEqual(body.storeId, storeIdBytes) ||
      !bytesEqual(body.deliveryProfileHash, profileHashBytes) ||
      body.ingressWindow !== statement.window ||
      body.finalizedChunkCount !==
        profileFinalizedChunkCount(profileGeometry(profile)) ||
      !(await verify(
        await publicStoreCheckpointSigningHash(body),
        storeSignature,
        descriptor.storeIdentityEd25519Key,
        module,
      ))
    )
      return null;
    checkpointCommitsWindow = true;
  }
  return signedStatusContradiction(
    statement,
    descriptor,
    profile,
    checkpointCommitsWindow,
  );
};

const copyDescriptor = (descriptor: StoreDescriptorV1): StoreDescriptorV1 => ({
  version: descriptor.version,
  storeIdentityEd25519Key: copyBytes(descriptor.storeIdentityEd25519Key),
  allocationIssuerPublicKeyDer: copyBytes(
    descriptor.allocationIssuerPublicKeyDer,
  ),
  descriptorGeneration: descriptor.descriptorGeneration,
  compatibilityHash: copyBytes(descriptor.compatibilityHash),
  supportedDeliveryProfileHashes:
    descriptor.supportedDeliveryProfileHashes.map(copyBytes),
  checkpointChainStarts: descriptor.checkpointChainStarts.map((start) => ({
    deliveryProfileHash: copyBytes(start.deliveryProfileHash),
    chainStartIngressWindow: start.chainStartIngressWindow,
  })),
  retentionWindows: descriptor.retentionWindows,
  notBeforeUnixMs: descriptor.notBeforeUnixMs,
  notAfterUnixMs: descriptor.notAfterUnixMs,
  descriptorSignature: copyBytes(descriptor.descriptorSignature),
});

/**
 * How long one request to this store may stay outstanding, in milliseconds.
 *
 * **One delivery window**, taken from the profile rather than pinned as a
 * number, because the schedule is what makes the value meaningful. Every
 * request this client sends belongs to exactly one ingress window, and the
 * fixed schedule reissues the identical request one window later; an answer
 * that arrives after its own successor was due can no longer change anything.
 * A read has by then been superseded by the next window's read. An
 * append is long past `chunkFinalizationOffsetMs` — 2,800 ms of 4,000
 * in the pinned profile — so the store would answer `window-finalized` to it
 * anyway. A token or an allocation names a window whose appends have already
 * gone out as unallocated cover.
 *
 * It is also strictly longer than every budget the profile itself sets for an
 * answer (`tokenIssueResponseBudgetMs` and `allocationResponseBudgetMs`, 300 ms
 * each in the pinned profile, plus `maxScheduleSkewMs` 200), so it can never
 * abort a request the profile considers on time; and it scales with the
 * geometry, so `--window-ms=1000` gives a 1,000 ms deadline rather than a
 * constant that silently stops fitting.
 *
 * One value for every route, deliberately: the profile sets no per-route
 * budget for appends, chunks, or checkpoints, so there is no geometry to
 * derive a per-route deadline from, and one value is simpler than inventing
 * budgets that would need their own justification.
 *
 * Without a deadline, a store that accepts the connection and never answers
 * holds `scanWindow` open forever, and because the carrier runtime joins both
 * stores' scans under one `Promise.all` that stalls the honest store's objects
 * too — the cheapest way to falsify "either store may fail and the rendezvous
 * still completes", and the one fault mode neither E2E scenario exercises
 * (a killed store refuses the connection, and `withhold` lies at full speed).
 */
const requestDeadlineMs = (profile: DeliveryProfileV1): number => {
  const deadline = Number(profile.deliveryWindowMs);
  if (!Number.isSafeInteger(deadline) || deadline <= 0)
    fail(
      "the delivery profile's window length is not a usable request deadline",
    );
  return deadline;
};

const textDecoder = new TextDecoder("utf-8", { fatal: true });

/**
 * The call signature of `fetch`, without the properties hung off the global.
 *
 * The default is a wrapper rather than the global itself because an unbound
 * `fetch` invoked as a method throws "Illegal invocation" in several engines;
 * this type is what lets the wrapper stand in for one without a cast.
 */
type StoreTransport = (...args: Parameters<typeof fetch>) => Promise<Response>;

const transportOf = (options: StoreClientOptions): StoreTransport =>
  options.fetch ?? ((...args) => globalThis.fetch(...args));

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const copyBytes = (value: Uint8Array): Uint8Array => Uint8Array.from(value);

const copyLease = (
  lease: PublicAllocationLeaseV1,
): PublicAllocationLeaseV1 => ({
  version: lease.version,
  storeId: copyBytes(lease.storeId),
  deliveryProfileHash: copyBytes(lease.deliveryProfileHash),
  ingressWindow: lease.ingressWindow,
  requestHash: copyBytes(lease.requestHash),
  allocationOrdinal: lease.allocationOrdinal,
  allocationEd25519PublicKey: copyBytes(lease.allocationEd25519PublicKey),
  storeSignature: copyBytes(lease.storeSignature),
});

/** `${sizeClass}:${chunkIndex}:${objectIndexWithinChunk}` */
const slotKeyOf = (
  sizeClass: number,
  chunkIndex: bigint,
  objectIndexWithinChunk: number,
): string =>
  `${String(sizeClass)}:${String(chunkIndex)}:${String(objectIndexWithinChunk)}`;

/** An append with a lease, sent and not yet answered. */
interface InFlightAppend {
  readonly window: bigint;
  readonly slotKey: string;
  /** Set once the window's scan has reported it unacknowledged. */
  reported: boolean;
}

const copyWitnessRecord = (
  record: StoreWitnessRecordV1,
): StoreWitnessRecordV1 => ({
  version: record.version,
  witnessedStoreId: copyBytes(record.witnessedStoreId),
  deliveryProfileHash: copyBytes(record.deliveryProfileHash),
  ingressWindow: record.ingressWindow,
  checkpointHash: copyBytes(record.checkpointHash),
});

/**
 * Sign one admission over the lease this store issued.
 *
 * The transcript binds the store, profile, window, size class, ordinal and the
 * exact object bytes at once, so an admission cannot be replayed into another
 * slot of the same allocation or against different bytes. The secret key is
 * the caller's ephemeral allocation key and is neither copied nor retained
 * here.
 */
export const buildAppendAdmission = async (
  lease: PublicAllocationLeaseV1,
  allocationSecretKey: Uint8Array,
  sizeClass: number,
  objectOrdinal: number,
  exactFixedObject: Uint8Array,
  module: LibCrypto,
): Promise<PublicAppendAdmissionV1> => {
  // Own every caller-controlled byte before the first await: an admission that
  // was signed over one object and shipped with another is unusable evidence.
  const privateLease = copyLease(lease);
  const privateObject = copyBytes(exactFixedObject);
  const { storeSignature: _signature, ...leaseBody } = privateLease;

  return {
    version: 1,
    lease: privateLease,
    objectOrdinalWithinAllocation: objectOrdinal,
    allocationSignature: await sign(
      await allocationAppendSignedMessage(
        leaseBody,
        sizeClass,
        objectOrdinal,
        privateObject,
      ),
      allocationSecretKey,
      module,
    ),
  };
};

/**
 * The part of the observed run already verified as one chain: the checkpoint
 * hash of every observation in it, by window, and the descriptor hash the
 * newest of them was served under.
 */
interface VerifiedRun {
  readonly descriptorHash: Uint8Array;
  readonly hashes: Map<string, Uint8Array>;
}

/** A decoded signed refusal, with the request it answers. */
type SignedRefusalRead =
  | {
      readonly route: "checkpoint";
      readonly value: PublicStoreCheckpointStatusBodyV1;
      readonly storeSignature: Uint8Array;
    }
  | {
      readonly route: "chunk";
      readonly value: PublicChunkStatusBodyV1;
      readonly storeSignature: Uint8Array;
      /** The chunk this client asked for. */
      readonly sizeClass: number;
      readonly chunkIndex: number;
      /** The finalized checkpoint read this scan verified for the window. */
      readonly checkpointBytes: Uint8Array;
    };

export class PrototypeStoreClient {
  /**
   * Public identity, as the design's adapter shape requires it. These are
   * copies: every security decision this file makes uses the private key and
   * hashes below, so a caller that mutates one of them changes what it reads,
   * never what is verified.
   */
  readonly storeId: Uint8Array;
  readonly storeIdHex: string;
  readonly descriptor: StoreDescriptorV1;
  readonly carrierContextId: Uint8Array;
  readonly origin: string;

  readonly #module: LibCrypto;
  readonly #fetch: StoreTransport;
  readonly #profile: DeliveryProfileV1;
  readonly #geometry: PublicProfileGeometry;
  readonly #profileHash: Uint8Array;
  readonly #profileHex: string;
  readonly #storeId: Uint8Array;
  readonly #storeKey: Uint8Array;
  readonly #chainStart: bigint;
  readonly #objectBytesByClass: ReadonlyMap<number, number>;
  readonly #requestDeadlineMs: number;
  readonly #admissionTokens: StoreAdmissionTokenProvider | undefined;

  readonly #nowMs: () => bigint;
  /**
   * The pinned descriptor every signed refusal is judged under and every
   * evidence record keeps: a private copy, like the key and the hashes.
   */
  readonly #descriptor: StoreDescriptorV1;
  /** `DescriptorHash` of the pinned descriptor, which every status must name. */
  readonly #descriptorHash: Uint8Array;

  #inert = false;
  /** Recorded faults with their arrival order, blame and reports apart. */
  readonly #blame: {
    readonly order: number;
    readonly fault: StoreFaultRecord;
  }[] = [];
  readonly #reports: {
    readonly order: number;
    readonly fault: StoreFaultRecord;
  }[] = [];
  #faultOrder = 0;
  /**
   * Windows this client could not read back from this store — expired or
   * withheld — so a receipt for one is reported unchecked, never held for a
   * scan that cannot come. Bounded like the scanned windows.
   */
  readonly #unreadable = new Set<string>();
  /** Sorted by ingress window; the input to `verifyStoreCheckpointChain`. */
  readonly #observed: ObservedStoreCheckpoint[] = [];
  /** The checkpoint hash of every observation, computed once at its scan. */
  readonly #observedHashes = new WeakMap<ObservedStoreCheckpoint, Uint8Array>();
  /**
   * What of `#observed` is verified as one chain, or `null` when nothing is
   * trusted: before the first scan, and after anything that makes this
   * client distrust the store (blame of any kind, a checkpoint served under
   * another descriptor than the run's). A client that reconnects is a new
   * client and starts with none. See `#verifyChain`.
   */
  #verified: VerifiedRun | null = null;
  readonly #checkpointHashes = new Map<string, Uint8Array>();
  #receipts: AppendReceipt[] = [];
  readonly #inFlight = new Set<InFlightAppend>();
  /**
   * The hash of every object of each scanned window, by slot, from the first
   * finalized scan of that window: what a receipt arriving after the scan is
   * judged against. Keyed `String(window)`.
   */
  readonly #scannedSlots = new Map<
    string,
    { readonly window: bigint; readonly hashes: Map<string, Uint8Array> }
  >();

  private constructor(
    options: StoreClientOptions,
    pinned: {
      readonly storeId: Uint8Array;
      readonly descriptor: StoreDescriptorV1;
      readonly descriptorHash: Uint8Array;
      readonly carrierContextId: Uint8Array;
      readonly chainStart: bigint;
      readonly profileHash: Uint8Array;
      readonly objectBytesByClass: ReadonlyMap<number, number>;
    },
  ) {
    this.storeId = copyBytes(pinned.storeId);
    this.storeIdHex = hexOf(pinned.storeId);
    this.descriptor = pinned.descriptor;
    this.carrierContextId = copyBytes(pinned.carrierContextId);
    this.origin = options.origin;

    this.#module = options.module;
    this.#fetch = transportOf(options);
    this.#profile = options.profile;
    this.#geometry = profileGeometry(options.profile);
    this.#profileHash = pinned.profileHash;
    this.#profileHex = hexOf(pinned.profileHash);
    this.#storeId = pinned.storeId;
    this.#storeKey = copyBytes(pinned.descriptor.storeIdentityEd25519Key);
    this.#chainStart = pinned.chainStart;
    this.#objectBytesByClass = pinned.objectBytesByClass;
    this.#requestDeadlineMs = requestDeadlineMs(options.profile);
    this.#admissionTokens = options.admissionTokens;
    this.#nowMs = options.nowMs;
    this.#descriptor = copyDescriptor(pinned.descriptor);
    this.#descriptorHash = copyBytes(pinned.descriptorHash);
  }

  /**
   * Fetch the descriptor, validate it, and pin the identity every later answer
   * is checked against.
   *
   * This is the one place that throws: a client that could not establish whom
   * it is talking to has no store, and returning a half-usable object would
   * push that decision to a caller with less context. Everything after this
   * point degrades instead.
   *
   * `nowMs` is read here, and twice at every scan: when its requests leave
   * and when their answers are in. Those two readings decide only what is
   * believed without proof — whether a signed refusal is one a store within
   * the profile's skew could have given then, and whether the pinned
   * descriptor covered the read (`judgeSignedRefusal`, steps 4 to 6). Whether
   * an answer is a breach is decided from the store's own signed statements,
   * never from this clock. The route lease is about now too and is checked
   * here only; every other later check is anchored to the instant the window
   * it concerns was finalized — historical evidence must not change meaning
   * because the wall clock moved.
   */
  static async connect(
    options: StoreClientOptions,
  ): Promise<PrototypeStoreClient> {
    if (options.profileHash.length !== 32)
      fail("the delivery profile hash must be exactly 32 bytes");
    const profileHash = copyBytes(options.profileHash);
    const transport = transportOf(options);

    // The descriptor fetch is bounded like every later request, and for the
    // same reason: a store that accepts this connection and then says nothing
    // would otherwise leave the caller's whole composition waiting on one
    // origin before the run has begun.
    const deadlineMs = requestDeadlineMs(options.profile);
    const deadline = AbortSignal.timeout(deadlineMs);
    let response: Response;
    try {
      response = await transport(
        `${options.origin}${PROTOTYPE_STORE_ROUTES.descriptor}`,
        { signal: deadline },
      );
    } catch (error) {
      return fail(
        deadline.aborted
          ? `the store descriptor did not arrive within the ${String(deadlineMs)} ms request deadline`
          : `the store descriptor could not be fetched: ${
              error instanceof Error ? error.name : "unknown error"
            }`,
      );
    }
    // The version first, whatever the status: a store of another version
    // answers this client's descriptor path with its own 404 or 426, and
    // says which version it is in this header on every answer.
    const protocol = response.headers.get("x-p2party-store");
    if (protocol !== null && protocol !== PROTOTYPE_STORE_PROTOCOL)
      throw new StoreVersionError(protocol);
    if (response.status !== 200)
      fail(`the store descriptor route answered ${String(response.status)}`);
    if (protocol === null)
      fail("the descriptor answer is not from a prototype store");

    let served: PrototypeStoreDescriptorDocumentV1;
    try {
      served = decodePrototypeStoreDescriptorDocumentV1(
        new Uint8Array(await response.arrayBuffer()),
      );
    } catch (error) {
      return fail(
        `the store descriptor document is not canonical: ${
          error instanceof Error ? error.message : "unknown error"
        }`,
      );
    }

    const descriptor = served.descriptor;
    if (descriptor.version !== 1) fail("unsupported store descriptor version");

    const nowMs = options.nowMs();
    const validity = await validateStoreDescriptor(
      descriptor,
      nowMs,
      options.module,
    );
    if (!validity.valid)
      fail(`the store descriptor is invalid: ${validity.reason}`);

    // Signed with the rest of the descriptor, so this is the store's own
    // statement of how far back it serves.
    if (descriptor.retentionWindows < PROTOTYPE_READ_BACK_WINDOWS)
      throw new StoreRetentionError(
        `storeClient: the store states a retention of ${String(descriptor.retentionWindows)} windows, and this client reads up to ${String(PROTOTYPE_READ_BACK_WINDOWS)} back`,
      );

    // Prototype compatibility is deliberately its own hash: a store that
    // advertises release compatibility bytes is refused rather than
    // half-spoken to.
    if (
      !bytesEqual(
        descriptor.compatibilityHash,
        await prototypeStoreCompatibilityHash(profileHash),
      )
    )
      fail("the store is not compatible with this prototype delivery profile");
    if (!descriptorSupportsProfile(descriptor, profileHash))
      fail("the store does not serve this delivery profile");

    // Exactly one anchor, asserted rather than assumed: the chain start is
    // what every later window is judged against, and `descriptorChainStart`
    // would silently take the first of two. Descriptor validity already makes
    // a second entry impossible; this is the check that says so out loud.
    if (
      descriptor.checkpointChainStarts.filter((start) =>
        bytesEqual(start.deliveryProfileHash, profileHash),
      ).length !== 1
    )
      fail(
        "the store declares no single chain start for this delivery profile",
      );
    const chainStart = descriptorChainStart(descriptor, profileHash);
    if (chainStart === null)
      fail("the store declares no chain start for this delivery profile");

    // The route is checked separately from the descriptor because it binds
    // values the descriptor never sees — the locator this client dialled, the
    // family, and its own lease. A store that signed no route for this origin
    // has not authorized being reached here.
    const route = served.routes.find((candidate) => {
      try {
        return textDecoder.decode(candidate.opaqueLocator) === options.origin;
      } catch {
        return false;
      }
    });
    if (route === undefined)
      fail("the store signed no route whose locator is this origin");
    const routeValidity = await validateStoreRoute(
      route,
      descriptor,
      nowMs,
      options.module,
    );
    if (!routeValidity.valid)
      fail(`the store route is invalid: ${routeValidity.reason}`);

    const storeIdBytes = await computeStoreId(
      descriptor.storeIdentityEd25519Key,
    );

    // One envelope encoding per class, at connect: the wire length is fixed by
    // the profile, and recomputing it per verified object would burn it on the
    // read path.
    const objectBytesByClass = new Map<number, number>(
      options.profile.sizeClasses.map((sizeClass) => [
        sizeClass.id,
        carrierObjectWireBytes(options.profile, sizeClass.id, profileHash),
      ]),
    );

    return new PrototypeStoreClient(options, {
      storeId: storeIdBytes,
      descriptor,
      descriptorHash: await computeDescriptorHash(descriptor),
      carrierContextId: await publicCarrierContextId(storeIdBytes, profileHash),
      chainStart,
      profileHash,
      objectBytesByClass,
    });
  }

  /** True once this store has been caught in a fault no absence explains. */
  get inert(): boolean {
    return this.#inert;
  }

  get faults(): readonly StoreFaultRecord[] {
    return [...this.#blame, ...this.#reports]
      .sort((left, right) => left.order - right.order)
      .map(({ fault }) => ({
        ...fault,
        ...(fault.evidence === undefined
          ? {}
          : { evidence: fault.evidence.map(copyBytes) }),
        ...(fault.descriptor === undefined
          ? {}
          : { descriptor: copyDescriptor(fault.descriptor) }),
      }));
  }

  /* ---------------------------------------------------------------- *
   * Ingress
   * ---------------------------------------------------------------- */

  /**
   * Ask for an allocation token for `targetWindow`.
   *
   * Open mode has no quota to consume, so the answer carries no authority; it
   * is requested and verified anyway because the traffic shape is part of the
   * profile — a client that skipped it would be distinguishable from one that
   * did not.
   */
  async issueToken(targetWindow: bigint): Promise<boolean> {
    const body = encodeAllocationTokenIssueRequestV1({
      version: 1,
      storeId: copyBytes(this.#storeId),
      deliveryProfileHash: copyBytes(this.#profileHash),
      ingressWindow: targetWindow,
      privacyPassTokenRequest: new Uint8Array(32),
    });
    const bytes = await this.#post(
      PROTOTYPE_STORE_ROUTES.token,
      PROTOTYPE_STORE_MEDIA_TYPES.tokenRequest,
      body,
      targetWindow,
    );
    if (bytes === null) return false;

    const result = this.#decode(
      decodeAllocationTokenIssueResultV1,
      bytes,
      targetWindow,
      "allocation token result",
    );
    if (result === null) return false;
    if (result.body.version !== 1)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "unsupported allocation token result version",
        false,
      );

    const verified = await verify(
      await allocationTokenIssueResultSignedMessage(result.body),
      result.storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the allocation token result signature does not verify",
        false,
      );
    return result.body.kind === "issued";
  }

  /**
   * Redeem a token for a lease over `targetWindow`.
   *
   * Only the public half of `allocationKey` is sent; the secret stays with the
   * caller, which is what makes the lease usable by nobody else.
   */
  async allocate(
    targetWindow: bigint,
    allocationKey: { publicKey: Uint8Array; secretKey: Uint8Array },
  ): Promise<PublicAllocationLeaseV1 | null> {
    const allocationEd25519PublicKey = copyBytes(allocationKey.publicKey);
    const token =
      (await this.#admissionToken("allocation", targetWindow)) ??
      new Uint8Array(ADMISSION_TOKEN_BYTES);
    const body = encodePublicAllocationRequestV1({
      version: 1,
      deliveryProfileHash: copyBytes(this.#profileHash),
      ingressWindow: targetWindow,
      allocationEd25519PublicKey,
      privacyPassToken: token,
    });
    token.fill(0);
    const bytes = await this.#post(
      PROTOTYPE_STORE_ROUTES.allocation,
      PROTOTYPE_STORE_MEDIA_TYPES.allocationRequest,
      body,
      targetWindow,
    );
    if (bytes === null) return null;

    const result = this.#decode(
      decodePublicAllocationResultV1,
      bytes,
      targetWindow,
      "allocation result",
    );
    if (result === null) return null;

    if (result.kind === "status") {
      if (result.value.version !== 1)
        return this.#reject(
          "signature-invalid",
          targetWindow,
          "unsupported allocation status version",
          null,
        );
      // A refusal is verified for the same reason a lease is: an unsigned one
      // could be forged by the network to push this client onto one store.
      const verified = await verify(
        await publicAllocationStatusSignedMessage(result.value),
        result.storeSignature,
        this.#storeKey,
        this.#module,
      );
      if (!verified)
        return this.#reject(
          "signature-invalid",
          targetWindow,
          "the allocation status signature does not verify",
          null,
        );
      return null;
    }

    const lease = result.lease;
    if (lease.version !== 1)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "unsupported allocation lease version",
        null,
      );
    const { storeSignature, ...leaseBody } = lease;
    const verified = await verify(
      await publicAllocationLeaseSignedMessage(leaseBody),
      storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the allocation lease signature does not verify",
        null,
      );

    // The signature only proves this store wrote the lease; these checks prove
    // it wrote the lease this client asked for. A lease for another window or
    // another key would be admitted by nothing later.
    if (
      !bytesEqual(lease.storeId, this.#storeId) ||
      !bytesEqual(lease.deliveryProfileHash, this.#profileHash) ||
      lease.ingressWindow !== targetWindow ||
      !bytesEqual(lease.allocationEd25519PublicKey, allocationEd25519PublicKey)
    )
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the lease does not bind the allocation this client requested",
        null,
      );

    // The ordinal is the one input to the slot mapping the *store* picks, and
    // the wire carries it as a plain u32. Outside the cohort capacity it names
    // no slot in any window, so a signature over it proves only that the store
    // meant it: `appendSlotCoordinates` would throw on the first use, which is
    // a store choosing when this client crashes. It is refused here instead.
    if (!this.#ordinalWithinCohort(lease.allocationOrdinal))
      return this.#reject(
        "signature-invalid",
        targetWindow,
        "the lease names an allocation ordinal outside the cohort capacity",
        null,
      );
    return lease;
  }

  /** `0 <= allocationOrdinal < cohortAllocationsPerWindow`. */
  #ordinalWithinCohort(allocationOrdinal: number): boolean {
    return (
      Number.isSafeInteger(allocationOrdinal) &&
      allocationOrdinal >= 0 &&
      allocationOrdinal < this.#profile.cohortAllocationsPerWindow
    );
  }

  /** `0 <= objectOrdinal < roomSlotsPerClient × appendSchedule.length`. */
  #ordinalWithinAllocation(sizeClass: number, objectOrdinal: number): boolean {
    const found = this.#profile.sizeClasses.find(
      (candidate) => candidate.id === sizeClass,
    );
    if (found === undefined) return false;
    return (
      Number.isSafeInteger(objectOrdinal) &&
      objectOrdinal >= 0 &&
      objectOrdinal <
        this.#profile.roomSlotsPerClient * found.appendSchedule.length
    );
  }

  /**
   * Publish one fixed-size object into `(window, sizeClass)`.
   *
   * `admission === null` is a deliberate unallocated cover append: the store
   * accepts it, answers the one fixed status, and discards it.
   *
   * An append with a lease is tracked from the moment it is sent until its
   * answer arrives: a scan of its window that finds it still unanswered
   * reports `custody-unacknowledged` (see `StoreFaultKind`).
   */
  async append(
    window: bigint,
    sizeClass: number,
    exactFixedObject: Uint8Array,
    admission: PublicAppendAdmissionV1 | null,
  ): Promise<PublicAppendResultV1 | null> {
    // Every caller-controlled byte is owned before the first await.
    const request: PublicAppendRequestV1 = {
      version: 1,
      bucket: {
        deliveryProfileHash: copyBytes(this.#profileHash),
        ingressWindow: window,
        sizeClass,
      },
      exactFixedObject: copyBytes(exactFixedObject),
      admission:
        admission === null
          ? null
          : {
              version: admission.version,
              lease: copyLease(admission.lease),
              objectOrdinalWithinAllocation:
                admission.objectOrdinalWithinAllocation,
              allocationSignature: copyBytes(admission.allocationSignature),
            },
    };

    const token = await this.#admissionToken("append", window);
    const inFlight = this.#trackInFlight(window, sizeClass, request.admission);
    let bytes: Uint8Array | null;
    try {
      bytes = await this.#post(
        PROTOTYPE_STORE_ROUTES.append,
        PROTOTYPE_STORE_MEDIA_TYPES.appendRequest,
        encodePublicAppendRequestV1(request),
        window,
        token,
      );
    } finally {
      if (inFlight !== null) this.#inFlight.delete(inFlight);
      token?.fill(0);
    }
    if (bytes === null) return null;

    const result = this.#decode(
      decodePublicAppendResultV1,
      bytes,
      window,
      "append result",
    );
    if (result === null) return null;
    if (result.version !== 1)
      return this.#reject(
        "signature-invalid",
        window,
        "unsupported append result version",
        null,
      );

    const { storeSignature, ...body } = result;
    const verified = await verify(
      await publicAppendResultSignedMessage(body),
      storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        window,
        "the append result signature does not verify",
        null,
      );

    // The echoed request hash is what makes this receipt evidence about *this*
    // append rather than some other one the store also answered.
    if (
      !bytesEqual(body.storeId, this.#storeId) ||
      !bytesEqual(body.bucket.deliveryProfileHash, this.#profileHash) ||
      body.bucket.ingressWindow !== window ||
      body.bucket.sizeClass !== sizeClass ||
      !bytesEqual(body.requestHash, await publicAppendRequestHash(request))
    )
      return this.#reject(
        "signature-invalid",
        window,
        "the append result does not answer the request this client sent",
        null,
      );
    return result;
  }

  /**
   * Remember what the store promised, until the window it names is scanned —
   * or, when that window was already scanned, judge it now against the slot
   * hashes that scan kept.
   *
   * Validated eagerly, and each coordinate against the half it comes from: the
   * object ordinal is the caller's, so an out-of-range one is a caller bug and
   * says so; the allocation ordinal is the store's, and `allocate` has already
   * refused it if it named no slot — the check here is the belt to that brace,
   * for a lease that reached this client by some other path. Either way the
   * bounds are decided before `appendSlotCoordinates`, which throws, and a
   * throw inside a scan would turn a bad coordinate into a fault report
   * against a store that did nothing wrong.
   */
  recordReceipt(receipt: AppendReceipt): void {
    if (receipt.lease.ingressWindow !== receipt.window)
      fail("the receipt's lease names a different ingress window");
    if (!bytesEqual(receipt.lease.storeId, this.#storeId))
      fail("the receipt's lease names a different store");
    if (!bytesEqual(receipt.lease.deliveryProfileHash, this.#profileHash))
      fail("the receipt's lease names a different delivery profile");
    if (receipt.objectHash.length !== 32)
      fail("the receipt's object hash must be exactly 32 bytes");
    if (!this.#ordinalWithinCohort(receipt.lease.allocationOrdinal))
      fail("the receipt's lease names an ordinal outside the cohort capacity");
    if (
      !this.#ordinalWithinAllocation(receipt.sizeClass, receipt.objectOrdinal)
    )
      fail("the receipt's object ordinal is outside this allocation's slots");

    const privateReceipt: AppendReceipt = {
      window: receipt.window,
      sizeClass: receipt.sizeClass,
      lease: copyLease(receipt.lease),
      objectOrdinal: receipt.objectOrdinal,
      objectHash: copyBytes(receipt.objectHash),
      result: { ...receipt.result },
    };
    if (this.#unreadable.has(String(receipt.window))) {
      this.#reportUnchecked(receipt.window, 1);
      return;
    }
    // A promise that arrived after its window was read is evidence all the
    // same: the slot it names either held these bytes in that read or not.
    const scanned = this.#scannedSlots.get(String(receipt.window));
    if (scanned !== undefined) {
      this.#judgeReceipt(privateReceipt, scanned.hashes);
      return;
    }
    // Never dropped without a word: a receipt pushed out to make room is one
    // whose window this client will not check, as after a read that ended in
    // a clock disagreement and was not made again.
    if (this.#receipts.length >= MAX_PENDING_RECEIPTS) {
      const evicted = this.#receipts.shift();
      if (evicted !== undefined)
        this.#record(
          "custody-unchecked",
          evicted.window,
          `an append receipt for this window was not checked: it waited for a read of the window past the ${String(MAX_PENDING_RECEIPTS)} receipts this client holds`,
        );
    }
    this.#receipts.push(privateReceipt);
  }

  /* ---------------------------------------------------------------- *
   * The fixed scan
   * ---------------------------------------------------------------- */

  /**
   * Read one window whole and decide what it proves.
   *
   * The checkpoint and every chunk are issued together and only then awaited:
   * the profile's fixed geometry is the point of the scan, and one round trip
   * per chunk would both leak the reader's pace and miss the window.
   */
  async scanWindow(window: bigint): Promise<WindowScan> {
    const empty = (status: WindowScan["status"]): WindowScan => ({
      window,
      status,
      objects: [],
      checkpointHash: null,
    });

    // Below the chain start there is nothing this store ever promised, so it
    // is out of range rather than missing.
    if (window < this.#chainStart) return empty("out-of-range");

    const classes = [...this.#profile.sizeClasses].sort(
      (left, right) => left.id - right.id,
    );
    // This client's clock as the requests leave: with the reading when the
    // answers are in, the span every signed refusal is judged against.
    const sentMs = this.#nowMs();
    const checkpointPromise = this.#get(
      `${PROTOTYPE_STORE_ROUTES.checkpoint}/${this.#profileHex}/${String(window)}`,
      window,
    );
    const chunkPromises = classes.map((sizeClass) =>
      Array.from({ length: sizeClass.publicChunksPerWindow }, (_, index) =>
        this.#get(
          `${PROTOTYPE_STORE_ROUTES.chunk}/${this.#profileHex}/${String(window)}/${String(sizeClass.id)}/${String(index)}`,
          window,
        ),
      ),
    );
    const [checkpointBytes, chunkBytes] = await Promise.all([
      checkpointPromise,
      Promise.all(chunkPromises.map((promises) => Promise.all(promises))),
    ]);

    // One reading for the whole scan, taken before any answer is judged:
    // every answer was signed before it. A clock that stepped back while the
    // requests were out is read as not having moved.
    const nowMs = this.#nowMs();
    const read: StoreReadSpan = {
      sentMs,
      receivedMs: nowMs > sentMs ? nowMs : sentMs,
    };

    const checkpointStatus = await this.#readCheckpoint(
      window,
      checkpointBytes,
      read,
    );
    if (checkpointStatus.kind !== "finalized")
      return this.#unreadableOutcome(window, empty(checkpointStatus.status));
    const { checkpoint, descriptor } = checkpointStatus;

    const chunks = await this.#readChunks(
      window,
      classes,
      chunkBytes,
      read,
      checkpointBytes ?? new Uint8Array(0),
    );
    if (chunks.kind !== "finalized")
      return this.#unreadableOutcome(window, empty(chunks.status));

    // The chunks are only *this store's* claim until the checkpoint commits
    // them: recompute the root over the complete profile-fixed sequence and
    // require the committed value.
    const recomputedRoot = await rfc9162MerkleTreeHash(
      await checkpointLeafEntries(this.#geometry, chunks.hashesByClass),
    );
    // The fault kind is `root-mismatch` and the store is inert from here on;
    // the *scan status* is `unreachable`, the same string a switched-off store
    // gets. That is deliberate and not the `f1f5aa4` taxonomy leaking back in:
    // `WindowScan["status"]` answers "is there a usable window here", which is
    // "no" either way, while the blame lives in the fault record and in
    // `inert`. See the docblock on `WindowScan`.
    if (!bytesEqual(recomputedRoot, checkpoint.finalizedChunkRoot))
      return this.#breach(
        "root-mismatch",
        window,
        "the served chunks do not recompute the committed chunk root",
        empty("unreachable"),
      );

    const checkpointHash = await publicStoreCheckpointHash(checkpoint);
    this.#rememberCheckpointHash(window, checkpointHash);

    await this.#verifyChain(window, checkpoint, descriptor, checkpointHash);
    await this.#verifyCustody(window, chunks.chunksByClass);

    // The pinned descriptor is the store's lease to be read at all, and it is
    // checked at every read, not only at `connect`. A window read while this
    // client's clock is outside it is not served: everything above still ran,
    // because what the store signed is evidence whenever it is read, and the
    // window's receipts were judged against it.
    if (!descriptorValidThroughRead(this.#descriptor, read)) {
      this.#record(
        "descriptor-out-of-validity",
        window,
        `this client's clock read ${String(read.sentMs)} to ${String(read.receivedMs)} ms during the read, outside the pinned descriptor's validity (${String(this.#descriptor.notBeforeUnixMs)} to ${String(this.#descriptor.notAfterUnixMs)} ms); the window was not served`,
      );
      return empty("descriptor-out-of-validity");
    }

    // Objects in `(sizeClass, chunkIndex, objectIndex)` order: the profile's
    // own order, which is what makes an index into this array meaningful to a
    // caller that never saw the chunks.
    const objects: Uint8Array[] = [];
    for (const sizeClass of classes)
      for (const chunk of chunks.chunksByClass.get(sizeClass.id) ?? [])
        for (const object of chunk.fixedObjects)
          objects.push(copyBytes(object));

    return {
      window,
      status: "finalized",
      objects,
      checkpointHash: copyBytes(checkpointHash),
    };
  }

  /** The verified checkpoint hash for a window this client scanned. */
  checkpointHashFor(window: bigint): Uint8Array | null {
    const held = this.#checkpointHashes.get(String(window));
    return held === undefined ? null : copyBytes(held);
  }

  /**
   * Keep the *first* verified checkpoint hash for a window.
   *
   * This is the value the client witnessed to other stores, so a later branch
   * of an equivocating store must not quietly replace what was gossiped; the
   * branch is not lost either — `#observe` keeps both, which is what turns the
   * pair into a conflict. Bounded like the observation run, and for the same
   * reason: a long-lived tab must not accumulate one entry per window forever.
   */
  #rememberCheckpointHash(window: bigint, checkpointHash: Uint8Array): void {
    const key = String(window);
    if (this.#checkpointHashes.has(key)) return;
    if (this.#checkpointHashes.size >= MAX_OBSERVED_CHECKPOINTS) {
      const oldest = this.#checkpointHashes.keys().next();
      if (!oldest.done) this.#checkpointHashes.delete(oldest.value);
    }
    this.#checkpointHashes.set(key, checkpointHash);
  }

  /* ---------------------------------------------------------------- *
   * Witnessing (design doc §8)
   * ---------------------------------------------------------------- */

  /**
   * Offer this store one observation of another store's checkpoint.
   *
   * Certificate-Transparency-style gossip with the other store as the carrier
   * and no witness network. Unlike every other route here, this one is not a
   * fixed per-window POST: the caller invokes it only when its scan of the
   * *other* store came back `finalized` and neither store is inert, which
   * makes it the cross-store status oracle disclosed in design doc §3a item
   * 14.
   */
  async postWitness(record: StoreWitnessRecordV1): Promise<boolean> {
    const privateRecord = copyWitnessRecord(record);
    const token = await this.#admissionToken(
      "witness",
      privateRecord.ingressWindow,
    );
    try {
      const bytes = await this.#post(
        PROTOTYPE_STORE_ROUTES.witness,
        PROTOTYPE_STORE_MEDIA_TYPES.witnessRecord,
        encodeStoreWitnessRecordV1(privateRecord),
        privateRecord.ingressWindow,
        token,
      );
      return bytes !== null;
    } finally {
      token?.fill(0);
    }
  }

  /**
   * Read the observations this store holds for `window`.
   *
   * Witness records are unauthenticated peer input and are returned as data,
   * never as a claim. The one thing this client can decide locally is whether
   * a record about *itself* contradicts the checkpoint it was shown: that is a
   * split-view hint, not a proof — the specification's conflict proof needs
   * two checkpoints signed by the store — so it is logged and does not make
   * the store inert. Comparing records about *other* stores is the carrier
   * runtime's job, since only it holds both stores' verified hashes.
   */
  async readWitnesses(
    window: bigint,
  ): Promise<readonly StoreWitnessRecordV1[]> {
    const bytes = await this.#get(
      `${PROTOTYPE_STORE_ROUTES.witness}/${this.#profileHex}/${String(window)}`,
      window,
    );
    if (bytes === null) return [];
    const records = this.#decode(
      decodeStoreWitnessRecordsV1,
      bytes,
      window,
      "witness records",
    );
    if (records === null) return [];

    const held = this.#checkpointHashes.get(String(window));
    const output: StoreWitnessRecordV1[] = [];
    for (const record of records) {
      if (record.version !== 1) continue;
      if (!bytesEqual(record.deliveryProfileHash, this.#profileHash)) continue;
      if (record.ingressWindow !== window) continue;
      if (
        held !== undefined &&
        bytesEqual(record.witnessedStoreId, this.#storeId) &&
        !bytesEqual(record.checkpointHash, held)
      )
        this.#record(
          "checkpoint-split-view-hint",
          window,
          "a witness record names a different checkpoint than this store showed",
        );
      output.push(copyWitnessRecord(record));
    }
    return output;
  }

  /* ---------------------------------------------------------------- *
   * Internals
   * ---------------------------------------------------------------- */

  /**
   * One GET or POST, reduced to bytes or `null`.
   *
   * A rejected fetch, a request that outlived its deadline, a non-200 status,
   * a missing protocol header and a body that cannot even be read off the wire
   * are one outcome here: this attempt produced no usable answer. They are
   * recorded as `unreachable`, not `signature-invalid` — none of them is a
   * signature this client checked and found wanting, they are the absence of
   * one, and a store merely switched off would produce every one of them. None
   * of them makes the store inert: being unreachable is not evidence of
   * dishonesty, and the store may come back.
   *
   * The deadline is the reason a store that answers *nothing* lands in this
   * same class rather than hanging: `requestDeadlineMs` explains the value.
   */
  async #request(
    path: string,
    window: bigint | null,
    init?: RequestInit,
  ): Promise<Uint8Array | null> {
    const deadline = AbortSignal.timeout(this.#requestDeadlineMs);
    let response: Response;
    try {
      response = await this.#fetch(`${this.origin}${path}`, {
        ...init,
        signal: deadline,
      });
    } catch (error) {
      return this.#reject(
        "unreachable",
        window,
        deadline.aborted
          ? `${path}: no answer within the ${String(this.#requestDeadlineMs)} ms request deadline`
          : `${path}: the request failed (${
              error instanceof Error ? error.name : "unknown error"
            })`,
        null,
      );
    }
    // Every answer of this protocol is attributable to it; one that is not did
    // not come from a store of this version, whatever is in its body or its
    // status. A store that changed version since `connect` is named.
    const protocol = response.headers.get("x-p2party-store");
    if (protocol !== null && protocol !== PROTOTYPE_STORE_PROTOCOL)
      return this.#reject(
        "unreachable",
        window,
        `${path}: the answer is from a ${protocol} store, and this client speaks ${PROTOTYPE_STORE_PROTOCOL}`,
        null,
      );
    if (response.status !== 200)
      return this.#reject(
        "unreachable",
        window,
        `${path}: answered ${String(response.status)}`,
        null,
      );
    if (protocol === null)
      return this.#reject(
        "unreachable",
        window,
        `${path}: the answer is not from a prototype store`,
        null,
      );
    try {
      return new Uint8Array(await response.arrayBuffer());
    } catch {
      // The deadline covers the body too: a store that sends headers and then
      // stops writing is the same stall as one that never answered at all.
      return this.#reject(
        "unreachable",
        window,
        deadline.aborted
          ? `${path}: the answer body did not arrive within the ${String(this.#requestDeadlineMs)} ms request deadline`
          : `${path}: the answer body could not be read`,
        null,
      );
    }
  }

  async #get(path: string, window: bigint | null): Promise<Uint8Array | null> {
    return this.#request(path, window);
  }

  /**
   * One POST. A redirect is refused outright rather than followed: every POST
   * may carry an admission token, in the allocation body or the
   * `authorization` header, and a store that redirected one would have it
   * replayed to an origin it was never issued for. The store never redirects,
   * so a redirect is an unusable answer like any other.
   */
  async #post(
    path: string,
    mediaType: string,
    body: Uint8Array,
    window: bigint | null,
    admissionToken: Uint8Array | null = null,
  ): Promise<Uint8Array | null> {
    // `lib.dom`'s `BodyInit` is narrower than the codecs' `Uint8Array`, and a
    // copy is owed anyway: the request must not be able to change under the
    // transport after the bytes were signed over.
    const buffer = new ArrayBuffer(body.byteLength);
    new Uint8Array(buffer).set(body);
    return this.#request(path, window, {
      method: "POST",
      redirect: "error",
      headers:
        admissionToken === null
          ? { "content-type": mediaType }
          : {
              "content-type": mediaType,
              authorization: `Bearer ${hexOf(admissionToken)}`,
            },
      body: buffer,
    });
  }

  /**
   * The token to present for one request, or `null` under open admission.
   *
   * Asked for before anything is sent, so a provider that fails costs no
   * request and never turns into an unauthenticated one; the token must name
   * the store this client pinned, so it reaches no other.
   */
  async #admissionToken(
    route: StoreAdmissionRoute,
    window: bigint,
  ): Promise<Uint8Array | null> {
    const provider = this.#admissionTokens;
    if (provider === undefined) return null;
    let issued: unknown;
    try {
      issued = await provider({
        storeId: copyBytes(this.#storeId),
        origin: this.origin,
        route,
        ingressWindow: window,
      });
    } catch (error) {
      throw new StoreAdmissionTokenError(
        `the admission token provider failed for the ${route} route (${
          error instanceof Error ? error.name : "unknown error"
        })`,
      );
    }
    const candidate = issued as Partial<StoreAdmissionToken> | null;
    if (
      typeof candidate !== "object" ||
      candidate === null ||
      !(candidate.storeId instanceof Uint8Array) ||
      !bytesEqual(candidate.storeId, this.#storeId)
    )
      throw new StoreAdmissionTokenError(
        `the admission token for the ${route} route was not issued for this store`,
      );
    if (
      !(candidate.token instanceof Uint8Array) ||
      candidate.token.length !== ADMISSION_TOKEN_BYTES
    )
      throw new StoreAdmissionTokenError(
        `the admission token for the ${route} route is not exactly ${String(ADMISSION_TOKEN_BYTES)} bytes`,
      );
    return copyBytes(candidate.token);
  }

  /**
   * Start tracking an append with a lease, or `null` for cover and for
   * ordinals no slot answers to (the store refuses those as malformed).
   */
  #trackInFlight(
    window: bigint,
    sizeClass: number,
    admission: PublicAppendAdmissionV1 | null,
  ): InFlightAppend | null {
    if (admission === null) return null;
    const allocationOrdinal = admission.lease.allocationOrdinal;
    const objectOrdinal = admission.objectOrdinalWithinAllocation;
    if (
      !this.#ordinalWithinCohort(allocationOrdinal) ||
      !this.#ordinalWithinAllocation(sizeClass, objectOrdinal)
    )
      return null;
    const coordinates = appendSlotCoordinates(
      this.#geometry,
      sizeClass,
      allocationOrdinal,
      objectOrdinal,
    );
    const entry: InFlightAppend = {
      window,
      slotKey: slotKeyOf(
        sizeClass,
        coordinates.chunkIndex,
        coordinates.objectIndexWithinChunk,
      ),
      reported: false,
    };
    if (this.#inFlight.size >= MAX_IN_FLIGHT_APPENDS) {
      const oldest = this.#inFlight.values().next();
      if (!oldest.done) this.#inFlight.delete(oldest.value);
    }
    this.#inFlight.add(entry);
    return entry;
  }

  /**
   * Decode one canonical answer.
   *
   * `decodeCanonicalStrict` re-encodes, so a value that decodes here is the
   * unique encoding of itself — which is what makes a signature over these
   * bytes mean anything. Bytes that fail to decode at all carry no signature
   * this client could check — there is no claim here to call false, only
   * garbage that never became one — so this is `unreachable`, the same class
   * as the transport failures in `#request`, not `signature-invalid`.
   */
  #decode<T>(
    decoder: (bytes: Uint8Array) => T,
    bytes: Uint8Array,
    window: bigint | null,
    what: string,
  ): T | null {
    try {
      return decoder(bytes);
    } catch (error) {
      return this.#reject(
        "unreachable",
        window,
        `the ${what} is not canonical: ${
          error instanceof Error ? error.message : "unknown error"
        }`,
        null,
      );
    }
  }

  #record(
    kind: StoreFaultKind,
    window: bigint | null,
    detail: string,
    evidence?: readonly Uint8Array[],
  ): void {
    const list = BLAME_FAULT_KINDS.has(kind) ? this.#blame : this.#reports;
    if (list.length >= MAX_RECORDED_FAULTS) return;
    list.push({
      order: this.#faultOrder++,
      fault: {
        storeIdHex: this.storeIdHex,
        kind,
        window,
        detail,
        // Kept with the descriptor the answers name, which `connect` pinned.
        ...(evidence === undefined
          ? {}
          : {
              evidence: evidence.map(copyBytes),
              descriptor: copyDescriptor(this.#descriptor),
            }),
      },
    });
  }

  /** Record a fault and answer with the caller's degraded value. */
  #reject<T>(
    kind: StoreFaultKind,
    window: bigint | null,
    detail: string,
    value: T,
  ): T {
    this.#record(kind, window, detail);
    return value;
  }

  /**
   * Record a fault this store cannot blame on absence, and go inert. Nothing
   * it signed is taken as verified any more: the next scan re-decides the
   * whole observed run.
   */
  #breach<T>(
    kind: StoreFaultKind,
    window: bigint,
    detail: string,
    value: T,
  ): T {
    this.#inert = true;
    this.#verified = null;
    return this.#reject(kind, window, detail, value);
  }

  /**
   * Verify the checkpoint answer for `window`.
   *
   * The descriptor served beside a checkpoint is what makes the evidence
   * portable, so it — not the pinned copy — is what structural validity is
   * decided against. It must still be the same store identity: accepting a
   * checkpoint under another key would let a store swap identities mid-scan
   * and keep its reputation.
   */
  async #readCheckpoint(
    window: bigint,
    bytes: Uint8Array | null,
    span: StoreReadSpan,
  ): Promise<
    | {
        readonly kind: "finalized";
        readonly checkpoint: PublicStoreCheckpointV1;
        readonly descriptor: StoreDescriptorV1;
      }
    | { readonly kind: "status"; readonly status: WindowScan["status"] }
  > {
    const unusable = { kind: "status", status: "unreachable" } as const;
    if (bytes === null) return unusable;

    const read = this.#decode(
      decodePublicStoreCheckpointReadV1,
      bytes,
      window,
      "checkpoint read",
    );
    if (read === null) return unusable;

    if (read.kind === "status")
      return {
        kind: "status",
        status: await this.#judgeSignedRefusal(
          window,
          {
            route: "checkpoint",
            value: read.value,
            storeSignature: read.storeSignature,
          },
          bytes,
          span,
        ),
      };

    const { descriptor, checkpoint } = read;
    // Which key may sign at all is the one question that has to precede
    // verification: a signature checked under a key the same answer carried
    // proves nothing about the store this client pinned.
    if (!bytesEqual(descriptor.storeIdentityEd25519Key, this.#storeKey))
      return this.#reject(
        "descriptor-invalid",
        window,
        "the checkpoint was served under a different store identity",
        unusable,
      );

    // This is where the checkpoint signature is checked, so nothing below
    // reads a field of an unverified body. The descriptor must have been
    // valid when this window was finalized, not now: historical evidence must
    // not depend on today's clock.
    const validity = await structurallyValidCheckpoint(
      descriptor,
      checkpoint,
      this.#geometry,
      windowFinalizationInstantMs(window, this.#profile),
      this.#module,
    );
    if (!validity.valid)
      return this.#reject(
        "signature-invalid",
        window,
        `the checkpoint is not structurally valid: ${validity.reason}`,
        unusable,
      );

    if (checkpoint.version !== 1)
      return this.#reject(
        "signature-invalid",
        window,
        "unsupported checkpoint version",
        unusable,
      );
    if (
      checkpoint.ingressWindow !== window ||
      !bytesEqual(checkpoint.deliveryProfileHash, this.#profileHash)
    )
      return this.#reject(
        "signature-invalid",
        window,
        "the checkpoint names another window or delivery profile",
        unusable,
      );
    // `structurallyValidCheckpoint` judges the chain start against the
    // descriptor served beside the checkpoint, which is what keeps the
    // evidence portable. This client also pinned one, and a checkpoint
    // anchored elsewhere under the same key is a store restarting its chain —
    // which, unobserved beside a second window, nothing downstream would see.
    if (checkpoint.chainStartIngressWindow !== this.#chainStart)
      return this.#reject(
        "descriptor-invalid",
        window,
        "the checkpoint is anchored to a chain start this store did not pin",
        unusable,
      );
    return { kind: "finalized", checkpoint, descriptor };
  }

  /**
   * Verify every chunk of every class for `window`.
   *
   * A chunk is only usable once it is this store's signature over these exact
   * coordinates, this exact object count, this class's exact object length,
   * and the hash of the chunk before it. Everything a store could otherwise
   * do — relocate an object between classes or windows, shorten a chunk,
   * reorder the sequence — is one of those checks.
   *
   * The signature is checked first and the rest after, in both branches. The
   * conjunction would be fail-closed either way, but a reader should not have
   * to prove that: nothing here reads a field of a body whose signature has
   * not verified.
   */
  async #readChunks(
    window: bigint,
    classes: readonly {
      readonly id: number;
      readonly publicChunksPerWindow: number;
    }[],
    chunkBytes: readonly (readonly (Uint8Array | null)[])[],
    span: StoreReadSpan,
    checkpointBytes: Uint8Array,
  ): Promise<
    | {
        readonly kind: "finalized";
        readonly chunksByClass: ReadonlyMap<number, readonly PublicChunkV1[]>;
        readonly hashesByClass: ReadonlyMap<number, readonly Uint8Array[]>;
      }
    | { readonly kind: "status"; readonly status: WindowScan["status"] }
  > {
    const unusable = { kind: "status", status: "unreachable" } as const;
    const chunksByClass = new Map<number, PublicChunkV1[]>();
    const hashesByClass = new Map<number, Uint8Array[]>();

    for (let classIndex = 0; classIndex < classes.length; classIndex++) {
      const sizeClass = classes[classIndex];
      const objectBytes = this.#objectBytesByClass.get(sizeClass.id);
      if (objectBytes === undefined)
        return this.#reject(
          "signature-invalid",
          window,
          `no size class with id ${String(sizeClass.id)} in this profile`,
          unusable,
        );

      const verifiedChunks: PublicChunkV1[] = [];
      const hashes: Uint8Array[] = [];
      let previousChunkHash = ZERO32;

      for (let index = 0; index < sizeClass.publicChunksPerWindow; index++) {
        const bytes = chunkBytes[classIndex][index];
        if (bytes === null) return unusable;
        const read = this.#decode(
          decodePublicChunkReadV1,
          bytes,
          window,
          "chunk read",
        );
        if (read === null) return unusable;

        // A refusal for a chunk of a window whose checkpoint this scan has
        // just verified: judged by the same order as a checkpoint refusal,
        // with that checkpoint beside it.
        if (read.kind === "status")
          return {
            kind: "status",
            status: await this.#judgeSignedRefusal(
              window,
              {
                route: "chunk",
                value: read.value,
                storeSignature: read.storeSignature,
                sizeClass: sizeClass.id,
                chunkIndex: index,
                checkpointBytes,
              },
              bytes,
              span,
            ),
          };

        const chunk = read.chunk;
        if (chunk.version !== 1)
          return this.#reject(
            "signature-invalid",
            window,
            "unsupported chunk version",
            unusable,
          );
        // The signature comes before every other question about this chunk:
        // its coordinates, its object count, its object lengths and its link
        // to the chunk before it are all claims, and an unsigned claim is not
        // one this client should be reasoning about at all.
        const { storeSignature, ...body } = chunk;
        const verified = await verify(
          await publicChunkSigningHash(body),
          storeSignature,
          this.#storeKey,
          this.#module,
        );
        if (!verified)
          return this.#reject(
            "signature-invalid",
            window,
            "the chunk signature does not verify",
            unusable,
          );

        if (
          !bytesEqual(chunk.bucket.deliveryProfileHash, this.#profileHash) ||
          chunk.bucket.ingressWindow !== window ||
          chunk.bucket.sizeClass !== sizeClass.id ||
          chunk.chunkIndex !== BigInt(index)
        )
          return this.#reject(
            "signature-invalid",
            window,
            "the chunk does not name the coordinates that were requested",
            unusable,
          );
        if (chunk.fixedObjects.length !== this.#profile.publicChunkObjectCount)
          return this.#reject(
            "signature-invalid",
            window,
            "the chunk does not hold the profile's fixed object count",
            unusable,
          );
        for (const object of chunk.fixedObjects)
          if (object.length !== objectBytes)
            return this.#reject(
              "signature-invalid",
              window,
              "a carrier object is not this size class's exact wire length",
              unusable,
            );
        if (!bytesEqual(chunk.previousChunkHash, previousChunkHash))
          return this.#reject(
            "signature-invalid",
            window,
            `chunk ${String(index)} of class ${String(sizeClass.id)} does not link to its predecessor`,
            unusable,
          );

        previousChunkHash = await publicChunkHash(chunk);
        verifiedChunks.push(chunk);
        hashes.push(previousChunkHash);
      }

      chunksByClass.set(sizeClass.id, verifiedChunks);
      hashesByClass.set(sizeClass.id, hashes);
    }

    return { kind: "finalized", chunksByClass, hashesByClass };
  }

  /**
   * Add this scan's checkpoint to the run and decide the chain, checking only
   * what the checkpoint adds.
   *
   * `checkpoint` is one `#readCheckpoint` verified in this same scan:
   * structurally valid under the descriptor served beside it (signature,
   * descriptor, store, profile, chain start, count), naming this store, this
   * profile and the pinned chain start. What `verifyStoreCheckpointChain`
   * decides beyond that is local: two checkpoints for one window, and each
   * window's link to the one before. So when the verified run is held under
   * the same descriptor, a checkpoint already in it adds nothing, and a new
   * one is checked against its two neighbours by the hashes kept for them.
   * Everything else re-decides the whole observed run with
   * `verifyStoreCheckpointChain`, exactly as before the run was kept: no run
   * (the first scan, or after blame), a checkpoint served under another
   * descriptor, a second checkpoint for a window already in the run, or one
   * that does not link. The full verifier is also what names a fault, and a
   * run is only ever rebuilt from its blame-free verdict.
   *
   * The verifier is given the run rather than the pair because blame outranks
   * absence: a conflict or a broken predecessor anywhere in what this client
   * holds must be reported even when a later window is missing.
   */
  async #verifyChain(
    window: bigint,
    checkpoint: PublicStoreCheckpointV1,
    descriptor: StoreDescriptorV1,
    checkpointHash: Uint8Array,
  ): Promise<void> {
    const key = String(window);
    const run = this.#verified;
    // `structurallyValidCheckpoint` tied `descriptorHash` to the descriptor
    // served beside this checkpoint, so it names that descriptor.
    if (
      run !== null &&
      bytesEqual(run.descriptorHash, checkpoint.descriptorHash)
    ) {
      const held = run.hashes.get(key);
      if (held !== undefined && bytesEqual(held, checkpointHash)) return;
      if (
        held === undefined &&
        this.#extendsRun(run, checkpoint, checkpointHash)
      ) {
        const observation = this.#observation(
          window,
          checkpoint,
          descriptor,
          checkpointHash,
        );
        this.#observe(observation);
        // A full run that dropped this very observation as its oldest keeps
        // the run equal to what is observed.
        if (this.#observed.includes(observation))
          run.hashes.set(key, copyBytes(checkpointHash));
        return;
      }
    }

    this.#observe(
      this.#observation(window, checkpoint, descriptor, checkpointHash),
    );
    this.#verified = null;
    const verdict = await verifyStoreCheckpointChain(
      this.#observed,
      this.#geometry,
      this.#module,
    );
    // A gap is the one blame-free outcome besides success: it says this client
    // did not observe enough, which no proof can attribute to the store.
    if (
      verdict.outcome === "chain-verified" ||
      verdict.outcome === "unverified-chain-gap"
    ) {
      const hashes = new Map<string, Uint8Array>();
      for (const observed of this.#observed) {
        const hash = this.#observedHashes.get(observed);
        if (hash === undefined) return;
        hashes.set(String(observed.checkpoint.ingressWindow), hash);
      }
      this.#verified = {
        descriptorHash: copyBytes(checkpoint.descriptorHash),
        hashes,
      };
      return;
    }
    this.#breach(
      "chain-fault",
      window,
      `${verdict.outcome}: ${verdict.reason}`,
      undefined,
    );
  }

  #observation(
    window: bigint,
    checkpoint: PublicStoreCheckpointV1,
    descriptor: StoreDescriptorV1,
    checkpointHash: Uint8Array,
  ): ObservedStoreCheckpoint {
    const observation: ObservedStoreCheckpoint = {
      checkpoint,
      descriptor,
      finalizationInstantUnixMs: windowFinalizationInstantMs(
        window,
        this.#profile,
      ),
    };
    this.#observedHashes.set(observation, copyBytes(checkpointHash));
    return observation;
  }

  /**
   * Whether a checkpoint for a window the run does not hold is consistent with
   * it: the run's store, profile and chain start, a predecessor hash equal to
   * the kept hash of the window before, and the kept window after naming this
   * checkpoint's hash as its predecessor. These are the questions
   * `verifyStoreCheckpointChain` asks of a pair beyond structural validity
   * (`chainLinksSuccessor`), asked only of the pairs this checkpoint is in.
   */
  #extendsRun(
    run: VerifiedRun,
    checkpoint: PublicStoreCheckpointV1,
    checkpointHash: Uint8Array,
  ): boolean {
    const window = checkpoint.ingressWindow;
    if (
      !bytesEqual(checkpoint.storeId, this.#storeId) ||
      !bytesEqual(checkpoint.deliveryProfileHash, this.#profileHash) ||
      checkpoint.chainStartIngressWindow !== this.#chainStart
    )
      return false;
    const previous = run.hashes.get(String(window - 1n));
    if (
      previous !== undefined &&
      !bytesEqual(checkpoint.previousCheckpointHash, previous)
    )
      return false;
    const next = this.#observed.find(
      (held) => held.checkpoint.ingressWindow === window + 1n,
    );
    return (
      next === undefined ||
      bytesEqual(next.checkpoint.previousCheckpointHash, checkpointHash)
    );
  }

  /**
   * Keep the run sorted by ingress window, and keep both sides of a same-window
   * disagreement: dropping the second one would erase the equivocation.
   */
  #observe(observation: ObservedStoreCheckpoint): void {
    const window = observation.checkpoint.ingressWindow;
    for (const held of this.#observed)
      if (
        held.checkpoint.ingressWindow === window &&
        bytesEqual(
          held.checkpoint.storeSignature,
          observation.checkpoint.storeSignature,
        )
      )
        return;

    let position = this.#observed.length;
    while (
      position > 0 &&
      this.#observed[position - 1].checkpoint.ingressWindow > window
    )
      position--;
    this.#observed.splice(position, 0, observation);
    if (this.#observed.length > MAX_OBSERVED_CHECKPOINTS) {
      const dropped = this.#observed.shift();
      // The run holds one observation per window, so the dropped window
      // leaves it too; a neighbour of it is then checked as a run edge.
      if (dropped !== undefined)
        this.#verified?.hashes.delete(String(dropped.checkpoint.ingressWindow));
    }
  }

  /**
   * Compare every receipt for this window against the slot the geometry says
   * it must occupy, and report every append to it still unanswered.
   *
   * This is exactly the specification's custody-breach contradiction: the
   * store signed that it stored these bytes at coordinates derived only from
   * public values, and the window it finalized says otherwise.
   *
   * Every object is hashed first, and only then — with no `await` from there
   * to the end — are this window's receipts claimed and the hashes kept. So a
   * receipt recorded or an answer arriving while the hashes were computed is
   * seen exactly once: by this claim, or by `recordReceipt` judging it against
   * the kept hashes afterwards.
   *
   * A window whose slot hashes are already kept is not hashed again: the
   * first finalized scan's hashes are the custody baseline whatever a later
   * scan of the window shows, and they are what its receipts are judged
   * against.
   */
  async #verifyCustody(
    window: bigint,
    chunksByClass: ReadonlyMap<number, readonly PublicChunkV1[]>,
  ): Promise<void> {
    let hashes = this.#scannedSlots.get(String(window))?.hashes;
    if (hashes === undefined) {
      const computed = new Map<string, Uint8Array>();
      for (const [sizeClass, chunks] of chunksByClass)
        for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex++) {
          const objects = chunks[chunkIndex].fixedObjects;
          for (let index = 0; index < objects.length; index++)
            computed.set(
              slotKeyOf(sizeClass, BigInt(chunkIndex), index),
              await sha256(objects[index]),
            );
        }
      hashes = computed;
      // The first finalized scan's hashes are the ones kept: a later branch
      // of an equivocating store is the chain verifier's evidence, not a
      // second custody baseline. A scan that overlapped this one may have
      // kept its own first.
      if (!this.#scannedSlots.has(String(window)))
        this.#keepScannedSlots(window, computed);
    }

    const receipts = this.#receipts.filter(
      (receipt) => receipt.window === window,
    );
    this.#receipts = this.#receipts.filter(
      (receipt) => receipt.window !== window,
    );
    for (const receipt of receipts) this.#judgeReceipt(receipt, hashes);

    for (const entry of this.#inFlight) {
      if (entry.window !== window || entry.reported) continue;
      entry.reported = true;
      this.#record(
        "custody-unacknowledged",
        window,
        `the append to slot ${entry.slotKey} was still unanswered when this window was read`,
      );
    }
  }

  /**
   * Judge one signed refusal of a read of `window`: steps 1 and 2 of
   * `judgeSignedRefusal`'s order here, steps 3 to 7 by that function, and
   * then what each outcome does. Every checkpoint status and every chunk
   * status goes through this and nothing else.
   *
   * Blame marks the window unreadable, sets `inert` and keeps the evidence.
   * A report keeps the window's receipts for a later read, except where this
   * client will make none it believes: after `beyond-retention`, and once
   * its own clock is past the pinned descriptor's end.
   */
  async #judgeSignedRefusal(
    window: bigint,
    refusal: SignedRefusalRead,
    bytes: Uint8Array,
    span: StoreReadSpan,
  ): Promise<
    | "not-final"
    | "beyond-retention"
    | "clock-disagreement"
    | "descriptor-out-of-validity"
    | "unreachable"
  > {
    const unusable = "unreachable" as const;
    const noun =
      refusal.route === "checkpoint" ? "checkpoint status" : "chunk status";

    // Step 1. The version is the only field read before the signature: it is
    // the "is this a shape I can hash at all" question, and the transcript is
    // the canonical encoding of exactly this type. Every other field is read
    // after the signature over the whole body verifies.
    if (refusal.value.version !== 1)
      return this.#reject(
        "signature-invalid",
        window,
        `unsupported ${noun} version`,
        unusable,
      );
    const verified = await verify(
      refusal.route === "checkpoint"
        ? await publicCheckpointStatusSigningHash(refusal.value)
        : await publicChunkStatusSigningHash(refusal.value),
      refusal.storeSignature,
      this.#storeKey,
      this.#module,
    );
    if (!verified)
      return this.#reject(
        "signature-invalid",
        window,
        `the ${noun} signature does not verify`,
        unusable,
      );
    let statement: SignedStoreStatusStatement;
    let what: string;
    if (refusal.route === "checkpoint") {
      const value = refusal.value;
      if (
        !bytesEqual(value.storeId, this.#storeId) ||
        !bytesEqual(value.deliveryProfileHash, this.#profileHash) ||
        value.ingressWindow !== window
      )
        return this.#reject(
          "signature-invalid",
          window,
          "the checkpoint status does not name this store, profile and window",
          unusable,
        );
      what = "the checkpoint";
      statement = {
        route: "checkpoint",
        status: value.status,
        deliveryProfileHash: this.#profileHash,
        window,
        storeWindow: value.storeIngressWindow,
      };
    } else {
      // A chunk status carries no store id: the signature under the pinned
      // key is what binds it to this store.
      const value = refusal.value;
      if (
        !bytesEqual(value.bucket.deliveryProfileHash, this.#profileHash) ||
        value.bucket.ingressWindow !== window ||
        value.bucket.sizeClass !== refusal.sizeClass ||
        value.chunkIndex !== BigInt(refusal.chunkIndex)
      )
        return this.#reject(
          "signature-invalid",
          window,
          "the chunk status does not name the chunk that was requested",
          unusable,
        );
      what = `chunk ${String(refusal.chunkIndex)} of class ${String(refusal.sizeClass)}`;
      statement = {
        route: "chunk",
        status: value.status,
        deliveryProfileHash: this.#profileHash,
        window,
        storeWindow: value.storeIngressWindow,
        sizeClass: refusal.sizeClass,
        chunkIndex: value.chunkIndex,
      };
    }

    // Step 2. Judged against the descriptor it names and no other: one this
    // client does not hold could state any retention.
    if (!bytesEqual(refusal.value.descriptorHash, this.#descriptorHash))
      return this.#reject(
        "signature-invalid",
        window,
        `the ${noun} names a descriptor other than the one this client pinned`,
        unusable,
      );

    // Steps 3 to 7. Every chunk asked for is one the profile defines (the
    // scan derives each request from it), and a chunk status is judged only
    // after this scan verified the window's checkpoint, which commits to it.
    const judgment = judgeSignedRefusal(
      statement,
      this.#descriptor,
      this.#profile,
      span,
      refusal.route === "chunk",
    );
    const stated = `the store signed ${statement.status} for ${what} at its own window ${String(statement.storeWindow)}`;
    const skew = String(this.#profile.maxScheduleSkewMs);
    const during = `${String(span.sentMs)} to ${String(span.receivedMs)} ms`;
    switch (judgment.outcome) {
      case "retention-breach":
        return this.#blameOnEvidence(
          judgment.outcome,
          window,
          `${stated}, which puts this window inside the ${String(this.#descriptor.retentionWindows)}-window retention its descriptor states`,
          [bytes],
        );
      case "finalization-breach":
        return this.#blameOnEvidence(
          judgment.outcome,
          window,
          `${stated}, which begins at or after this window's finalization instant`,
          [bytes],
        );
      case "chain-denial-breach":
        return this.#blameOnEvidence(
          judgment.outcome,
          window,
          `${stated}, denying a profile chain its own descriptor declares`,
          [bytes],
        );
      case "chunk-denial-breach":
        return this.#blameOnEvidence(
          judgment.outcome,
          window,
          `${stated}, denying a chunk that the checkpoint it signed for this window commits to`,
          refusal.route === "chunk"
            ? [refusal.checkpointBytes, bytes]
            : [bytes],
        );
      case "store-clock-disagreement":
        this.#record(
          "store-clock-disagreement",
          window,
          judgment.step === 4
            ? `${stated}, a window no clock within ${skew} ms of this client's showed while the request was out (${during}); not read at this store this time`
            : `${stated}, and the request left at ${String(span.sentMs)} ms on this client's clock, at or after this window's finalization instant plus the ${skew} ms skew; not read at this store this time`,
        );
        return "clock-disagreement";
      case "descriptor-out-of-validity":
        // Past the descriptor's end on this client's own clock, no later
        // read of this window will be believed either: its receipts are
        // reported now instead of held.
        if (span.receivedMs >= this.#descriptor.notAfterUnixMs)
          this.#markUnreadable(window);
        this.#record(
          "descriptor-out-of-validity",
          window,
          `${stated}; the pinned descriptor's validity (${String(this.#descriptor.notBeforeUnixMs)} to ${String(this.#descriptor.notAfterUnixMs)} ms) does not cover that whole window and this client's clock during the read (${during}); not read at this store`,
        );
        return "descriptor-out-of-validity";
      case "beyond-retention":
        this.#markUnreadable(window);
        return "beyond-retention";
      case "not-final":
        return "not-final";
      case "no-benign-meaning":
        return this.#reject(
          "signature-invalid",
          window,
          `${stated}, which answers no read this client makes`,
          unusable,
        );
    }
  }

  /**
   * Record a fault the store's own signed answers prove, keep them, and go
   * inert. The window will not be read back from this store.
   */
  #blameOnEvidence(
    kind: StoreEvidenceFaultKind,
    window: bigint,
    detail: string,
    evidence: readonly Uint8Array[],
  ): "unreachable" {
    this.#markUnreadable(window);
    this.#inert = true;
    this.#verified = null;
    this.#record(kind, window, detail, evidence);
    return "unreachable";
  }

  #markUnreadable(window: bigint): void {
    const key = String(window);
    if (this.#unreadable.has(key)) return;
    this.#unreadable.add(key);
    while (this.#unreadable.size > MAX_SCANNED_WINDOWS) {
      const oldest = this.#unreadable.values().next();
      if (oldest.done) break;
      this.#unreadable.delete(oldest.value);
    }
  }

  /**
   * After a scan that will never read `window` back from this store, report
   * the receipts held for it as unchecked instead of keeping them for a scan
   * that cannot come. A receipt that arrives later is reported on arrival
   * (`recordReceipt`); an append that is never answered promised nothing.
   */
  #unreadableOutcome(window: bigint, scan: WindowScan): WindowScan {
    if (!this.#unreadable.has(String(window))) return scan;
    const claimed = this.#receipts.filter(
      (receipt) => receipt.window === window,
    ).length;
    this.#receipts = this.#receipts.filter(
      (receipt) => receipt.window !== window,
    );
    this.#reportUnchecked(window, claimed);
    return scan;
  }

  #reportUnchecked(window: bigint, count: number): void {
    if (count === 0) return;
    this.#record(
      "custody-unchecked",
      window,
      `${String(count)} append receipt(s) for a window this store will not serve back were not checked`,
    );
  }

  /** Keep one window's slot hashes, dropping the oldest window past the cap. */
  #keepScannedSlots(window: bigint, hashes: Map<string, Uint8Array>): void {
    this.#scannedSlots.set(String(window), { window, hashes });
    while (this.#scannedSlots.size > MAX_SCANNED_WINDOWS) {
      let oldest: { readonly window: bigint } | null = null;
      for (const held of this.#scannedSlots.values())
        if (oldest === null || held.window < oldest.window) oldest = held;
      if (oldest === null) break;
      this.#scannedSlots.delete(String(oldest.window));
    }
  }

  /** One receipt against one scan's slot hashes; synchronous by design. */
  #judgeReceipt(
    receipt: AppendReceipt,
    hashes: ReadonlyMap<string, Uint8Array>,
  ): void {
    // Only a promise of custody can be breached: a refused or unallocated
    // append committed the store to nothing. Allocated client cover that
    // received `stored` carries exactly the same promise as real data.
    if (
      receipt.result.status !== "stored" &&
      receipt.result.status !== "already-present"
    )
      return;

    const coordinates = appendSlotCoordinates(
      this.#geometry,
      receipt.sizeClass,
      receipt.lease.allocationOrdinal,
      receipt.objectOrdinal,
    );
    const held = hashes.get(
      slotKeyOf(
        receipt.sizeClass,
        coordinates.chunkIndex,
        coordinates.objectIndexWithinChunk,
      ),
    );
    if (held === undefined) {
      this.#breach(
        "custody-breach",
        receipt.window,
        "the window holds no chunk for a slot this store signed a receipt for",
        undefined,
      );
      return;
    }
    if (!bytesEqual(held, receipt.objectHash))
      this.#breach(
        "custody-breach",
        receipt.window,
        `the object at class ${String(receipt.sizeClass)} chunk ${String(coordinates.chunkIndex)} slot ${String(coordinates.objectIndexWithinChunk)} is not the one this store received`,
        undefined,
      );
  }
}
