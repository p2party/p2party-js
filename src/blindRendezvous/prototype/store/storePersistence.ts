/**
 * The prototype store's durable state, and the in-memory implementation the
 * tests and the E2E's ephemeral mode run on.
 *
 * Windows store public geometry and opaque object bytes, plus allocation
 * public keys and request hashes. An optional experimental admission mode
 * also retains an opaque quota key per allocation. That key links uses of the
 * same admission grant; it is not a room identifier or a claim of unique-person
 * identity. The private database exposes more metadata than public chunks.
 *
 * The port is whole-window replace rather than per-row upsert. A window is the
 * unit the specification makes atomic — allocation ordinals, slot bindings and
 * the finalization that freezes both — so a single `saveWindow` is the
 * smallest transaction that can never publish half a finalization. The SQLite
 * implementation (`storeSqlite.ts`) sits behind this same interface.
 *
 * Every row is deletable by window: a window row carries its own allocation
 * records (and their admission quota keys) and goes with the precomputed
 * responses built from it, and a witness window carries its records and the
 * per-key counts that bound them, so the retention sweep removes a window's
 * bookkeeping by removing the window.
 *
 * Status: PROTOTYPE. This is the `prototype-v1` route family, not a frozen
 * registry.
 */

import { encodeStoreWitnessRecordV1 } from "../storeWire";

import type {
  PublicAllocationLeaseBodyV1,
  PublicAllocationLeaseV1,
  StoreWitnessRecordV1,
} from "../storeWire";
import type {
  PublicBucketV1,
  PublicChunkV1,
  PublicStoreCheckpointV1,
} from "../../publicWindow";

/** One bound append position: the object and the hash that binds it. */
export interface StoreWindowSlot {
  objectHash: Uint8Array;
  object: Uint8Array;
}

/**
 * One issued lease, kept so an exact duplicate allocation request replays the
 * byte-identical result instead of consuming a second ordinal.
 */
export interface StoreAllocationRecord {
  leaseBody: PublicAllocationLeaseBodyV1;
  lease: PublicAllocationLeaseV1;
  requestHash: Uint8Array;
  /** Optional admission grant quota key, exactly 32 bytes; never on the wire. */
  admissionQuotaKey32?: Uint8Array;
}

/** The immutable half of a window: signed once, then never re-signed. */
export interface StoreFinalizedWindow {
  chunks: Map<number, PublicChunkV1[]>;
  checkpoint: PublicStoreCheckpointV1;
}

export interface StoreWindowState {
  readonly window: bigint;
  allocations: Map<number, StoreAllocationRecord>;
  /** Keyed `${sizeClass}:${chunkIndex}:${objectIndexWithinChunk}`. */
  slots: Map<string, StoreWindowSlot>;
  finalized: StoreFinalizedWindow | null;
}

/**
 * The exact response bodies a finalized window is read back as.
 *
 * A finalized window never changes, so the bytes a chunk GET and a checkpoint
 * GET answer with once the clock has let the read through are fixed the
 * instant the window is signed: nothing in them depends on when the request
 * arrives. Keeping them lets such a read return one row instead of decoding
 * the whole window. Every signed status, which names the store's window at
 * the time of the request, is still built per request. `descriptorHash` is
 * carried because the checkpoint response embeds the store's descriptor: a
 * row written under another descriptor than the one this process serves is
 * ignored rather than replayed.
 */
export interface StoreFinalizedResponses {
  readonly window: bigint;
  readonly descriptorHash: Uint8Array;
  readonly checkpoint: Uint8Array;
  readonly chunks: readonly {
    readonly sizeClass: number;
    readonly chunkIndex: bigint;
    readonly body: Uint8Array;
  }[];
}

/** How much one witness insert may fill. */
export interface StoreWitnessBounds {
  /** Distinct records one window may hold, from every caller together. */
  readonly maxRecordsPerWindow: number;
  /**
   * The admission quota key the record is offered under, exactly 32 bytes,
   * or `null` when the store runs open admission and has no key to charge.
   */
  readonly quotaKey32: Uint8Array | null;
  /** New records one quota key may add to one window. */
  readonly maxRecordsPerQuotaKey: number;
}

/**
 * `present`: those exact canonical bytes are already held for the window, and
 * nothing was charged to anybody. `window-full` and `quota-full`: nothing was
 * written.
 */
export type StoreWitnessInsertOutcome =
  "added" | "present" | "window-full" | "quota-full";

export interface StorePersistencePort {
  loadWindow(window: bigint): Promise<StoreWindowState | null>;
  /** Whole-window replace; the implementation must not alias caller buffers. */
  saveWindow(state: StoreWindowState): Promise<void>;
  lastFinalizedWindow(): Promise<bigint | null>;
  loadWitnessRecords(window: bigint): Promise<StoreWitnessRecordV1[]>;
  /**
   * Add one record if its window and the offering key both have room, in one
   * atomic step. Idempotent on identical canonical bytes, and constant work in
   * the number of records the window already holds: an implementation keeps
   * counts rather than reading the window's records to decide.
   */
  addWitnessRecord(
    record: StoreWitnessRecordV1,
    bounds: StoreWitnessBounds,
  ): Promise<StoreWitnessInsertOutcome>;
  /**
   * Delete up to `limit` window rows below `window`, smallest first, and
   * answer how many went. Each row takes its allocation records and its
   * precomputed responses with it, in the same step: a response row that
   * outlived its window would be the only trace of it left.
   */
  deleteWindowsBefore(window: bigint, limit: number): Promise<number>;
  /**
   * Delete the witness records of up to `limit` windows below `window`,
   * smallest first, with the counts that bound them, and answer how many
   * windows went.
   */
  deleteWitnessRecordsBefore(window: bigint, limit: number): Promise<number>;

  /* ---------------------------------------------------------------- *
   * Precomputed finalized responses: optional, and the store answers the
   * same bytes without them.
   *
   * They are an accelerator, not a source of truth. An implementation may
   * omit them (`MemoryStorePersistence` does), and a window finalized before
   * they were written, or whose rows failed to save, has none; the core then
   * answers from `loadWindow`. They are consulted only after the clock has
   * decided that the read is of a finalized, retained window, so a row never
   * answers for a window the clock refuses.
   * ---------------------------------------------------------------- */

  /** Called after `saveWindow` has committed the finalization, never before:
   * a row that outlived a finalization that did not commit would be replayed
   * against a re-finalized window whose cover bytes are different. */
  saveFinalizedResponses?(responses: StoreFinalizedResponses): Promise<void>;
  loadChunkResponse?(
    window: bigint,
    sizeClass: number,
    chunkIndex: bigint,
  ): Promise<Uint8Array | null>;
  /** Null unless a row exists *and* was written under `descriptorHash`. */
  loadCheckpointResponse?(
    window: bigint,
    descriptorHash: Uint8Array,
  ): Promise<Uint8Array | null>;
}

export const emptyStoreWindowState = (window: bigint): StoreWindowState => ({
  window,
  allocations: new Map(),
  slots: new Map(),
  finalized: null,
});

/* ------------------------------------------------------------------ *
 * Structured copies
 *
 * Every boundary crossing copies. A caller that keeps a reference to bytes it
 * handed the store, or to bytes the store handed back, must not be able to
 * mutate a finalized chunk after it has been signed.
 *
 * `storeCore.ts` copies the same values on the request and response paths, so
 * these are exported rather than written twice: one definition of "how a
 * chunk is copied" is what keeps a later wire field from being copied in one
 * place and aliased in the other.
 * ------------------------------------------------------------------ */

export const copyBytes = (value: Uint8Array): Uint8Array =>
  Uint8Array.from(value);

export const copyBucket = (bucket: PublicBucketV1): PublicBucketV1 => ({
  deliveryProfileHash: copyBytes(bucket.deliveryProfileHash),
  ingressWindow: bucket.ingressWindow,
  sizeClass: bucket.sizeClass,
});

const copyLeaseBody = (
  body: PublicAllocationLeaseBodyV1,
): PublicAllocationLeaseBodyV1 => ({
  version: body.version,
  storeId: copyBytes(body.storeId),
  deliveryProfileHash: copyBytes(body.deliveryProfileHash),
  ingressWindow: body.ingressWindow,
  requestHash: copyBytes(body.requestHash),
  allocationOrdinal: body.allocationOrdinal,
  allocationEd25519PublicKey: copyBytes(body.allocationEd25519PublicKey),
});

export const copyLease = (
  lease: PublicAllocationLeaseV1,
): PublicAllocationLeaseV1 => ({
  ...copyLeaseBody(lease),
  storeSignature: copyBytes(lease.storeSignature),
});

const copyAllocation = (
  record: StoreAllocationRecord,
): StoreAllocationRecord => ({
  leaseBody: copyLeaseBody(record.leaseBody),
  lease: copyLease(record.lease),
  requestHash: copyBytes(record.requestHash),
  ...(record.admissionQuotaKey32 === undefined
    ? {}
    : { admissionQuotaKey32: copyBytes(record.admissionQuotaKey32) }),
});

const copySlot = (slot: StoreWindowSlot): StoreWindowSlot => ({
  objectHash: copyBytes(slot.objectHash),
  object: copyBytes(slot.object),
});

export const copyChunk = (chunk: PublicChunkV1): PublicChunkV1 => ({
  version: chunk.version,
  bucket: copyBucket(chunk.bucket),
  chunkIndex: chunk.chunkIndex,
  previousChunkHash: copyBytes(chunk.previousChunkHash),
  fixedObjects: chunk.fixedObjects.map(copyBytes),
  storeSignature: copyBytes(chunk.storeSignature),
});

export const copyCheckpoint = (
  checkpoint: PublicStoreCheckpointV1,
): PublicStoreCheckpointV1 => ({
  version: checkpoint.version,
  storeId: copyBytes(checkpoint.storeId),
  descriptorHash: copyBytes(checkpoint.descriptorHash),
  deliveryProfileHash: copyBytes(checkpoint.deliveryProfileHash),
  ingressWindow: checkpoint.ingressWindow,
  chainStartIngressWindow: checkpoint.chainStartIngressWindow,
  previousCheckpointHash: copyBytes(checkpoint.previousCheckpointHash),
  finalizedChunkCount: checkpoint.finalizedChunkCount,
  finalizedChunkRoot: copyBytes(checkpoint.finalizedChunkRoot),
  storeSignature: copyBytes(checkpoint.storeSignature),
});

export const copyWitnessRecord = (
  record: StoreWitnessRecordV1,
): StoreWitnessRecordV1 => ({
  version: record.version,
  witnessedStoreId: copyBytes(record.witnessedStoreId),
  deliveryProfileHash: copyBytes(record.deliveryProfileHash),
  ingressWindow: record.ingressWindow,
  checkpointHash: copyBytes(record.checkpointHash),
});

export const copyStoreWindowState = (
  state: StoreWindowState,
): StoreWindowState => ({
  window: state.window,
  allocations: new Map(
    [...state.allocations].map(([ordinal, record]) => [
      ordinal,
      copyAllocation(record),
    ]),
  ),
  slots: new Map([...state.slots].map(([key, slot]) => [key, copySlot(slot)])),
  finalized:
    state.finalized === null
      ? null
      : {
          chunks: new Map(
            [...state.finalized.chunks].map(([sizeClass, chunks]) => [
              sizeClass,
              chunks.map(copyChunk),
            ]),
          ),
          checkpoint: copyCheckpoint(state.finalized.checkpoint),
        },
});

/* ------------------------------------------------------------------ *
 * In-memory implementation
 * ------------------------------------------------------------------ */

export const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/** One window's witness records, keyed by canonical bytes, and per-key counts. */
interface MemoryWitnessWindow {
  readonly records: Map<string, StoreWitnessRecordV1>;
  readonly recordsByQuotaKey: Map<string, number>;
}

/** The `limit` smallest keys below `floor`, as the windows they name. */
const smallestBelow = (
  keys: Iterable<string>,
  floor: bigint,
  limit: number,
): bigint[] =>
  [...keys]
    .map((key) => BigInt(key))
    .filter((window) => window < floor)
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    .slice(0, Math.max(0, limit));

/**
 * Volatile store state for tests and for a store started without a database
 * path. It copies on the way in and on the way out, so the core's mutable
 * working state and the stored state are never the same objects — the same
 * isolation a real transaction gives, at the cost of the copy.
 */
export class MemoryStorePersistence implements StorePersistencePort {
  // Windows are u64, so a decimal string is the only lossless Map key.
  readonly #windows = new Map<string, StoreWindowState>();
  readonly #witnesses = new Map<string, MemoryWitnessWindow>();

  async loadWindow(window: bigint): Promise<StoreWindowState | null> {
    const stored = this.#windows.get(String(window));
    return stored === undefined ? null : copyStoreWindowState(stored);
  }

  async saveWindow(state: StoreWindowState): Promise<void> {
    this.#windows.set(String(state.window), copyStoreWindowState(state));
  }

  async lastFinalizedWindow(): Promise<bigint | null> {
    let latest: bigint | null = null;
    for (const state of this.#windows.values()) {
      if (state.finalized === null) continue;
      if (latest === null || state.window > latest) latest = state.window;
    }
    return latest;
  }

  async loadWitnessRecords(window: bigint): Promise<StoreWitnessRecordV1[]> {
    const stored = this.#witnesses.get(String(window));
    return stored === undefined
      ? []
      : [...stored.records.values()].map(copyWitnessRecord);
  }

  /** No `await` between the checks and the writes, so the step is atomic. */
  async addWitnessRecord(
    record: StoreWitnessRecordV1,
    bounds: StoreWitnessBounds,
  ): Promise<StoreWitnessInsertOutcome> {
    const key = String(record.ingressWindow);
    // Keyed by the canonical encoding, which is what makes a re-offer of the
    // same observation a no-op rather than a second row.
    const encoded = hexOf(encodeStoreWitnessRecordV1(record));
    const held = this.#witnesses.get(key) ?? {
      records: new Map<string, StoreWitnessRecordV1>(),
      recordsByQuotaKey: new Map<string, number>(),
    };
    if (held.records.has(encoded)) return "present";
    if (held.records.size >= bounds.maxRecordsPerWindow) return "window-full";
    const quotaKey =
      bounds.quotaKey32 === null ? null : hexOf(bounds.quotaKey32);
    const charged =
      quotaKey === null ? 0 : (held.recordsByQuotaKey.get(quotaKey) ?? 0);
    if (quotaKey !== null && charged >= bounds.maxRecordsPerQuotaKey)
      return "quota-full";

    held.records.set(encoded, copyWitnessRecord(record));
    if (quotaKey !== null) held.recordsByQuotaKey.set(quotaKey, charged + 1);
    this.#witnesses.set(key, held);
    return "added";
  }

  async deleteWindowsBefore(window: bigint, limit: number): Promise<number> {
    const doomed = smallestBelow(this.#windows.keys(), window, limit);
    for (const each of doomed) this.#windows.delete(String(each));
    return doomed.length;
  }

  async deleteWitnessRecordsBefore(
    window: bigint,
    limit: number,
  ): Promise<number> {
    const doomed = smallestBelow(this.#witnesses.keys(), window, limit);
    for (const each of doomed) this.#witnesses.delete(String(each));
    return doomed.length;
  }
}
