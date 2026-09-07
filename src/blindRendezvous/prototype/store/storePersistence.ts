/**
 * The prototype store's durable state, and the in-memory implementation the
 * tests and the E2E's ephemeral mode run on.
 *
 * Everything a store keeps is public geometry: a delivery-profile hash, an
 * ingress window, a size class, an ordinal, and opaque object bytes. There is
 * deliberately no room, peer, member, or account key anywhere in these rows,
 * because a store that cannot name a room cannot be asked which rooms a
 * request belonged to.
 *
 * The port is whole-window replace rather than per-row upsert. A window is the
 * unit the specification makes atomic — allocation ordinals, slot bindings and
 * the finalization that freezes both — so a single `saveWindow` is the
 * smallest transaction that can never publish half a finalization. The SQLite
 * implementation lands in a later task behind this same interface.
 *
 * Status: PROTOTYPE. This is the `prototype-v0` route family, not a frozen
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

export interface StorePersistencePort {
  loadWindow(window: bigint): Promise<StoreWindowState | null>;
  /** Whole-window replace; the implementation must not alias caller buffers. */
  saveWindow(state: StoreWindowState): Promise<void>;
  lastFinalizedWindow(): Promise<bigint | null>;
  loadWitnessRecords(window: bigint): Promise<StoreWitnessRecordV1[]>;
  /** Idempotent on identical canonical bytes. */
  saveWitnessRecord(record: StoreWitnessRecordV1): Promise<void>;
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

const hexOf = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * Volatile store state for tests and for a store started without a database
 * path. It copies on the way in and on the way out, so the core's mutable
 * working state and the stored state are never the same objects — the same
 * isolation a real transaction gives, at the cost of the copy.
 */
export class MemoryStorePersistence implements StorePersistencePort {
  // Windows are u64, so a decimal string is the only lossless Map key.
  readonly #windows = new Map<string, StoreWindowState>();
  readonly #witnesses = new Map<string, Map<string, StoreWitnessRecordV1>>();

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
      : [...stored.values()].map(copyWitnessRecord);
  }

  async saveWitnessRecord(record: StoreWitnessRecordV1): Promise<void> {
    const key = String(record.ingressWindow);
    const existing = this.#witnesses.get(key) ?? new Map();
    // Keyed by the canonical encoding, which is what makes a re-offer of the
    // same observation a no-op rather than a second row.
    existing.set(
      hexOf(encodeStoreWitnessRecordV1(record)),
      copyWitnessRecord(record),
    );
    this.#witnesses.set(key, existing);
  }
}
