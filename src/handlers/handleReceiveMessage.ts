import { assertMetadataV1, deserializeMetadata } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { uint8ArrayToHex } from "../utils/uint8array";
import { isStorableChunkRange } from "../utils/chunkBounds";
import { createChunkReceiptToken } from "../utils/receiptToken";
import { DatabaseUnavailableError } from "../db/dbErrors";
import {
  MAX_REPORTED_RECEIVE_STORAGE_ERRORS,
  MESSAGE_LEN,
  METADATA_LEN,
  PROOF_LEN,
} from "../utils/constants";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import { messageCacheKey } from "./messageChunkCrypto";
import { parseChunkFrameHeader } from "./chunkFrame";
import { decryptMessageChunkDurably } from "./ratchetPersist";
import { bindReceiveMessageKey } from "./receiveMessageKeyLifetime";

import {
  abortReceivedFileVerification,
  getDBMessageData,
  settleReceivedFileVerification,
  storeReceiveChunk as persistReceiveChunk,
  verifyReceivedFile,
} from "../db/api";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type {
  ReceiveChunk,
  ReceiveChunkStoreFailure,
  ReceiveChunkStoreResult,
  ReceiveStorageFailure,
  ReceiveVerificationOutcome,
  ReceiveVerificationVerdict,
} from "../db/types";
import type { PersistRatchetState } from "./ratchetPersist";

export interface ReceiveMessageResult {
  date: Date;
  chunkSize: number;
  chunkIndex: number;
  receivedFullSize: boolean;
  chunkAlreadyExists: boolean;
  totalSize: number;
  messageType: number;
  filename: string;
  /** 64-byte root/index/leaf-bound receipt token (legacy field name). */
  chunkHash: Uint8Array;
  messageHash: Uint8Array;
  /**
   * Set when this chunk would complete a file: it is held, and the file must
   * be verified (verifyHeldFile, then settleHeldFile) before it is complete.
   */
  verification?: string;
}

// Uniform "not stored / crypto-failed" result — the queueing layer reacts to it
// by emitting a decoy receipt (so the reverse count still matches the forward
// frame count) and skipping storage. Mirrors the box path's error returns.
const dropped = (): ReceiveMessageResult => ({
  date: new Date(),
  chunkIndex: -1,
  chunkSize: 0,
  receivedFullSize: false,
  chunkAlreadyExists: false,
  totalSize: 0,
  messageType: MessageType.Text,
  filename: "",
  chunkHash: new Uint8Array(),
  messageHash: new Uint8Array(),
});

type ReceiveChunkStore = (
  chunk: ReceiveChunk,
) => Promise<ReceiveChunkStoreResult>;

export interface ReceiveMessageDependencies {
  /** Test/fault-injection seam; production uses the ratchet worker database. */
  persistRatchetState?: PersistRatchetState;
  /** Test/fault-injection seam; production uses the receive-chunk worker. */
  storeReceiveChunk?: ReceiveChunkStore;
  /** Test seams for whole-file verification; production uses the worker. */
  closeReceiveFile?: (merkleRootHex: string) => Promise<void>;
  verifyReceivedFile?: typeof verifyReceivedFile;
  settleReceivedFileVerification?: typeof settleReceivedFileVerification;
  abortReceivedFileVerification?: typeof abortReceivedFileVerification;
}

/**
 * A received chunk this device could not store. The chunk was not
 * acknowledged: its sender sees no receipt for it and will retransmit or give
 * up, so the transfer stays incomplete until storage is available again.
 */
export interface ReceiveStorageError {
  /**
   * - `insufficient-quota`: the transfer is larger than the estimated free
   *   storage and was refused before anything was written.
   * - `quota-exceeded`: the browser refused a write for lack of space.
   * - `storage-failed`: any other storage fault.
   * - `integrity`: the file's last chunk arrived, but the stored bytes do not
   *   hash to the whole-file hash its message carries. The file's chunks were
   *   dropped and reading it throws ReceiveIntegrityError.
   */
  readonly code: ReceiveStorageFailure;
  readonly roomId: string;
  readonly fromPeerId: string;
  readonly merkleRootHex: string;
  readonly filename: string;
  readonly totalSize: number;
  readonly chunkIndex: number;
  /** `insufficient-quota` only: the bytes the transfer needs. */
  readonly requiredBytes?: number;
  /** `insufficient-quota` only: the estimated free bytes. */
  readonly availableBytes?: number;
}

const receiveStorageErrorListeners = new Set<
  (error: ReceiveStorageError) => void
>();

// Each (transfer, code) is reported once until a later chunk of that transfer
// stores again, so a full disk does not raise one event per retransmitted
// chunk.
const reportedReceiveStorageErrors = new Set<string>();

/**
 * Call `listener` when a received chunk cannot be stored. Returns an
 * unsubscribe function. Listener errors are caught and logged.
 */
export const onReceiveStorageError = (
  listener: (error: ReceiveStorageError) => void,
): (() => void) => {
  receiveStorageErrorListeners.add(listener);
  return () => {
    receiveStorageErrorListeners.delete(listener);
  };
};

/** What names a received transfer in a ReceiveStorageError. */
export type ReceivedChunkContext = Pick<
  ReceiveChunk,
  | "roomId"
  | "fromPeerId"
  | "merkleRoot"
  | "filename"
  | "totalSize"
  | "chunkIndex"
>;

const reportReceiveStorageError = (
  chunk: ReceivedChunkContext,
  failure: ReceiveChunkStoreFailure,
): void => {
  const key = `${chunk.merkleRoot}:${failure.failure}`;
  if (reportedReceiveStorageErrors.has(key)) return;
  if (reportedReceiveStorageErrors.size >= MAX_REPORTED_RECEIVE_STORAGE_ERRORS)
    reportedReceiveStorageErrors.clear();
  reportedReceiveStorageErrors.add(key);
  const error: ReceiveStorageError = {
    code: failure.failure,
    roomId: chunk.roomId,
    fromPeerId: chunk.fromPeerId,
    merkleRootHex: chunk.merkleRoot,
    filename: chunk.filename,
    totalSize: chunk.totalSize,
    chunkIndex: chunk.chunkIndex,
    ...(failure.requiredBytes === undefined
      ? {}
      : { requiredBytes: failure.requiredBytes }),
    ...(failure.availableBytes === undefined
      ? {}
      : { availableBytes: failure.availableBytes }),
  };
  console.error("p2party: a received chunk could not be stored", error);
  for (const listener of receiveStorageErrorListeners) {
    try {
      listener(error);
    } catch (listenerError) {
      console.error(
        "p2party: onReceiveStorageError listener threw",
        listenerError,
      );
    }
  }
};

const clearReceiveStorageErrors = (merkleRootHex: string): void => {
  if (reportedReceiveStorageErrors.size === 0) return;
  for (const code of [
    "insufficient-quota",
    "quota-exceeded",
    "storage-failed",
    "integrity",
  ] satisfies ReceiveStorageFailure[])
    reportedReceiveStorageErrors.delete(`${merkleRootHex}:${code}`);
};

/**
 * Thrown when reading a received file whose stored bytes did not match the
 * whole-file hash its message carries. Its chunks were dropped, so it stays
 * unreadable until its sender sends the whole file again.
 */
export class ReceiveIntegrityError extends Error {
  readonly code = "integrity" as const;
  readonly merkleRootHex: string;

  constructor(merkleRootHex: string) {
    super("p2party: the received file does not match its message hash");
    this.name = "ReceiveIntegrityError";
    this.merkleRootHex = merkleRootHex;
  }
}

/**
 * Throw ReceiveIntegrityError if this received file failed whole-file
 * verification. A completed file was verified when it completed, so callers
 * need this only for a file that is not complete.
 */
export const assertReceivedFileIntact = async (
  merkleRootHex: string,
  readProgress: typeof getDBMessageData = getDBMessageData,
): Promise<void> => {
  const progress = await readProgress(merkleRootHex);
  if (progress?.integrityFailed === true)
    throw new ReceiveIntegrityError(merkleRootHex);
};

// Ask once per page for persistent storage, so the browser does not evict a
// partially received file under storage pressure. Window-only API (workers
// cannot call it); the answer is not awaited and a refusal changes nothing.
let persistentStorageRequested = false;
const requestPersistentStorageOnce = (): void => {
  if (persistentStorageRequested) return;
  const storage = (
    globalThis as { navigator?: { storage?: Partial<StorageManager> } }
  ).navigator?.storage;
  if (typeof storage?.persist !== "function") return;
  persistentStorageRequested = true;
  try {
    void storage.persist().catch(() => undefined);
  } catch {
    /* a refusal is not an error */
  }
};

/**
 * Worker storage is the durability boundary for a receipt. A failed write must
 * look exactly like a decoy/drop to the caller, and the owned real-byte copy is
 * erased after postMessage has cloned it (or after an injected failure).
 */
export const storeReceiveChunkFailClosed = async (
  chunk: Omit<ReceiveChunk, "data">,
  realChunk: Uint8Array,
  store: ReceiveChunkStore = persistReceiveChunk,
): Promise<ReceiveChunkStoreResult | null> => {
  try {
    return await store({ ...chunk, data: realChunk.buffer as ArrayBuffer });
  } catch (error) {
    console.error("Could not durably store received chunk", error);
    // The database as a whole is down (its worker failed, or an older tab
    // blocks its upgrade): a storage failure the app is told about, unlike a
    // chunk the worker refused.
    if (error instanceof DatabaseUnavailableError)
      return { failure: "storage-failed" };
    return null;
  } finally {
    realChunk.fill(0);
  }
};

// ── protocol-v3 receive (Stage-5 task 3) ─────────────────────────────────────────
// Decrypt one inbound v3 CHUNK frame off the seeded Double Ratchet (replacing the
// authenticated v3 receive path), verify its Merkle proof, and store real bytes.
//
// Crypto: `decryptMessageChunk` derives the per-MESSAGE key off the ratchet (one
// step per message, cached per `(dhPub, N)`; clone-rollback so a replayed header
// can't desync the session), then hands the raw frame + key + expected root to the
// C `_receive_message_with_key`, which decrypts, hashes the leaf, verifies the
// Merkle proof, and writes the receipt leaf — the ENTIRE receive crypto in ONE
// libsodium call, in place, no TS↔WASM back-and-forth. On success it returns the
// DECRYPTED_LEN plaintext `metadata ‖ receiptLeaf ‖ chunk`; only frame parsing,
// ratchet bookkeeping, and storage remain in TS. The store-receipt tail below is
// verbatim from the box path.
export const handleReceiveMessage = async (
  frame: Uint8Array,
  roomId: string,
  channelLabel: string,
  epc: IRTCPeerConnection,
  merkleRoot: Uint8Array,
  module: LibCrypto,
  signal?: AbortSignal,
  dependencies: ReceiveMessageDependencies = {},
): Promise<ReceiveMessageResult> => {
  if (signal?.aborted) return dropped();
  if (!epc.ratchetState) {
    // Ratchet not established yet (should not happen: the queue awaits the gate
    // before draining) — drop rather than mis-decrypt.
    console.error("v3 receive: no ratchet state for peer");
    return dropped();
  }
  // v4: the per-edge cache IS the PQ runtime's active combined receive-key
  // collection (aliased at handshake activation) so every persisted edge
  // checkpoint carries it. An edge without a PQ runtime gets a bare Map here,
  // but decryptMessageChunkDurably refuses to decrypt for it unless a test
  // opted the edge in through ratchetPersist's test-only classical opt-in.
  if (!epc.messageKeyCache)
    epc.messageKeyCache =
      epc.pqHealingState?.activeReceiveKeys ??
      new Map<string, Uint8Array>();
  const cache = epc.messageKeyCache;

  // The per-message cache key (dhPub, N, pqEpoch). It stays live through
  // channel drain: the real cell can complete storage before later valid cover
  // cells arrive. Production identity is epoch-bound; the two-field form is
  // the test-only classical path.
  let cacheKey: string | undefined;
  try {
    const { header, pqEpoch } = parseChunkFrameHeader(frame);
    cacheKey = messageCacheKey(
      header.dhPub,
      header.N,
      epc.pqHealingState ? pqEpoch : undefined,
    );
  } catch {
    return dropped();
  }

  // Anti-DoS backstop: a normally closed complete message is retired after its
  // queue drains, but a peer could pin keys with never-completing messages.
  // Bound the per-edge cache BEFORE the durable decrypt (oldest first, Map
  // insertion order) so the staged active-key map can never exceed the
  // encrypted edge checkpoint's key budget.
  const MESSAGE_KEY_CACHE_MAX = 256;
  if (cache.size >= MESSAGE_KEY_CACHE_MAX) {
    for (const k of cache.keys()) {
      if (cache.size < MESSAGE_KEY_CACHE_MAX) break;
      cache.get(k)?.fill(0);
      cache.delete(k);
      if (epc.messageKeyByMerkleRoot) {
        for (const [root, mappedKey] of epc.messageKeyByMerkleRoot) {
          if (mappedKey === k) epc.messageKeyByMerkleRoot.delete(root);
        }
      }
    }
  }

  // 1) Derive/decrypt against a staged clone, then persist and adopt the
  //    authenticated successor before exposing any plaintext. The per-edge lock
  //    also serializes concurrent send/receive/PQ ratchet transitions. With a
  //    PQ runtime the staged combined key is persisted inside the encrypted
  //    edge checkpoint (same row as the ratchet successor), never in the
  //    classical skipped map.
  let decrypted: Uint8Array | null;
  let ok: boolean;
  try {
    const d = await decryptMessageChunkDurably(
      epc,
      roomId,
      frame,
      cache,
      merkleRoot,
      module,
      dependencies.persistRatchetState,
    );
    decrypted = d.decrypted;
    ok = d.ok;
  } catch (error) {
    console.error("Could not durably decrypt message", error);
    return dropped();
  }

  // 2) A drop (AEAD auth OR Merkle proof failed inside the C call, or a stale-chain
  //    replay) → emit a decoy receipt, don't store.
  if (!ok || !decrypted) {
    console.error("Could not decrypt or verify message");
    return dropped();
  }

  const merkleRootHex = uint8ArrayToHex(merkleRoot);
  bindReceiveMessageKey(epc, merkleRootHex, cacheKey);

  try {
    // Cancellation waits for this handler to quiesce before retiring the
    // mapped receive key. Stop before any plaintext reaches storage.
    if (signal?.aborted) return dropped();

    // 3) Split the C output: metadata ‖ receiptLeaf ‖ chunk. The C wrote the
    //    leaf hash SHA-512(0x00 ‖ chunk) over the proof region; that is the
    //    receipt token, so no second hash is computed here.
    const metadataArray = decrypted.subarray(0, METADATA_LEN);
    const leafHash = decrypted.slice(
      METADATA_LEN,
      METADATA_LEN + crypto_hash_sha512_BYTES,
    );
    const chunk = decrypted.subarray(METADATA_LEN + PROOF_LEN);
    const metadata = deserializeMetadata(metadataArray);
    assertMetadataV1(metadata);

    const chunkSize =
      metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
        ? 0
        : metadata.chunkEndIndex - metadata.chunkStartIndex > MESSAGE_LEN
          ? 0
          : metadata.chunkEndIndex - metadata.chunkStartIndex;

    const rejectedResult = (): ReceiveMessageResult => ({
      date: metadata.date,
      chunkIndex: -1,
      chunkSize: 0,
      receivedFullSize: false,
      chunkAlreadyExists: true,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash: leafHash,
      messageHash: metadata.hash,
    });

    if (chunkSize === 0) return rejectedResult();

    // The real-data offsets come from attacker-controllable metadata; reject
    // anything outside the padded chunk or inverted.
    if (
      !isStorableChunkRange(
        metadata.chunkStartIndex,
        metadata.chunkEndIndex,
        chunk.length,
      )
    )
      return rejectedResult();

    const receiptToken = await createChunkReceiptToken(
      merkleRoot,
      metadata.chunkIndex,
      leafHash,
    );
    if (signal?.aborted) {
      receiptToken.fill(0);
      return dropped();
    }
    const mimeType = getMimeType(metadata.messageType);
    const storedChunk: Omit<ReceiveChunk, "data"> = {
      schemaVersion: metadata.schemaVersion,
      roomId,
      fromPeerId: epc.withPeerId,
      channelLabel,
      timestamp: metadata.date.getTime(),
      merkleRoot: merkleRootHex,
      hash: uint8ArrayToHex(metadata.hash),
      filename: metadata.name,
      messageType: metadata.messageType,
      chunkIndex: metadata.chunkIndex,
      mimeType,
      // Keep the leaf on the receiver so reconnect can derive the same scoped
      // token without retaining the padded body.
      leafHash: uint8ArrayToHex(leafHash),
      realLen: chunkSize,
      totalSize: metadata.totalSize,
      storage: metadata.messageType === MessageType.Text ? "indexeddb" : "opfs",
    };
    if (storedChunk.storage === "opfs") requestPersistentStorageOnce();
    // Create this owned plaintext copy only once all fallible preprocessing is
    // done; storeReceiveChunkFailClosed assumes ownership and always wipes it.
    const realChunk = chunk.slice(
      metadata.chunkStartIndex,
      metadata.chunkEndIndex,
    );

    const progress = await storeReceiveChunkFailClosed(
      storedChunk,
      realChunk,
      dependencies.storeReceiveChunk,
    );
    if (!progress) {
      receiptToken.fill(0);
      return dropped();
    }
    if (progress.failure !== undefined) {
      // Not stored, so not acknowledged: the sender gets the same decoy as for
      // a dropped frame and the app is told why.
      receiptToken.fill(0);
      reportReceiveStorageError(storedChunk, progress);
      return dropped();
    }
    clearReceiveStorageErrors(merkleRootHex);
    if (signal?.aborted) {
      // The worker write may already have crossed its durability boundary.
      // cancelReceiveTransfer queues a locked delete after this handler exits.
      receiptToken.fill(0);
      return dropped();
    }

    // `complete` comes from the same transaction that inserted/deduplicated
    // the chunk and updated messageData. A duplicate of an incomplete message
    // remains incomplete; a duplicate after a crash may safely re-emit the
    // idempotent terminal receipt for an already-durable complete message.
    const receivedFullSize = progress.complete;

    return {
      date: metadata.date,
      chunkIndex: metadata.chunkIndex,
      chunkSize,
      receivedFullSize,
      chunkAlreadyExists: !progress.stored,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash: receiptToken,
      messageHash: metadata.hash,
      ...(progress.verification === undefined
        ? {}
        : { verification: progress.verification }),
    };
  } catch (error) {
    console.error("Could not parse or store decrypted message", error);
    return dropped();
  } finally {
    // `receiveWithKey` returned an owned plaintext copy. All returned metadata
    // and receipt fields are independent slices, so erase the padded body now.
    decrypted.fill(0);
  }
};

/**
 * Hash a received file held pending verification (a result with
 * `verification`). Call it outside the edge's receive lock: the worker reads
 * the file once and keeps serving other requests meanwhile. If `signal`
 * aborts once the edge is no longer current (teardown, room leave), the
 * hashing stops at its next read and the verdict is "aborted".
 */
export const verifyHeldFile = async (
  merkleRootHex: string,
  token: string,
  signal: AbortSignal | undefined,
  edgeIsCurrent: () => boolean,
  dependencies: ReceiveMessageDependencies = {},
): Promise<ReceiveVerificationVerdict> => {
  const verify = dependencies.verifyReceivedFile ?? verifyReceivedFile;
  const abort =
    dependencies.abortReceivedFileVerification ?? abortReceivedFileVerification;
  const onAbort = (): void => {
    if (edgeIsCurrent()) return;
    void abort(merkleRootHex, token).catch((error: unknown) => {
      console.error("p2party: could not stop a file verification", error);
    });
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();
  try {
    return await verify(merkleRootHex, token);
  } catch (error) {
    console.error("p2party: could not verify a received file", error);
    return "storage-failed";
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
};

/**
 * Commit a verification's verdict under the edge's receive lock, or decline
 * it (`commit` false: the edge is gone), which leaves the file to be verified
 * again by the next copy of its last chunk. Reports an integrity failure, or a
 * storage fault while reading the file, through onReceiveStorageError.
 */
export const settleHeldFile = async (
  context: ReceivedChunkContext,
  token: string,
  verdict: ReceiveVerificationVerdict,
  commit: boolean,
  dependencies: ReceiveMessageDependencies = {},
): Promise<ReceiveVerificationOutcome> => {
  const settle =
    dependencies.settleReceivedFileVerification ??
    settleReceivedFileVerification;
  let outcome: ReceiveVerificationOutcome;
  try {
    outcome = await settle(context.merkleRoot, token, commit);
  } catch (error) {
    // The commit itself failed (nothing was written): the file stays to be
    // verified again by the next copy of its last chunk.
    console.error("p2party: could not settle a file verification", error);
    if (commit)
      reportReceiveStorageError(context, { failure: "storage-failed" });
    return "aborted";
  }
  if (outcome === "integrity")
    reportReceiveStorageError(context, { failure: "integrity" });
  else if (commit && verdict === "storage-failed")
    reportReceiveStorageError(context, { failure: "storage-failed" });
  return outcome;
};
