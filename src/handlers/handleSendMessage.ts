import {
  immediateCloseMeansPause,
  hasImmediateRemoteCancel,
  sendImmediateCancel,
} from "./immediateDisposition";
import { outboxRequest } from "../db/api";
import {
  startOutboxSession,
  persistOutboundReceipt,
  persistOutboundCancellation,
  OutboxOwnershipLostError,
} from "./outbox";
import type { OutboxSession } from "./outbox";
import type { OutboxLease, OutboxManifest } from "../db/outboxTypes";
import { encodeRoomPolicyV1 } from "../roomPolicy";
import { createTransferId } from "./transferAbort";
import {
  planMessageChunkCount,
  estimateOutboundStagingBytes,
} from "../utils/splitToChunks";
import { debugLog } from "../utils/debug";
import { handleOpenChannel } from "./handleOpenChannel";

import { fisherYatesShuffle } from "../cryptography/utils";
import { buildMerkleProofLevels } from "../cryptography/merkle";
import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../cryptography/interfaces";

import {
  concatUint8Arrays,
  hexToUint8Array,
  uint8ArrayToHex,
} from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import { createChunkReceiptToken } from "../utils/receiptToken";
import {
  compileChannelMessageLabel,
  decompileChannelMessageLabel,
} from "../utils/channelLabel";
import { waitForOpen } from "../utils/waitForOpen";
import { incrementMessageStats } from "../reducers/roomSlice";
import {
  clearTransfer,
  isTransferComplete,
  isTransferCancelled,
  waitForCompletion,
  getAckedChunks,
  markChunkAcked,
  hasChunkAcked,
  getAckedChunkCount,
  onTransferActivity,
  onTransferProgress,
  reportedCompletionCapMs,
  transferWaitClock,
  waitForReportedCompletion,
} from "./reconcile";
import type { TransferWaitClock } from "./reconcile";
import { MAX_QUEUED_FRAMES_PER_CHANNEL } from "./handleMessageQueueing";
import { createMessageChunkSealer } from "./messageChunkCrypto";
import {
  isRatchetGateWaitTimeout,
  waitForRatchetGate,
} from "./ratchetGateWait";
import { isCurrentRatchetGateLease, isRatchetGateOpen } from "./ratchetGate";
import {
  markChannelClosedLocally,
  wasChannelClosedLocally,
} from "../api/webrtc/localChannelClose";
import {
  isPqApplicationTrafficBlocked,
  tryReservePqApplicationTraffic,
} from "./pqHealingOrchestrator";
import {
  cancelScheduledSend,
  coverEdgeGeneration,
  enqueueScheduledSend,
  onCoverEdgeRetired,
  trackScheduledSend,
  untrackScheduledSend,
  waitForCoverEdgeGeneration,
} from "./coverEdge";
import {
  scheduledCoverIsSuspended,
  queueScheduledCancel,
  scheduledDeliveryTimeoutMs,
  scheduledSendProgress,
  waitForScheduledDelivery,
} from "./coverTransfer";
import { ratchetEncryptDurably } from "./ratchetPersist";
import {
  claimTransfer,
  throwIfTransferAborted,
  waitWithTransferAbort,
} from "./transferAbort";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  MAX_BUFFERED_AMOUNT,
  PROOF_LEN,
  MAX_RETRANSMITS,
  RETRANSMIT_TIMEOUT_MS,
  PEER_ADMISSION_WAIT_MS,
  RECONNECT_RESUME_TIMEOUT_MS,
  RECONNECT_RESUME_POLL_MS,
  MAX_RESUME_ATTEMPTS,
  MAX_SCHEDULED_SEND_RESUMES,
  RECEIPT_WINDOW_FALLBACK_MS,
  MAX_TIMER_DELAY_MS,
  RECEIVER_SILENCE_LIMIT_MS,
  SEND_BUFFER_FALLBACK_MS,
  SEND_BUFFER_LOW_THRESHOLD,
} from "../utils/constants";

import { deleteDBSendQueue, getDBNewChunk, setDBNewChunk } from "../db/api";
import { roomSendQueueLabel } from "../utils/sendQueueKey";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { MerkleProofLevels } from "../cryptography/merkle";
import type { PqMessageKeyContext } from "../cryptography/pqMessageKey";
import type { MessageChunkSealer } from "./messageChunkCrypto";
import type { NewChunk } from "../db/types";
import type { Metadata } from "../utils/metadata";
import type { RatchetHeader } from "../cryptography/ratchet";
import type { RatchetGateLease } from "./ratchetGate";
import type { ScheduledDeliveryWaitOptions } from "./coverTransfer";
import type { CoverSchedulerStatus } from "./coverScheduler";
import type { RoomPolicyV1 } from "../roomPolicy";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

// Sender-side flow control beyond SCTP. The receiver enqueues at most
// MAX_QUEUED_FRAMES_PER_CHANNEL frames before its budget CLOSES the channel —
// that budget is a DoS guard, not backpressure — and SCTP pacing alone lets a
// fast link outrun the receiver's decrypt+store drain (a 16 MiB send on
// localhost deterministically trips the budget). Cap sent-but-unreceipted REAL
// frames at half the receiver's budget; decoy receipts do not resolve to
// staged chunks on the sender, so the window counts reals only (decoy-heavy
// messages are small minChunks sends that cannot overflow the budget).
export const SEND_RECEIPT_WINDOW = MAX_QUEUED_FRAMES_PER_CHANNEL / 2;
// After this long without any receipt progress the window unblocks and the
// legacy behavior (receiver budget + reconcile retransmit) is the backstop,
// so this flow control can never introduce a new deadlock.
export const SEND_WINDOW_STALL_MS = 10_000;

export interface ReceiptWindowParams {
  readonly windowSize: number;
  readonly stallTimeoutMs: number;
  /** The longest the wait goes without re-checking on its own. */
  readonly fallbackMs: number;
  readonly isOpen: () => boolean;
  readonly inFlight: () => number;
  /**
   * Subscribe `wake` to what can end the wait — a receipt on this edge, the
   * channel leaving "open" — and return the unsubscribe.
   */
  readonly subscribe: (wake: () => void) => () => void;
  readonly signal?: AbortSignal;
  readonly clock?: TransferWaitClock;
}

/**
 * Resolve once in-flight drops below the window, the channel leaves "open",
 * or receipt progress stalls for stallTimeoutMs. Any receipt progress while
 * still over the window resets the stall clock. Throws only on transfer abort.
 *
 * Woken by `subscribe` (a receipt, a close) and by the abort signal; its one
 * timer fires only at the stall deadline or after fallbackMs without a
 * wake-up, never on a polling cadence.
 */
export const waitForReceiptWindow = async (
  params: ReceiptWindowParams,
): Promise<void> => {
  throwIfTransferAborted(params.signal);
  if (!params.isOpen() || params.inFlight() < params.windowSize) return;
  const clock = params.clock ?? transferWaitClock;

  await new Promise<void>((resolve, reject) => {
    let lastInFlight = params.inFlight();
    let lastProgressAt = clock.now();
    let done = false;
    let timer: unknown;
    let unsubscribe = (): void => undefined;
    const finish = (settle: () => void): void => {
      done = true;
      if (timer !== undefined) clock.clearTimeout(timer);
      unsubscribe();
      params.signal?.removeEventListener("abort", check);
      settle();
    };
    const check = (): void => {
      if (done) return;
      if (params.signal?.aborted) {
        finish(() => {
          try {
            throwIfTransferAborted(params.signal);
          } catch (error) {
            reject(error);
          }
        });
        return;
      }
      const inFlight = params.inFlight();
      if (!params.isOpen() || inFlight < params.windowSize) {
        finish(resolve);
        return;
      }
      if (inFlight < lastInFlight) {
        lastInFlight = inFlight;
        lastProgressAt = clock.now();
      }
      if (clock.now() - lastProgressAt >= params.stallTimeoutMs)
        finish(resolve);
    };
    const arm = (): void => {
      const untilStall = lastProgressAt + params.stallTimeoutMs - clock.now();
      timer = clock.setTimeout(
        onTimer,
        Math.max(0, Math.min(params.fallbackMs, untilStall)),
      );
    };
    const onTimer = (): void => {
      timer = undefined;
      check();
      if (!done) arm();
    };
    // Registered before the state is checked again, so a receipt between the
    // first check and the subscription cannot be missed.
    unsubscribe = params.subscribe(check);
    params.signal?.addEventListener("abort", check);
    check();
    if (!done) arm();
  });
};

/** One edge's receipt count, and a way to be woken when it changes. */
export interface ReceiptProgress {
  readonly count: () => number;
  readonly subscribe: (wake: () => void) => () => void;
}

/** The receipts of one transfer edge, as reconcile records them. */
export const edgeReceiptProgress = (
  roomId: string,
  peerId: string,
  transferId: string,
): ReceiptProgress => ({
  count: () => getAckedChunkCount(roomId, peerId, transferId),
  subscribe: (wake) => onTransferProgress(roomId, peerId, transferId, wake),
});

/**
 * Where a sender's staged plaintext cells live: the durable `newChunks` store
 * the DB worker owns. Injectable so the read/write pattern of a send has a
 * focused unit test; production always uses the worker.
 */
export interface OutboundChunkStore {
  readonly get: (
    transferId: string,
    chunkIndex: number,
  ) => Promise<NewChunk | undefined>;
  readonly put: (chunk: NewChunk, lease?: OutboxLease) => Promise<void>;
}

const stagedChunkStore: OutboundChunkStore = {
  get: (transferId, chunkIndex) => getDBNewChunk(transferId, chunkIndex),
  put: (chunk, lease) => setDBNewChunk(chunk, lease),
};

export interface OutboundMessageParams {
  readonly transferId: string;
  readonly hashHex: string;
  readonly merkleRoot: Uint8Array;
  readonly totalChunks: number;
  /** The leaf hashes, totalChunks × 64 bytes, in chunk order. */
  readonly chunkHashes: Uint8Array;
  /** Hashes the tree's internal nodes when the proof levels are built. */
  readonly merkleModule: LibCrypto;
  readonly store?: OutboundChunkStore;
}

/** One staged cell, read once, with what its own metadata says it is. */
export interface StagedOutboundChunk {
  readonly index: number;
  readonly row: NewChunk;
  readonly metadataArray: Uint8Array;
  readonly metadata: Metadata;
  /** Real bytes, not padding. A decoy has chunkEnd − chunkStart > totalSize. */
  readonly real: boolean;
}

// Per-cell kinds an OutboundMessage learned by reading; 0 = not read yet.
const CHUNK_KIND_REAL = 1;
const CHUNK_KIND_DECOY = 2;

/**
 * Everything a sender knows about one logical message for as long as that
 * message is being delivered, shared by every peer's transfer of it.
 *
 * Its Merkle proof levels are built at most once — on the first cell whose
 * staged row has no proof yet — and serve every chunk, every retransmit round
 * and every peer in O(log N). The previous path called `getMerkleProof` per
 * chunk, which rebuilds the whole tree each time (about 51 ms at 19,270
 * leaves). A resume after a page reload builds them once from the leaves the
 * outbox claim returned, and only if some chunk still lacks a stored proof.
 *
 * It also remembers which cells a read showed to be decoys, so a retransmit
 * pass skips them without reading them again.
 *
 * `close()` drops both. `withOutboundMessage` owns that call; after it nothing
 * is rebuilt.
 */
export class OutboundMessage {
  readonly transferId: string;
  readonly hashHex: string;
  readonly merkleRoot: Uint8Array;
  readonly merkleRootHex: string;
  readonly totalChunks: number;
  readonly #chunkHashes: Uint8Array;
  readonly #merkleModule: LibCrypto;
  readonly #store: OutboundChunkStore;
  #kinds: Uint8Array;
  // Cells whose staged row now carries its proof; the levels are not needed
  // for those again.
  #proven: Uint8Array;
  #provenCount = 0;
  #totalSize = 0;
  #levels: MerkleProofLevels | null = null;
  #levelsError: Error | null = null;
  #closed = false;

  constructor(params: OutboundMessageParams) {
    if (params.merkleRoot.length !== crypto_hash_sha512_BYTES)
      throw new Error("Outbound message Merkle root must be 64 bytes");
    if (
      !Number.isSafeInteger(params.totalChunks) ||
      params.totalChunks < 1 ||
      params.chunkHashes.length !==
        params.totalChunks * crypto_hash_sha512_BYTES
    )
      throw new Error("Outbound message leaves do not match its chunk count");
    this.transferId = params.transferId;
    this.hashHex = params.hashHex;
    this.merkleRoot = params.merkleRoot;
    this.merkleRootHex = uint8ArrayToHex(params.merkleRoot);
    this.totalChunks = params.totalChunks;
    this.#chunkHashes = params.chunkHashes;
    this.#merkleModule = params.merkleModule;
    this.#store = params.store ?? stagedChunkStore;
    this.#kinds = new Uint8Array(params.totalChunks);
    this.#proven = new Uint8Array(params.totalChunks);
  }

  get closed(): boolean {
    return this.#closed;
  }

  /** Bytes the cached proof levels hold; zero before they are built and after close. */
  get proofLevelBytes(): number {
    return this.#levels?.byteLength ?? 0;
  }

  /** True once a read of this cell showed it is padding. */
  isKnownDecoy(index: number): boolean {
    return this.#kinds[index] === CHUNK_KIND_DECOY;
  }

  /** The message's size in bytes, as its cells' metadata states it; 0 before any read. */
  get totalSize(): number {
    return this.#totalSize;
  }

  /**
   * True once every cell has been read and every real one is acknowledged:
   * the receiver holds the whole file. False while any cell's kind is unknown.
   */
  allRealsAcknowledged(isAcked: (index: number) => boolean): boolean {
    if (this.#kinds.length !== this.totalChunks) return false;
    for (let index = 0; index < this.totalChunks; index++) {
      const kind = this.#kinds[index];
      if (
        kind === CHUNK_KIND_REAL ? !isAcked(index) : kind !== CHUNK_KIND_DECOY
      )
        return false;
    }
    return true;
  }

  /** Read one staged cell from storage and check it belongs at `index`. */
  async read(
    index: number,
    signal?: AbortSignal,
  ): Promise<StagedOutboundChunk | undefined> {
    this.#assertOpen();
    const row = await this.#store.get(this.transferId, index);
    throwIfTransferAborted(signal);
    if (!row) return undefined;
    const metadataArray = new Uint8Array(row.metadata);
    const metadata = deserializeMetadata(metadataArray);
    if (metadata.chunkIndex !== index || row.chunkIndex !== index)
      throw new Error("Outbound chunk index does not match its staging key");
    // Real-vs-decoy is read from the chunk's own metadata (SSOT).
    const real =
      metadata.chunkEndIndex > metadata.chunkStartIndex &&
      metadata.chunkEndIndex - metadata.chunkStartIndex <= metadata.totalSize;
    if (!this.#closed) {
      this.#kinds[index] = real ? CHUNK_KIND_REAL : CHUNK_KIND_DECOY;
      this.#totalSize = metadata.totalSize;
    }
    return { index, row, metadataArray, metadata, real };
  }

  /**
   * The DECRYPTED_LEN plaintext (metadata ‖ proof ‖ chunk) for one staged
   * cell. Its proof and scoped receipt token are persisted BEFORE the frame
   * can go on the wire: if quota/storage fails, propagating the error is the
   * only recoverable behaviour, because a sent frame whose resend source was
   * not committed can never take part in reconnect reconciliation.
   */
  async cellPlaintext(
    staged: StagedOutboundChunk,
    outboxLease?: OutboxLease,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    this.#assertOpen();
    const { row, index } = staged;
    const hasStoredProof = row.merkleProof.byteLength > 0;
    const merkleProof = new Uint8Array(PROOF_LEN);
    if (hasStoredProof) merkleProof.set(new Uint8Array(row.merkleProof));
    else
      merkleProof.set(
        this.#proofLevels().proof(
          index,
          hexToUint8Array(row.leafHash),
          PROOF_LEN,
        ),
      );

    if (hasStoredProof) this.#noteProven(index);
    const receiptToken =
      row.receiptToken.length === crypto_hash_sha512_BYTES * 2
        ? row.receiptToken
        : uint8ArrayToHex(
            await createChunkReceiptToken(
              this.merkleRoot,
              staged.metadata.chunkIndex,
              hexToUint8Array(row.leafHash),
            ),
          );
    throwIfTransferAborted(signal);

    if (
      !hasStoredProof ||
      row.merkleRoot !== this.merkleRootHex ||
      row.receiptToken !== receiptToken
    ) {
      await this.#store.put(
        {
          transferId: this.transferId,
          hash: this.hashHex,
          merkleRoot: this.merkleRootHex,
          leafHash: row.leafHash,
          receiptToken,
          chunkIndex: index,
          data: row.data,
          metadata: row.metadata,
          merkleProof: merkleProof.buffer,
        },
        outboxLease,
      );
      this.#noteProven(index);
      throwIfTransferAborted(signal);
    }

    const data = new Uint8Array(row.data);
    if (
      DECRYPTED_LEN !==
      staged.metadataArray.length + merkleProof.length + data.length
    )
      throw new Error("Outbound staged chunk has invalid cell length");

    const chunk = await concatUint8Arrays([
      staged.metadataArray,
      merkleProof,
      data,
    ]);
    throwIfTransferAborted(signal);
    return chunk;
  }

  /** Drop the proof levels and the decoy map. Idempotent. */
  close(): void {
    this.#closed = true;
    this.#levels?.release();
    this.#levels = null;
    this.#kinds = new Uint8Array(0);
  }

  // Once every cell's row carries its proof, every later read finds it there:
  // the levels (about N × 64 bytes) are released while the delivery goes on.
  #noteProven(index: number): void {
    if (this.#closed || this.#proven[index] === 1) return;
    this.#proven[index] = 1;
    this.#provenCount++;
    if (this.#provenCount === this.totalChunks) {
      this.#levels?.release();
      this.#levels = null;
    }
  }

  #assertOpen(): void {
    if (this.#closed)
      throw new Error("Outbound message delivery has already ended");
  }

  #proofLevels(): MerkleProofLevels {
    this.#assertOpen();
    if (this.#levels) return this.#levels;
    // A failed build is not retried: every peer and cell of this delivery
    // would only pay N − 1 hashes again to reach the same answer.
    if (this.#levelsError) throw this.#levelsError;
    let levels: MerkleProofLevels;
    try {
      levels = buildMerkleProofLevels(this.#chunkHashes, this.#merkleModule);
    } catch (error) {
      this.#levelsError =
        error instanceof Error ? error : new Error(String(error));
      throw this.#levelsError;
    }
    // The leaves came from the outbox, not from this page's staging, on a
    // resume. Proofs over leaves that do not reach the message's root would
    // only be rejected by every receiver, chunk by chunk.
    const root = levels.root();
    if (root.some((byte, i) => byte !== this.merkleRoot[i])) {
      levels.release();
      this.#levelsError = new Error(
        "Outbound message leaves do not reach its Merkle root",
      );
      throw this.#levelsError;
    }
    this.#levels = levels;
    return levels;
  }
}

/**
 * Run one delivery of one message — every peer's transfer, immediate or
 * scheduled — against a single `OutboundMessage`, and close it however the
 * delivery ends: completion, the receiver's final receipt, a cancel, a torn
 * down edge, a left room. Each of those settles `deliver`.
 */
export const withOutboundMessage = async <T>(
  params: OutboundMessageParams,
  deliver: (message: OutboundMessage) => Promise<T>,
): Promise<T> => {
  const message = new OutboundMessage(params);
  try {
    return await deliver(message);
  } finally {
    message.close();
  }
};

/** The part of a data channel the send-buffer wait reads and listens to. */
export interface SendBufferChannel {
  readonly readyState: string;
  readonly bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  addEventListener(type: string, listener: () => void): void;
  removeEventListener(type: string, listener: () => void): void;
}

export interface SendBufferTimers {
  readonly setTimeout: (callback: () => void, ms: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
}

const sendBufferTimers: SendBufferTimers = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
};

// The events after which a data channel can no longer be sent on.
const CHANNEL_END_EVENTS = ["close", "closing", "error"] as const;

const SEND_BUFFER_WAKE_EVENTS = [
  "bufferedamountlow",
  ...CHANNEL_END_EVENTS,
] as const;

/**
 * Wait until `channel` can take another frame. Resolves true at once while
 * its buffer is below MAX_BUFFERED_AMOUNT; otherwise sets the low threshold
 * and waits for `bufferedamountlow`. Resolves false once the channel is no
 * longer open (the caller stops this pass, as the polling loop's caller did),
 * and rejects with the transfer's abort reason when `signal` aborts.
 *
 * The listeners are registered before the amount is re-checked, and a
 * SEND_BUFFER_FALLBACK_MS timer re-checks it after that, so a drain the event
 * did not report still ends the wait.
 */
export const waitForSendBuffer = async (
  channel: SendBufferChannel,
  signal?: AbortSignal,
  timers: SendBufferTimers = sendBufferTimers,
): Promise<boolean> => {
  throwIfTransferAborted(signal);
  if (channel.readyState !== "open") return false;
  if (channel.bufferedAmount < MAX_BUFFERED_AMOUNT) return true;

  return await new Promise<boolean>((resolve, reject) => {
    let settled = false;
    let timer: unknown;
    const finish = (settle: () => void): void => {
      settled = true;
      if (timer !== undefined) timers.clearTimeout(timer);
      for (const type of SEND_BUFFER_WAKE_EVENTS)
        channel.removeEventListener(type, check);
      signal?.removeEventListener("abort", check);
      settle();
    };
    const check = (): void => {
      if (settled) return;
      if (signal?.aborted) {
        finish(() => {
          try {
            throwIfTransferAborted(signal);
          } catch (error) {
            reject(error);
          }
        });
      } else if (channel.readyState !== "open")
        finish(() => {
          resolve(false);
        });
      else if (channel.bufferedAmount <= SEND_BUFFER_LOW_THRESHOLD)
        finish(() => {
          resolve(true);
        });
    };
    const fallback = (): void => {
      timer = undefined;
      check();
      if (!settled)
        timer = timers.setTimeout(fallback, SEND_BUFFER_FALLBACK_MS);
    };

    channel.bufferedAmountLowThreshold = SEND_BUFFER_LOW_THRESHOLD;
    for (const type of SEND_BUFFER_WAKE_EVENTS)
      channel.addEventListener(type, check);
    signal?.addEventListener("abort", check);
    check();
    if (!settled) timer = timers.setTimeout(fallback, SEND_BUFFER_FALLBACK_MS);
  });
};

/** The transfer's own channel, as the immediate-mode completion wait reads it. */
export interface TransferFrameSource {
  /** Only "closing" and "closed" end the wait; absent reads as open. */
  readonly readyState?: string;
  addEventListener(type: string, listener: () => void): void;
  removeEventListener(type: string, listener: () => void): void;
}

/**
 * Immediate mode, every chunk acknowledged: wait for the final receipt while
 * the receiver verifies the whole file. Any frame on the transfer's own
 * channel (a re-sent receipt) re-arms the RECEIVER_SILENCE_LIMIT_MS bound;
 * the wait is capped at reportedCompletionCapMs(totalSize). Only this peer
 * can send on that channel, and only about this transfer.
 *
 * The channel closing ends the wait at once: a close is the edge going away
 * or the receiver's cancel, and the caller handles it as it handles any close
 * (resume, or the cancel outcome).
 */
export const waitForVerifiedDelivery = (
  channel: TransferFrameSource,
  roomId: string,
  peerId: string,
  transferId: string,
  totalSize: number,
  options: {
    readonly signal?: AbortSignal;
    readonly clock?: TransferWaitClock;
  } = {},
): Promise<boolean> =>
  waitForReportedCompletion(roomId, peerId, transferId, {
    silenceMs: RECEIVER_SILENCE_LIMIT_MS,
    capMs: reportedCompletionCapMs(totalSize, RECEIVER_SILENCE_LIMIT_MS),
    onActivity: (wake) => {
      channel.addEventListener("message", wake);
      return () => {
        channel.removeEventListener("message", wake);
      };
    },
    onInterrupt: (interrupt) => {
      for (const type of CHANNEL_END_EVENTS)
        channel.addEventListener(type, interrupt);
      return () => {
        for (const type of CHANNEL_END_EVENTS)
          channel.removeEventListener(type, interrupt);
      };
    },
    isInterrupted: () =>
      channel.readyState === "closing" || channel.readyState === "closed",
    signal: options.signal,
    clock: options.clock,
  });

/**
 * Scheduled mode, every chunk acknowledged: the same wait, re-armed by each
 * authenticated scheduled receipt for this transfer as coverEdge attributes
 * it (noteTransferActivity). `silenceMs` is the caller's: a scheduled receipt
 * can arrive only in a cover slot, so the bound is at least the schedule's
 * own delivery idle budget. `onInterrupt`/`isInterrupted` end it at once for
 * an edge that was replaced or torn down.
 */
export const waitForScheduledVerifiedDelivery = (
  roomId: string,
  peerId: string,
  transferId: string,
  totalSize: number,
  silenceMs: number,
  options: {
    readonly onInterrupt?: (interrupt: () => void) => () => void;
    readonly isInterrupted?: () => boolean;
    readonly isHeld?: () => boolean;
    readonly signal?: AbortSignal;
    readonly clock?: TransferWaitClock;
    readonly subscribeActivity?: typeof onTransferActivity;
  } = {},
): Promise<boolean> =>
  waitForReportedCompletion(roomId, peerId, transferId, {
    silenceMs,
    capMs: reportedCompletionCapMs(totalSize, silenceMs),
    onActivity: (wake) =>
      (options.subscribeActivity ?? onTransferActivity)(
        roomId,
        peerId,
        transferId,
        wake,
      ),
    onInterrupt: options.onInterrupt,
    isInterrupted: options.isInterrupted,
    isHeld: options.isHeld,
    signal: options.signal,
    clock: options.clock,
  });

/**
 * The wait between retransmit rounds of an immediate transfer. While a real
 * chunk is unacknowledged it is the round's fixed RETRANSMIT_TIMEOUT_MS wait;
 * once every chunk is acknowledged it is waitForVerifiedDelivery, and
 * `verifying` tells the caller there is nothing left to retransmit.
 */
export const waitForTransferConfirmation = async (
  message: OutboundMessage,
  channel: TransferFrameSource,
  roomId: string,
  peerId: string,
  retries: number,
  signal?: AbortSignal,
  clock?: TransferWaitClock,
): Promise<{ readonly done: boolean; readonly verifying: boolean }> => {
  const { transferId } = message;
  if (
    message.allRealsAcknowledged((index) =>
      hasChunkAcked(roomId, peerId, transferId, index),
    )
  )
    return {
      verifying: true,
      done: await waitForVerifiedDelivery(
        channel,
        roomId,
        peerId,
        transferId,
        message.totalSize,
        { signal, clock },
      ),
    };
  return {
    verifying: false,
    done: await waitForCompletion(
      roomId,
      peerId,
      transferId,
      RETRANSMIT_TIMEOUT_MS * (retries + 1),
      signal,
      { clock },
    ),
  };
};

/**
 * One pass over a message's cells on one per-message channel, in a fresh
 * random order.
 *
 * Without `reconcileAcked` (the first pass) every cell, real and decoy, is
 * read once and sent once. With it (a retransmit or resume pass) only the real
 * cells the receiver has not acknowledged are sent, and a cell already known
 * to be acknowledged or a decoy is skipped before it is read.
 *
 * Exported only for a focused unit test of that read and proof pattern. It is
 * not part of the package's public root exports.
 */
export const sendChunks = async (
  channel: IRTCDataChannel,
  // v4: the sealer holds the combined key derived ONCE for the whole message
  // from the caller's ratchet step (`ratchetEncryptDurably`). Every chunk of
  // the message — across the initial pass AND every selective-retransmit
  // round — is sealed under this same key with a FRESH random nonce
  // (streaming-safe; no per-message frame cache needed).
  sealer: MessageChunkSealer,
  message: OutboundMessage,
  signal?: AbortSignal,
  // When set (reconcile: selective retransmit / resume), resend ONLY the un-acked
  // real chunks — skip decoys and already-acked reals.
  reconcileAcked?: Set<number>,
  // This transfer edge's receipts (live count + wake-up); enables the
  // sender-side receipt window. Absent → legacy SCTP-only pacing.
  receipts?: ReceiptProgress,
  outboxLease?: OutboxLease,
): Promise<void> => {
  throwIfTransferAborted(signal);
  const { merkleRootHex } = await decompileChannelMessageLabel(channel.label);
  if (merkleRootHex !== message.merkleRootHex)
    throw new Error("Outbound channel label does not match its Merkle root");

  // Receipts landing during this pass shrink the window; acks that predate the
  // pass (resume replays) must not count against frames sent in this pass.
  const ackedAtPassStart = receipts?.count() ?? 0;
  let sentRealThisPass = 0;

  const indexes = Array.from({ length: message.totalChunks }, (_, i) => i);
  const indexesRandomized = fisherYatesShuffle(indexes);

  for (let i = 0; i < message.totalChunks; i++) {
    throwIfTransferAborted(signal);
    const iRandom = indexesRandomized[i];

    // Reconcile: resend only un-acked REAL chunks. Decoys are cover and never
    // resent; acked reals are skipped. What is already known is skipped
    // before the read, so a retransmit round reads only what it may send.
    if (
      reconcileAcked !== undefined &&
      (reconcileAcked.has(iRandom) || message.isKnownDecoy(iRandom))
    )
      continue;

    const staged = await message.read(iRandom, signal);
    if (!staged)
      throw new Error(`Missing staged outbound chunk ${String(iRandom)}`);
    if (reconcileAcked !== undefined && !staged.real) continue;

    // Hold real frames inside the receipt window so a fast link cannot outrun
    // the receiver's decrypt+store drain into its queue-budget channel close.
    if (staged.real && receipts) {
      await waitForReceiptWindow({
        windowSize: SEND_RECEIPT_WINDOW,
        stallTimeoutMs: SEND_WINDOW_STALL_MS,
        fallbackMs: RECEIPT_WINDOW_FALLBACK_MS,
        isOpen: () => (channel.readyState as string) === "open",
        inFlight: () =>
          sentRealThisPass - Math.max(0, receipts.count() - ackedAtPassStart),
        subscribe: (wake) => {
          const unsubscribe = receipts.subscribe(wake);
          for (const type of CHANNEL_END_EVENTS)
            channel.addEventListener(type, wake);
          return () => {
            unsubscribe();
            for (const type of CHANNEL_END_EVENTS)
              channel.removeEventListener(type, wake);
          };
        },
        signal,
      });
    }

    const chunk = await message.cellPlaintext(staged, outboxLease, signal);

    // protocol-v3: seal the DECRYPTED_LEN plaintext (metadata ‖ proof ‖ chunk)
    // under the per-message ratchet key with a fresh random nonce, framed as
    // FRAME_TYPE_CHUNK ‖ dhPub ‖ N ‖ PN ‖ PQ_EPOCH ‖ nonce ‖ ciphertext‖tag.
    // Replaces the box scheme's per-chunk ephemeral keypair + signature + asymmetric
    // encrypt. A retransmit re-seals the same plaintext (fresh nonce) — the receiver
    // reuses its cached per-(dhPub,N) key, so no frame cache is required.
    // Backpressure stays inside this logical send. Persisting ciphertext here is
    // unsafe: a replacement RTCPeerConnection performs a fresh handshake, so
    // ciphertext sealed under the dead transport's ratchet can never be replayed
    // on the replacement. The durable resend source is the plaintext newChunks
    // store; after reconnect those chunks are resealed under a fresh message key.
    if (!(await waitForSendBuffer(channel, signal))) {
      debugLog(
        "Cannot send message because channel is " +
          channel.readyState +
          " and bufferedAmount is " +
          String(channel.bufferedAmount),
      );

      break;
    }

    let frame: Uint8Array;
    try {
      frame = sealer.seal(chunk, message.merkleRoot);
    } catch (error) {
      throw new Error("Could not seal outbound message chunk", {
        cause: error,
      });
    }

    throwIfTransferAborted(signal);
    try {
      channel.send(frame.buffer as ArrayBuffer);
      if (staged.real) sentRealThisPass++;
    } catch (error) {
      // The channel can close between the readyState check and send(). Return to
      // the reconcile loop so it can reopen/rekey instead of rejecting the whole
      // logical send at this unavoidable async transport race.
      if ((channel.readyState as string) !== "open") break;
      throw error;
    }
  }
  // protocol-v3: no box wasm scratch to free — each seal allocates + frees its
  // own transient buffers; the sealer and the message key are owned + wiped by
  // the caller after the last retransmit round.
};

// Resume-on-reconnect: a FULL peer reconnect (new RTCPeerConnection) destroys the
// per-message channel — only "main" is auto-reopened, and frames buffered in the
// dead channel were lost and never relayed. Wait (bounded) for the peer's fresh
// connection, re-open the SAME Merkle-root-labeled channel on it, and return it
// so the reconcile loop continues. The label is a pure function of the message,
// so it is byte-identical across the reconnect; the receiver re-emits its stored
// receipts on the new channel's onopen, letting the sender resend only the reals
// still missing. Returns null if the peer does not come back in time.
/**
 * Resolve true when the edge is usable, false when it is beyond repair or the
 * budget expires.
 *
 * `closed` and `failed` are terminal, so they resolve immediately rather than
 * burning the whole budget. Every other state is treated as in-flight: a peer
 * mid-ICE-restart reports `disconnected`, which is exactly the case this
 * exists for.
 *
 * The listener is added with `addEventListener` because handleConnectToPeer
 * installs the `onconnectionstatechange` *property* handler; using the
 * property here would silently replace the reconnect logic.
 */
const waitForConnectedEdge = (
  epc: IRTCPeerConnection,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<boolean> => {
  if (epc.connectionState === "connected") return Promise.resolve(true);
  if (epc.connectionState === "closed" || epc.connectionState === "failed")
    return Promise.resolve(false);
  if (signal?.aborted) return Promise.resolve(false);

  return new Promise<boolean>((resolve) => {
    let settled = false;
    const settle = (usable: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      epc.removeEventListener("connectionstatechange", onChange);
      signal?.removeEventListener("abort", onAbort);
      resolve(usable);
    };
    const onChange = (): void => {
      if (epc.connectionState === "connected") settle(true);
      else if (
        epc.connectionState === "closed" ||
        epc.connectionState === "failed"
      )
        settle(false);
    };
    const onAbort = (): void => {
      settle(false);
    };
    const timer = setTimeout(() => {
      settle(false);
    }, timeoutMs);
    epc.addEventListener("connectionstatechange", onChange);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
};

/**
 * Is this connection a transport a resumed transfer may open its per-message
 * channel on?
 *
 * `connectionState === "connected"` alone means DTLS is complete — it says
 * nothing about the main-channel handshake. Opening the per-message channel on
 * such a transport is what let the peer's replayed receipts arrive ahead of
 * THIS side's ratchet gate: the identity responder authenticates on SENDING
 * finish and replays immediately, while the initiator authenticates on
 * RECEIVING it, one IndexedDB persist later (C7). Requiring the gate to be
 * open, on this connection's own lease, removes that window at its source
 * instead of relying on the receiving guard to park the early frame.
 *
 * Not finding one is not fatal: the caller polls until its resume budget runs
 * out, which is exactly what it already did for a transport that had not
 * reconnected yet.
 */
export const isResumableAuthenticatedTransport = (
  candidate: IRTCPeerConnection,
  roomId: string,
  peerId: string,
): boolean =>
  candidate.roomId === roomId &&
  candidate.withPeerId === peerId &&
  candidate.connectionState === "connected" &&
  isRatchetGateOpen(roomId, peerId, candidate.ratchetGateLease);

const resumeChannel = async (
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelMessageLabel: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  timeoutMs: number,
  signal?: AbortSignal,
  deleteSendQueue: (label: string, peerId: string) => Promise<void> = (
    label,
    toPeerId,
  ) => deleteDBSendQueue(label, toPeerId),
): Promise<{
  epc: IRTCPeerConnection;
  channel: IRTCDataChannel;
} | null> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    throwIfTransferAborted(signal);
    const epc = peerConnections.find((p) =>
      isResumableAuthenticatedTransport(p, roomId, peerId),
    );
    if (!epc) {
      await new Promise((resolve) =>
        setTimeout(resolve, RECONNECT_RESUME_POLL_MS),
      );
      throwIfTransferAborted(signal);
      continue;
    }
    try {
      // A previous build may have left ciphertext in the legacy durable queue.
      // Drop it before the replacement channel can observe bufferedamountlow:
      // its ratchet belongs to the dead transport and is not replay-safe here.
      await deleteSendQueue(
        roomSendQueueLabel(roomId, channelMessageLabel),
        peerId,
      );
      const ch = await handleOpenChannel(
        { channel: channelMessageLabel, epc, roomId, dataChannels },
        api,
      );
      // Await opening for the REMAINING budget rather than a fixed window, so a
      // slow-to-open channel is waited on — NOT re-created, which would spawn a
      // duplicate same-label channel that leaks receive buffers and blocks the
      // newChunks cleanup. If it still hasn't opened (timed out, or the pc died
      // again mid-open), neutralize it so it can never later open, push into
      // dataChannels, or malloc receive buffers, then look for a fresh epc.
      if (await waitForOpen(ch, deadline - Date.now(), undefined, signal))
        return { epc, channel: ch };
      try {
        closeTransferChannel(ch);
      } catch (error) {
        console.error(error);
      }
      throwIfTransferAborted(signal);
    } catch (error) {
      console.error(error);
    }
  }
  return null;
};

interface TransferCipher {
  epc: IRTCPeerConnection;
  /**
   * Gate lease of the ratchet generation `messageKey`/`header` were derived
   * from. An in-place re-bind (remoteTransportChange) keeps the
   * RTCPeerConnection and replaces this lease, so the epc identity alone does
   * NOT identify the crypto generation.
   */
  lease?: RatchetGateLease;
  messageKey: Uint8Array;
  header: RatchetHeader;
  /**
   * OWNED copy of the PQ message context captured in the same edge
   * transaction as the ratchet step (v4). Null only on runtime-free
   * bootstrap/test edges. Wiped with the message key.
   */
  pqContext?: PqMessageKeyContext | null;
}

/**
 * Stop a per-message transport without depending on its eventual `close`
 * event to release protocol accounting. This also covers cancellation while
 * the SCTP stream is still connecting and has not entered `dataChannels`.
 */
export const closeTransferChannel = (channel: IRTCDataChannel): void => {
  // Record the close as OURS before performing it. sendWithReconcile reads the
  // very channel it closed on its next loop iteration, and without this marker
  // an entirely local retirement is reported as the peer cancelling — which
  // deletes the sender's staging and, via the close the peer observes, the
  // receiver's partial file (C7).
  markChannelClosedLocally(channel);
  channel.releaseProtocolResources?.();
  if (channel.readyState !== "closed") channel.close();
};

/**
 * Own the one normal terminal close for a message-scoped channel. Receipt
 * handling only records authenticated completion; sendWithReconcile reaches
 * this boundary after its send/reconcile work settles.
 */
export const runWithTerminalChannelClose = async <T>(
  currentChannel: () => IRTCDataChannel,
  operation: () => Promise<T>,
): Promise<T> => {
  try {
    return await operation();
  } finally {
    closeTransferChannel(currentChannel());
  }
};

type WaitForRatchetGate = (
  roomId: string,
  peerId: string,
  signal?: AbortSignal,
) => Promise<void>;
type DurableRatchetStep = (
  epc: IRTCPeerConnection,
  roomId: string,
  module: LibCrypto,
) => Promise<{
  messageKey: Uint8Array;
  header: RatchetHeader;
  pqContext: PqMessageKeyContext | null;
}>;

// v4: the sparse-PQ orchestrator blocks application sends during a healing
// exchange (its own machine phase plus the inbound-control gate). Poll the
// admission check with a bound comfortably above the exchange's worst-case
// retry window (8 attempts × 5 s).
const PQ_ADMISSION_POLL_MS = 25;
const PQ_ADMISSION_TIMEOUT_MS = 60_000;

const waitForPqTrafficAdmission = async (
  epc: IRTCPeerConnection,
  signal?: AbortSignal,
): Promise<void> => {
  if (!epc.pqHealingState) return; // runtime-free bootstrap/test edge
  const deadline = Date.now() + PQ_ADMISSION_TIMEOUT_MS;
  while (isPqApplicationTrafficBlocked(epc)) {
    throwIfTransferAborted(signal);
    if (Date.now() > deadline)
      throw new Error(
        "v4 send: sparse-PQ healing did not settle before the send timeout",
      );
    await new Promise((resolve) => setTimeout(resolve, PQ_ADMISSION_POLL_MS));
  }
};

/**
 * Bind an in-flight message to the active cryptographic transport.
 *
 * Reopening only its DataChannel on the same RTCPeerConnection AND the same
 * ratchet generation retains the session, so the per-message key/header remain
 * valid. Anything else — a replacement RTCPeerConnection, or the same one
 * re-bound in place onto a new remote DTLS certificate — performs a fresh
 * hybrid handshake and owns an unrelated ratchet. It must wait for that
 * generation's gate, advance its ratchet once and reseal the missing plaintext
 * chunks; replaying the old ciphertext/key/header cannot decrypt.
 *
 * The generation is identified by the gate lease, NOT by the connection: an
 * in-place re-bind keeps the very same epc while wiping its ratchet, PQ
 * runtime and message keys. Treating that as "same transport" would keep
 * sealing with a dead key and, worse, push frames onto an edge whose gate is
 * still closed — which the receiver can only reject as application data before
 * peer authentication, closing the channel and cascading into the edge.
 *
 * Exported only so the transport-identity and key-erasure contract has a focused
 * unit test. It is not part of the package's public root exports.
 */
export const bindTransferCipherToConnection = async (
  transfer: TransferCipher,
  nextEpc: IRTCPeerConnection,
  roomId: string,
  module: LibCrypto,
  waitForGate: WaitForRatchetGate = waitForRatchetGate,
  ratchetStep: DurableRatchetStep = ratchetEncryptDurably,
  signal?: AbortSignal,
): Promise<TransferCipher> => {
  throwIfTransferAborted(signal);
  if (transfer.epc === nextEpc && transfer.lease === nextEpc.ratchetGateLease)
    return transfer;

  await waitWithTransferAbort(
    waitForGate(roomId, nextEpc.withPeerId, signal),
    signal,
  );
  if (!nextEpc.ratchetState)
    throw new Error("v3 send: replacement connection has no ratchet state");

  const stepped = await ratchetStep(nextEpc, roomId, module);
  if (signal?.aborted) {
    stepped.messageKey.fill(0);
    stepped.pqContext?.rootKey.fill(0);
    throwIfTransferAborted(signal);
  }
  transfer.messageKey.fill(0);
  transfer.pqContext?.rootKey.fill(0);
  return {
    epc: nextEpc,
    lease: nextEpc.ratchetGateLease,
    messageKey: stepped.messageKey,
    header: stepped.header,
    pqContext: stepped.pqContext,
  };
};

/**
 * True iff a per-message channel closing is the PEER cancelling this transfer.
 *
 * Immediate mode has no CANCEL frame: one DataChannel is one logical message,
 * so its close IS the signal — but only when nothing on OUR side retired it.
 * Three things must hold: the RTCPeerConnection is still connected, it is
 * still the registered transport for this room/peer, and the ratchet
 * generation the transfer was sealed under is still the current one.
 *
 * That last test is what separates a remote cancel from a local retirement.
 * An in-place edge re-bind (remoteTransportChange) closes the generation's
 * message channels while KEEPING the connection connected and registered, so
 * the first two tests still pass; the gate lease it replaces is the only
 * evidence that the close was ours. Without it the sender abandons a perfectly
 * resumable transfer — and reports "cancelled by peer", which an application
 * may act on by deleting its outgoing message. Mirrors the receiver's
 * `authenticatedTransportStillAlive` test in handleOpenChannel.
 */
export const isAuthenticatedPeerCancel = (
  currentEpc: IRTCPeerConnection,
  peerConnections: IRTCPeerConnection[],
  roomId: string,
  peerId: string,
  transferGateLease: RatchetGateLease | undefined,
  currentChannel: IRTCDataChannel | undefined,
): boolean =>
  // A channel THIS side closed is never the peer's cancel signal, however
  // healthy every other check looks. The pre-authentication frame guard closes
  // a channel whose gate has not settled yet, and on a resumed edge that is
  // routine — the gate opens a moment later, every test below then passes, and
  // the sender reports a cancel nobody sent (C7).
  !wasChannelClosedLocally(currentChannel) &&
  (hasImmediateRemoteCancel(currentChannel) ||
    !immediateCloseMeansPause(currentChannel)) &&
  currentEpc.connectionState === "connected" &&
  transferGateLease !== undefined &&
  isCurrentRatchetGateLease(roomId, peerId, transferGateLease) &&
  peerConnections.some(
    (candidate) =>
      candidate === currentEpc &&
      candidate.roomId === roomId &&
      candidate.withPeerId === peerId,
  );

/**
 * A resumed transfer failed to re-bind onto the transport it resumed on: is
 * another of its bounded resume attempts owed?
 *
 * The normal reason is that the transport was REPLACED before its gate could
 * open — an unauthenticated transport is granted at most one in-place re-bind
 * (decideRemoteTransportChangeResponse), and the replacement tears the old one
 * down, which rejects the gate every awaiter is sitting on. The peer is coming
 * back on the replacement, so giving up here would abandon a transfer that is
 * one attempt away from finishing.
 *
 * Two failures are terminal. A cancelled transfer resumes nothing. And a
 * gate-wait TIMEOUT means nothing replaced anything: the peer simply never
 * opened a handshake within the budget (a stale authenticated view), so
 * another attempt only buys another full budget of the same wait — the same
 * reason the send's first gate wait rethrows it.
 */
export const isResumableRebindFailure = (
  error: unknown,
  signal?: AbortSignal,
): boolean => !signal?.aborted && !isRatchetGateWaitTimeout(error);

export interface PeerSendTarget {
  peerId: string;
  epc?: IRTCPeerConnection;
}

export type PeerDeliveryOutcome =
  | {
      peerId: string;
      status: "delivered";
    }
  | {
      peerId: string;
      status: "failed";
      phase: "setup" | "transfer";
      reason: unknown;
    }
  | {
      peerId: string;
      status: "skipped";
      // "not-connected": the transport itself never reached (or fell back out
      // of) "connected" within the admission wait -- a remote condition that
      // may never resolve.
      // "cover-unavailable": the transport IS connected, but this edge's
      // scheduled-cover runtime cannot currently admit a job (missing,
      // suspended -- by a pagehide, a freeze or going offline -- or stopped).
      // A hidden page does not suspend it. That is local and typically
      // temporary: it resolves on its own once the page is restored or back
      // online, unlike a dead peer.
      reason:
        "not-connected" | "cover-unavailable" | "unauthenticated" | "cancelled";
    };

export interface PeerSendFanoutResult {
  outcomes: PeerDeliveryOutcome[];
  startedTransfers: number;
}

type OpenPeerTransferChannel = (
  target: Required<PeerSendTarget>,
) => Promise<IRTCDataChannel>;
type StartPeerTransfer = (
  target: Required<PeerSendTarget>,
  channel: IRTCDataChannel,
) => Promise<void>;

/**
 * Set up every eligible room edge and settle every transfer that was started.
 *
 * Opening channels remains sequential so it cannot burst through the per-edge
 * channel budget. Transfer promises run concurrently, however, and are given a
 * rejection handler immediately. A later setup failure therefore becomes that
 * peer's outcome instead of unwinding past already-running sends and freeing
 * their shared `newChunks` staging records.
 */
export const runPeerSendFanout = async (
  targets: readonly PeerSendTarget[],
  openChannel: OpenPeerTransferChannel,
  startTransfer: StartPeerTransfer,
  signal?: AbortSignal,
  onTransferStarted?: () => void,
): Promise<PeerSendFanoutResult> => {
  const outcomes: Array<PeerDeliveryOutcome | Promise<PeerDeliveryOutcome>> =
    [];
  let startedTransfers = 0;

  for (const target of targets) {
    if (signal?.aborted) {
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "cancelled",
      });
      continue;
    }

    // A repairing edge is not a dead one: wait out the ICE-restart grace
    // period before declaring the peer unreachable.
    if (
      !target.epc ||
      !(await waitForConnectedEdge(target.epc, PEER_ADMISSION_WAIT_MS, signal))
    ) {
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "not-connected",
      });
      continue;
    }
    if (
      target.epc.withPeerPublicKey.length !==
      crypto_sign_ed25519_PUBLICKEYBYTES * 2
    ) {
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "unauthenticated",
      });
      continue;
    }

    const authenticatedTarget = target as Required<PeerSendTarget>;
    let channel: IRTCDataChannel;
    try {
      channel = await openChannel(authenticatedTarget);
    } catch (reason) {
      outcomes.push({
        peerId: target.peerId,
        status: "failed",
        phase: "setup",
        reason,
      });
      continue;
    }

    // Cancellation can race the asynchronous channel setup. No transfer owns
    // this channel yet, so close it here rather than relying on sendWithReconcile
    // (whose first abort check intentionally precedes its own try/finally).
    if (signal?.aborted) {
      closeTransferChannel(channel);
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "cancelled",
      });
      continue;
    }

    startedTransfers++;
    onTransferStarted?.();
    try {
      const started = startTransfer(authenticatedTarget, channel);
      outcomes.push(
        Promise.resolve(started).then<PeerDeliveryOutcome, PeerDeliveryOutcome>(
          () => ({
            peerId: target.peerId,
            status: "delivered",
          }),
          (reason: unknown) => ({
            peerId: target.peerId,
            status: "failed",
            phase: "transfer",
            reason,
          }),
        ),
      );
    } catch (reason) {
      // The production callback is async, but retaining the synchronous guard
      // makes this lifecycle helper safe for injected transports as well.
      closeTransferChannel(channel);
      outcomes.push({
        peerId: target.peerId,
        status: "failed",
        phase: "transfer",
        reason,
      });
    }
  }

  return {
    outcomes: await Promise.all(outcomes),
    startedTransfers,
  };
};

export interface SendMessageResult extends PeerSendFanoutResult {
  transferId: string;
  merkleRootHex: string;
}

export class MessageDeliveryError extends AggregateError {
  readonly result: SendMessageResult;

  constructor(result: SendMessageResult, message: string) {
    super(
      result.outcomes
        .filter(
          (
            outcome,
          ): outcome is Extract<PeerDeliveryOutcome, { status: "failed" }> =>
            outcome.status === "failed",
        )
        .map((outcome) => outcome.reason),
      message,
    );
    this.name = "MessageDeliveryError";
    this.result = result;
  }
}

/**
 * The sender's history is independent of remote delivery once splitToChunks
 * has committed its complete local copy. Network/setup failures may annotate
 * delivery status, but only an explicit local cancel removes that history.
 */
export const shouldDeleteLocalMessageAfterFailure = (
  localMessageCommitted: boolean,
  wireWorkStarted: boolean,
  explicitlyCancelled: boolean,
): boolean =>
  explicitlyCancelled || (!localMessageCommitted && !wireWorkStarted);

// Send once (all chunks), then reconcile: resend ONLY the un-acked real chunks
// until the receiver confirms completion (its final message-hash receipt) or the
// retry budget is exhausted. The acked set is extrapolated from receipts in
// handleReadReceipt. Selective (never resend-all) so no dup frames pile up. On a
// full reconnect the loop re-establishes the per-message channel and continues
// (resume), rather than giving up — the same reconcile drives both.
/**
 * Test/fault-injection seams for `sendWithReconcile`, the same shape as
 * `ScheduledSendDependencies`. Production passes none of them.
 */
export interface ImmediateSendDependencies {
  readonly ratchetStep?: DurableRatchetStep;
  /** Remove an older runtime's ciphertext queue for this channel. */
  readonly deleteSendQueue?: (label: string, peerId: string) => Promise<void>;
  readonly persistCancellation?: typeof persistOutboundCancellation;
  /** How long a resume watches for the peer's replacement connection. */
  readonly resumeTimeoutMs?: number;
  /** The clock of the waits between retransmit rounds. */
  readonly clock?: TransferWaitClock;
}

/**
 * One peer's immediate-mode transfer of one message, as described above.
 * Exported only so its completion and close handling have focused tests. It is
 * not part of the package's public root exports.
 */
export const sendWithReconcile = async (
  channel: IRTCDataChannel,
  api: BaseQueryApi,
  roomId: string,
  epc: IRTCPeerConnection,
  message: OutboundMessage,
  peerId: string,
  encryptionModule: LibCrypto,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  signal?: AbortSignal,
  outboxLease?: OutboxLease,
  dependencies: ImmediateSendDependencies = {},
): Promise<void> => {
  const ratchetStep = dependencies.ratchetStep ?? ratchetEncryptDurably;
  const deleteSendQueue =
    dependencies.deleteSendQueue ??
    ((label: string, toPeerId: string) => deleteDBSendQueue(label, toPeerId));
  const persistCancellation =
    dependencies.persistCancellation ?? persistOutboundCancellation;
  const { transferId, hashHex } = message;
  throwIfTransferAborted(signal);
  clearTransfer(roomId, peerId, transferId);

  // The ratchet generation this transfer's channel was opened on — the same
  // token handleOpenChannel captured for it. Everything derived below belongs
  // to it, and it is what tells a peer's cancel apart from our own retirement
  // of the generation (isAuthenticatedPeerCancel). Captured BEFORE the gate
  // wait: a re-bind that races the wait leaves a stale token here, which
  // resumes the transfer rather than declaring a cancel that never happened.
  let transportGateLease: RatchetGateLease | undefined = epc.ratchetGateLease;

  // This path no longer persists ciphertext. Remove any queue records left by an
  // older runtime before this channel can drain them; plaintext newChunks are the
  // sole durable resend source.
  await deleteSendQueue(roomSendQueueLabel(roomId, channel.label), peerId);
  throwIfTransferAborted(signal);

  // protocol-v3: do not send until the PACE + Double-Ratchet handshake has seeded
  // this peer's ratchet (the `main` channel opens the gate). A rejected gate =
  // failed handshake → abort this peer's send. The wait is bounded: a peer whose
  // handshake never starts (stale authenticated view after an edge re-dial)
  // fails this send with the transport-binding error instead of hanging.
  try {
    await waitForRatchetGate(roomId, peerId, signal);
  } catch (error) {
    if (isRatchetGateWaitTimeout(error)) throw error;
    throw new Error("v3 send: ratchet gate rejected", { cause: error });
  }
  if (!epc.ratchetState) throw new Error("v3 send: no ratchet state for peer");

  // v4: never step the ratchet into a healing exchange — wait for the sparse-PQ
  // traffic gate before deriving the message key/context.
  await waitForPqTrafficAdmission(epc, signal);

  // Stage one ratchet step for the whole message, persist its successor, then
  // adopt it in memory. No frame is built or sent until durability succeeds.
  // The per-edge transaction lock also prevents concurrent sends from deriving
  // the same message key or persisting snapshots out of order, and captures
  // the PQ message context atomically with the step.
  let messageKey: Uint8Array;
  let header: RatchetHeader;
  let pqContext: PqMessageKeyContext | null;
  try {
    const stepped = await ratchetStep(epc, roomId, encryptionModule);
    if (signal?.aborted) {
      stepped.messageKey.fill(0);
      stepped.pqContext?.rootKey.fill(0);
      throwIfTransferAborted(signal);
    }
    messageKey = stepped.messageKey;
    header = stepped.header;
    pqContext = stepped.pqContext;
  } catch (error) {
    throw new Error("v3 send: durable ratchet advance failed", {
      cause: error,
    });
  }

  let currentChannel = channel;
  let currentEpc = epc;
  // v4: the combined key for this ratchet step, derived once and used for
  // every chunk of every pass. A re-bind that re-steps the ratchet replaces it.
  let chunkSealer = null as MessageChunkSealer | null;
  const runTransfer = async (): Promise<void> => {
    let sealer = createMessageChunkSealer(
      messageKey,
      header,
      pqContext,
      encryptionModule,
    );
    chunkSealer = sealer;
    // The per-message channel label is a pure function of the message, so the dead
    // channel's own label is exactly what we re-open on reconnect.
    const channelMessageLabel = channel.label;

    // Wait for the per-message channel to open before the first send, so its
    // initial frames aren't spilled to the WS relay while it is still connecting.
    if (!(await waitForOpen(currentChannel, undefined, undefined, signal)))
      throw new Error("Message DataChannel did not open before send timeout");
    throwIfTransferAborted(signal);

    // Initial pass: all chunks (real + decoy), real frames held inside the
    // receipt window so the receiver's drain sets the pace on fast links.
    await sendChunks(
      currentChannel,
      sealer,
      message,
      signal,
      undefined,
      edgeReceiptProgress(roomId, peerId, transferId),
      outboxLease,
    );

    let retries = 0;
    let resumeAttempts = 0;
    let completed = false;
    while (retries < MAX_RETRANSMITS) {
      const confirmation = await waitForTransferConfirmation(
        message,
        currentChannel,
        roomId,
        peerId,
        retries,
        signal,
        dependencies.clock,
      );
      throwIfTransferAborted(signal);
      if (confirmation.done) {
        completed = true;
        break;
      }

      // Channel died — a full reconnect. Re-establish it on the peer's fresh
      // connection and continue; the receiver re-emits its receipts so we resend
      // only the still-missing reals. Bounded so a flapping peer can't loop. Only
      // treat a genuinely dead (closed/closing) channel as needing resume — a
      // still-"connecting" channel is given more time via waitForCompletion.
      if (
        currentChannel.readyState === "closed" ||
        currentChannel.readyState === "closing"
      ) {
        // One DataChannel is one logical message. If only this stream closed
        // while its authenticated RTCPeerConnection remains current, connected
        // AND on the generation this transfer was sealed under, that close is
        // the peer's immediate-mode CANCEL signal. Resume is reserved for a
        // replacement PC after a transport failure — and for the same PC once
        // an in-place re-bind has retired this transfer's generation, which
        // closes its channel from our own side.
        if (
          isAuthenticatedPeerCancel(
            currentEpc,
            peerConnections,
            roomId,
            peerId,
            transportGateLease,
            currentChannel,
          )
        ) {
          await persistCancellation({
            roomId,
            peerId,
            peerPublicKey: currentEpc.withPeerPublicKey,
            transferId,
            merkleRootHex: message.merkleRootHex,
          });
          throw new Error("Message transfer cancelled by peer");
        }

        if (resumeAttempts >= MAX_RESUME_ATTEMPTS) break;
        resumeAttempts++;
        // A legacy receiver deletes partial data on channel close. Rebuild its
        // have-set from the reopened channel instead of trusting prior receipts.
        clearTransfer(roomId, peerId, transferId);
        const resumed = await resumeChannel(
          api,
          roomId,
          peerId,
          channelMessageLabel,
          peerConnections,
          dataChannels,
          dependencies.resumeTimeoutMs ?? RECONNECT_RESUME_TIMEOUT_MS,
          signal,
          deleteSendQueue,
        );
        if (!resumed) break;
        // Adopt the replacement channel BEFORE re-deriving: re-binding can
        // reject (a gate that never opens on the new generation), and the
        // terminal-close runner must then close the channel we just opened,
        // not the dead one it replaced.
        currentChannel = resumed.channel;
        // The whole cipher — key, header and the OWNED PQ context — is handed
        // over, so the old generation's secrets are wiped by the re-bind
        // instead of being dropped un-wiped when `pqContext` is reassigned.
        let rebound: TransferCipher;
        try {
          rebound = await bindTransferCipherToConnection(
            {
              epc: currentEpc,
              lease: transportGateLease,
              messageKey,
              header,
              pqContext,
            },
            resumed.epc,
            roomId,
            encryptionModule,
            waitForRatchetGate,
            ratchetStep,
            signal,
          );
        } catch (error) {
          if (!isResumableRebindFailure(error, signal)) throw error;
          // The generation we resumed onto never opened its gate — it was
          // replaced first. Nothing was re-derived, so the cipher is still the
          // old generation's and this channel must never carry a frame (an
          // unauthenticated edge can only reject it, closing the channel and
          // cascading into `main`). Drop it and spend another of the bounded
          // resume attempts on the transport that replaces it.
          console.error(error);
          closeTransferChannel(currentChannel);
          continue;
        }
        const restepped = rebound.messageKey !== messageKey;
        currentEpc = rebound.epc;
        transportGateLease = rebound.lease;
        messageKey = rebound.messageKey;
        header = rebound.header;
        pqContext = rebound.pqContext ?? null;
        if (restepped) {
          // The re-bind wiped the old step's key and context; derive the
          // combined key for the new step.
          sealer.wipe();
          sealer = createMessageChunkSealer(
            messageKey,
            header,
            pqContext,
            encryptionModule,
          );
          chunkSealer = sealer;
        }
        retries = 0; // fresh retransmit budget for the resumed transfer

        // Telemetry: surface the reconnect recovery to the UI as a reliability
        // event (the user validates the transfer survived a dropped connection).
        api.dispatch(
          incrementMessageStats({
            roomId,
            sha512Hex: hashHex,
            retransmit: true,
          }),
        );
        continue;
      }

      // Every chunk is acknowledged and the verifying receiver went silent
      // (or ran past the cap): nothing is left to retransmit.
      if (confirmation.verifying) break;

      // Reconcile: resend only the reals the receiver hasn't acked yet. Same
      // message key + header + PQ context (the ratchet is NOT re-stepped); a
      // fresh nonce per re-seal keeps it safe and the receiver's cached key
      // still opens it.
      await sendChunks(
        currentChannel,
        sealer,
        message,
        signal,
        getAckedChunks(roomId, peerId, transferId),
        edgeReceiptProgress(roomId, peerId, transferId),
        outboxLease,
      );
      retries++;

      // Telemetry: a retransmit round happened — lets the UI show reliability.
      api.dispatch(
        incrementMessageStats({ roomId, sha512Hex: hashHex, retransmit: true }),
      );
    }
    // A final receipt can land while a resume or a retransmit round gives
    // up: a transfer the receiver has confirmed is never reported failed.
    if (!completed && !isTransferComplete(roomId, peerId, transferId))
      throw new Error("Message transfer ended without receiver confirmation");
  };
  try {
    await runWithTerminalChannelClose(
      () => currentChannel,
      async () => {
        try {
          await runTransfer();
        } finally {
          if (
            signal?.aborted &&
            !(signal.reason instanceof OutboxOwnershipLostError)
          )
            await sendImmediateCancel(currentChannel);
        }
      },
    );
  } finally {
    // The combined key, message key + owned PQ context copy are dead once
    // every retransmit round for this message is done (or given up) — wipe
    // them. The ratchet has already advanced past the key.
    chunkSealer?.wipe();
    messageKey.fill(0);
    pqContext?.rootKey.fill(0);
    clearTransfer(roomId, peerId, transferId);
  }
};

// Seal exactly one staged chunk into its uniform 65,490-byte cell under the
// message's sealer (its combined key, derived once). Mirrors sendChunks'
// per-chunk staging but for a single index, so a scheduled slot can lazily
// produce one cell without a burst.
const makeScheduledSlotSealer =
  (
    message: OutboundMessage,
    chunkSealer: MessageChunkSealer,
    jobRetired: () => boolean,
    outboxLease?: OutboxLease,
    signal?: AbortSignal,
  ) =>
  async (chunkIndex: number): Promise<Uint8Array | null> => {
    try {
      const staged = await message.read(chunkIndex, signal);
      if (!staged) return null;
      const chunk = await message.cellPlaintext(staged, outboxLease, signal);
      return chunkSealer.seal(chunk, message.merkleRoot);
    } catch (error) {
      // Nothing is left to send once the delivery this job served has ended
      // (confirmed, cancelled, timed out) or the job has settled and its key
      // was wiped, and any await above can outlive that moment: the closed
      // message, the abort and the wiped sealer each throw. The answer is a
      // dummy cell. Throwing makes the scheduler degrade the whole edge
      // (cell-production-failed), which stops cover for every job on it right
      // after a transfer ends.
      if (signal?.aborted || message.closed || jobRetired()) return null;
      throw error;
    }
  };

/**
 * Can this edge's cover runtime still admit a scheduled job?
 *
 * A scheduled job is dequeued only at a cycle open, and `CoverScheduler`
 * refuses to open one while suspended or stopped. Enqueuing into either and
 * then awaiting the schedule-derived delivery bound burns that whole budget —
 * 321 s on the shipped "5 min cycles" preset — for a job nothing was going to
 * send, and the whole send's result waits for every peer's outcome, so it
 * holds up the send for every peer in the room.
 *
 * "starting" and "degraded" both still open every subsequent cycle and both
 * still admit. Since C5 "degraded" is where a late or failed boundary lands,
 * so rejecting it here would turn one browser stall into a room that can never
 * send again — the same outcome, moved one layer up.
 */
export const coverRuntimeAdmitsScheduledJobs = (
  runtime: { readonly status: CoverSchedulerStatus } | undefined,
): boolean =>
  runtime !== undefined &&
  runtime.status !== "suspended" &&
  runtime.status !== "stopped";

/** The edge's cover runtime is still there and not stopped (torn down). */
const coverRuntimeIsLive = (
  runtime: { readonly status: CoverSchedulerStatus } | undefined,
): boolean => runtime !== undefined && runtime.status !== "stopped";

/**
 * Test/fault-injection seams for `sendScheduled`. Production passes none of
 * them; they exist so the resume loop can be driven without a durable ratchet
 * write, a real gate, or a schedule-derived wall-clock wait. Same shape as
 * `bindTransferCipherToConnection`'s trailing defaults.
 */
export interface ScheduledSendDependencies {
  readonly waitForGate?: WaitForRatchetGate;
  readonly ratchetStep?: DurableRatchetStep;
  readonly waitForDelivery?: (
    options: ScheduledDeliveryWaitOptions,
    peerId: string,
  ) => Promise<boolean>;
  /** How long to watch for a replacement cover runtime before giving up (C8). */
  readonly resumeWaitMs?: number;
  /** The clock of the wait while the receiver verifies the file. */
  readonly clock?: TransferWaitClock;
  /** How that wait hears of receipts; `onTransferActivity` in production. */
  readonly subscribeActivity?: typeof onTransferActivity;
}

/**
 * Scheduled-cover send: instead of opening a per-message DataChannel and
 * bursting, step the ratchet once for the message and enqueue a lazy cover job
 * on each peer edge's cover runtime. The scheduler substitutes one chunk cell
 * per slot into the already-running cover lanes; the tail is dummy. Delivery is
 * confirmed by the receiver's terminal scheduled receipt (markTransferComplete).
 *
 * A send survives its edge being replaced. Every recovery path destroys the
 * cover runtime, which settles and deletes every job it holds and (since C3)
 * wipes the message key at that settlement; the replacement runtime starts
 * empty. So the retired job cannot be carried across — its key is already zero,
 * and even a live one belongs to a ratchet generation the peer has thrown away.
 * The send is instead RE-DERIVED on the replacement generation and re-offered,
 * exactly as `bindTransferCipherToConnection` does for immediate mode (C8).
 */
export const sendScheduled = async (
  roomId: string,
  channelLabel: string,
  policy: RoomPolicyV1,
  targets: readonly PeerSendTarget[],
  message: OutboundMessage,
  encryptionModule: LibCrypto,
  signal?: AbortSignal,
  onTransferStarted?: () => void,
  /**
   * The room's LIVE connection array. A replacement RTCPeerConnection is a
   * different object, so `target.epc` is stale the moment the edge is rebuilt;
   * this is where the resume finds the transport that replaced it, exactly as
   * `resumeChannel` does on the immediate-mode path.
   */
  peerConnections: readonly IRTCPeerConnection[] = [],
  dependencies: ScheduledSendDependencies = {},
  outboxLease?: OutboxLease,
): Promise<PeerSendFanoutResult> => {
  const { totalChunks, merkleRoot, merkleRootHex, transferId } = message;
  const waitForGate = dependencies.waitForGate ?? waitForRatchetGate;
  const ratchetStep = dependencies.ratchetStep ?? ratchetEncryptDurably;
  const waitForDelivery =
    dependencies.waitForDelivery ?? waitForScheduledDelivery;
  const resumeWaitMs = dependencies.resumeWaitMs ?? RECONNECT_RESUME_TIMEOUT_MS;
  let startedTransfers = 0;
  // Derived from the room's authenticated policy, never a fixed constant: a
  // job is admitted only at a cycle open and the receiver's terminal receipt is
  // itself a job admitted at the boundary after that, so the floor scales with
  // the cadence. The 120 s constant this replaces rejected every send in a
  // "5 min cycles" room, whose minimum confirmation is 301.2 s (C3).
  // Used as an IDLE budget, not a total deadline: it is the arithmetic floor
  // of one confirmation and assumes admission at the very next cycle open,
  // which only holds while fewer than `coverLanes` other jobs are ahead. See
  // waitForScheduledDelivery.
  const deliveryIdleTimeoutMs = scheduledDeliveryTimeoutMs({
    coverCadenceMs: policy.coverCadenceMs,
    coverLanes: policy.coverLanes,
    coverFramesPerCell: policy.coverFramesPerCell,
    coverDurationEpochs: policy.coverDurationEpochs,
  });

  // Every peer's send runs concurrently: each edge has its own scheduler, and
  // one peer's waits (up to (1 + MAX_SCHEDULED_SEND_RESUMES) idle budgets and
  // as many resume watches, then its receiver's whole-file verification) must
  // not delay the next peer's enqueue. Outcomes keep the targets' order.
  //
  // With the idle-budget hold below (scheduledCoverIsSuspended) one send has
  // no upper bound at all while the page stays hidden or suspended. That is
  // deliberate: a hidden page, pagehide, freeze and offline are PAGE-wide, so
  // every edge in the room is held together. The wait ends when the page is
  // visible and running again, or when `signal` aborts.
  const sendToTarget = async (
    target: PeerSendTarget,
  ): Promise<PeerDeliveryOutcome> => {
    if (signal?.aborted) {
      return {
        peerId: target.peerId,
        status: "skipped",
        reason: "cancelled",
      };
    }
    const epc = target.epc;
    if (
      !epc ||
      !(await waitForConnectedEdge(epc, PEER_ADMISSION_WAIT_MS, signal))
    ) {
      return {
        peerId: target.peerId,
        status: "skipped",
        reason: "not-connected",
      };
    }
    // The transport is connected, so this is not a dead peer -- it is this
    // edge's own scheduled-cover pipeline (missing, suspended by a pagehide,
    // a freeze or going offline, or stopped) refusing to admit a job. Report that
    // distinctly: it is a local condition the caller can expect to clear on
    // its own, not a reason to give up on the peer.
    if (!coverRuntimeAdmitsScheduledJobs(epc.coverRuntime)) {
      return {
        peerId: target.peerId,
        status: "skipped",
        reason: "cover-unavailable",
      };
    }
    let currentEpc = epc;
    let channelMessageLabel = "";
    let admitted = false;
    // The runtime holding this target's latest job; settled on delivery.
    let jobRuntime: IRTCPeerConnection["coverRuntime"];
    try {
      channelMessageLabel = await compileChannelMessageLabel(
        channelLabel,
        merkleRootHex,
      );
      let delivered = false;
      let resumes = 0;
      for (;;) {
        // Read BEFORE the enqueue, and deliberately three awaits before it is
        // compared. The two directions are NOT symmetric:
        //
        //  - read early, and a replacement installed during the gate wait, the
        //    PQ admission wait or the durable ratchet step reads as an advance
        //    that this attempt may not have needed. The cost is one extra trip
        //    round the resume check, which the `nextEpc.coverRuntime === runtime`
        //    guard below turns into a `break` without re-sending anything.
        //  - read late (next to the enqueue), and exactly that replacement is
        //    swallowed: the generation would already include it, the comparison
        //    would say "nothing replaced anything", and a send whose job is
        //    sitting on a superseded runtime would be abandoned with a CANCEL
        //    instead of re-derived onto the live edge.
        //
        // One direction costs a guarded no-op and the other loses the send, so
        // the read stays here. `installCoverEdge` publishes its bump
        // synchronously after installing, so nothing can slip between them.
        const generation = coverEdgeGeneration(roomId, target.peerId);

        await waitForGate(roomId, target.peerId, signal);
        if (!currentEpc.ratchetState)
          throw new Error("v4 scheduled send: no ratchet state");
        let releasePq: (() => void) | null = null;
        while (!releasePq) {
          await waitForPqTrafficAdmission(currentEpc, signal);
          throwIfTransferAborted(signal);
          releasePq = tryReservePqApplicationTraffic(currentEpc);
        }
        let stepped: Awaited<ReturnType<DurableRatchetStep>>;
        try {
          stepped = await ratchetStep(currentEpc, roomId, encryptionModule);
        } catch (error) {
          releasePq();
          throw error;
        }
        const pqEpoch = currentEpc.pqHealingState?.epoch;
        // v4: derive the combined key once for the message; every cell the
        // scheduler asks for is sealed under it.
        let chunkSealer: MessageChunkSealer;
        try {
          chunkSealer = createMessageChunkSealer(
            stepped.messageKey,
            stepped.header,
            stepped.pqContext,
            encryptionModule,
          );
        } catch (error) {
          stepped.messageKey.fill(0);
          stepped.pqContext?.rootKey.fill(0);
          releasePq();
          throw error;
        }
        let wiped = false;
        const sealer = makeScheduledSlotSealer(
          message,
          chunkSealer,
          () => wiped,
          outboxLease,
          signal,
        );
        // The sealer closure above holds the message's combined key, and
        // `stepped` its message key and PQ context root, for exactly as long
        // as the scheduler can still ask this job for a cell. Wiping them on
        // the delivery timeout — what this did before C3 — did not stop the
        // still-admitted job: it kept emitting cells sealed under an all-zero
        // key, which the receiver can never open and a re-send can never
        // replace (a wiped sealer now throws instead). The wipe belongs to job
        // settlement, the one moment after which nextCell is never called
        // again. That is also why a resume cannot carry this sealer across the
        // edge: the teardown that causes the resume settles the job, so by then
        // this key is already zero. Each attempt owns its own generation's
        // secrets and its own wipe.
        const wipeMessageSecrets = (): void => {
          if (wiped) return;
          wiped = true;
          chunkSealer.wipe();
          stepped.messageKey.fill(0);
          stepped.pqContext?.rootKey.fill(0);
        };
        const runtime = currentEpc.coverRuntime;
        jobRuntime = runtime;
        try {
          throwIfTransferAborted(signal);
          const enqueued = enqueueScheduledSend({
            epc: currentEpc,
            channelMessageLabel,
            totalChunks,
            merkleRoot,
            sealSlotCell: sealer,
            isChunkAcked: (index) =>
              index !== 0 &&
              hasChunkAcked(roomId, target.peerId, transferId, index),
          });
          if (!enqueued)
            throw new Error("v4 scheduled send: edge has no cover runtime");
          // Registered synchronously with the enqueue, so the job cannot settle
          // in between and leave the message key alive for the page's lifetime.
          runtime?.onJobSettled(channelMessageLabel, wipeMessageSecrets);
        } catch (enqueueError) {
          // Nothing ever holds the sealer, so its secrets die here.
          wipeMessageSecrets();
          throw enqueueError;
        } finally {
          releasePq();
        }
        admitted = true;
        // Re-registered on EVERY attempt, not just the first: the root →
        // transferId map that turns the receiver's terminal receipt into
        // markTransferComplete hangs off the RTCPeerConnection, and a
        // replacement connection has none. Without this a resumed send that
        // arrives perfectly is still reported as a failure.
        trackScheduledSend(
          currentEpc,
          roomId,
          target.peerId,
          merkleRootHex,
          transferId,
        );
        if (resumes === 0) {
          startedTransfers += 1;
          onTransferStarted?.();
        }
        // Delivery confirmation: over reliable ordered lanes the receiver
        // signals completion with a terminal scheduled receipt. Bound the wait
        // by this send's own PROGRESS, not by elapsed time — a job admitted
        // only at a cycle open, behind every other job in the room, is not a
        // failed job, and cancelling it now deletes a partial that is still
        // filling.
        delivered = await waitForDelivery(
          {
            isComplete: () =>
              isTransferComplete(roomId, target.peerId, transferId),
            isInvalidated: () =>
              isTransferCancelled(roomId, target.peerId, transferId) ||
              coverEdgeGeneration(roomId, target.peerId) > generation,
            progress: () =>
              scheduledSendProgress(
                currentEpc.coverRuntime,
                channelMessageLabel,
              ),
            // A pagehide, a freeze or an offline event suspends this edge's
            // scheduler; on a hidden page the schedule stays armed, but
            // throttled timers degrade its cycles. Either way the scheduler
            // KEEPS the job and the signal above freezes while the send is
            // healthy: charging the idle budget through that gap cancels it, and
            // the CANCEL deletes the partial the peer is still holding. The
            // predicate holds the budget in both cases; neither is a stall.
            isSuspended: () =>
              scheduledCoverIsSuspended(currentEpc.coverRuntime),
            idleTimeoutMs: deliveryIdleTimeoutMs,
            signal,
          },
          target.peerId,
        );
        // Every chunk acknowledged, no final receipt yet: the receiver is
        // verifying the whole file, and re-sends a receipt while it does. Wait
        // for as long as one keeps arriving (no less than the schedule's own
        // idle budget between them), capped by the file's size. For an edge
        // that is already gone it returns at once, before it subscribes or
        // arms anything, and it ends the moment the edge goes: the
        // replacement is where the transfer resumes, at once.
        // Retired (torn down) or replaced (the peer's current authenticated
        // transport carries another runtime, even before the old edge is torn
        // down). A key-epoch change on the same runtime is neither: the
        // receiver is still verifying the same file for the same edge.
        const edgeIsGone = (): boolean => {
          if (
            currentEpc.coverRuntime !== runtime ||
            !coverRuntimeIsLive(runtime)
          )
            return true;
          const current = peerConnections.find((candidate) =>
            isResumableAuthenticatedTransport(candidate, roomId, target.peerId),
          );
          return current !== undefined && current.coverRuntime !== runtime;
        };
        if (
          !delivered &&
          !signal?.aborted &&
          !isTransferCancelled(roomId, target.peerId, transferId) &&
          message.allRealsAcknowledged((index) =>
            hasChunkAcked(roomId, target.peerId, transferId, index),
          )
        )
          delivered = await waitForScheduledVerifiedDelivery(
            roomId,
            target.peerId,
            transferId,
            message.totalSize,
            Math.max(RECEIVER_SILENCE_LIMIT_MS, deliveryIdleTimeoutMs),
            {
              // Woken by every generation published for the edge (a
              // replacement install, or a rekey) and by its teardown; it ends
              // only if edgeIsGone holds.
              onInterrupt: (wake) => {
                const watching = new AbortController();
                const watch = (since: number): void => {
                  void waitForCoverEdgeGeneration(
                    roomId,
                    target.peerId,
                    since,
                    MAX_TIMER_DELAY_MS,
                    watching.signal,
                  ).then((next) => {
                    if (watching.signal.aborted) return;
                    if (next > since) wake();
                    watch(next);
                  });
                };
                watch(coverEdgeGeneration(roomId, target.peerId));
                const unsubscribeRetired = onCoverEdgeRetired(
                  roomId,
                  target.peerId,
                  wake,
                );
                return () => {
                  watching.abort();
                  unsubscribeRetired();
                };
              },
              isInterrupted: edgeIsGone,
              // Held only while the scheduler still holds the job, exactly as
              // the delivery idle budget is.
              isHeld: () =>
                scheduledCoverIsSuspended(currentEpc.coverRuntime) &&
                scheduledSendProgress(
                  currentEpc.coverRuntime,
                  channelMessageLabel,
                ) !== undefined,
              signal,
              clock: dependencies.clock,
              subscribeActivity: dependencies.subscribeActivity,
            },
          );
        if (
          delivered ||
          signal?.aborted ||
          isTransferCancelled(roomId, target.peerId, transferId)
        )
          break;
        if (resumes >= MAX_SCHEDULED_SEND_RESUMES) break;

        // The budget expired with nothing confirmed. That is a resumable event
        // only if this edge's cover runtime was REPLACED under the job — the
        // one condition in which a fresh generation exists to re-derive onto.
        // Nothing else qualifies: a suspended runtime still holds the job, and
        // a torn-down edge with no replacement has nothing to re-offer on.
        const nextGeneration = await waitForCoverEdgeGeneration(
          roomId,
          target.peerId,
          generation,
          resumeWaitMs,
          signal,
        );
        // That await is up to RECONNECT_RESUME_TIMEOUT_MS long, and a terminal
        // scheduled receipt can land at any instant inside it. Re-read
        // completion HERE, above every exit below: leaving without it reports a
        // delivered message as `failed` and, worse, sends the receiver a CANCEL
        // for a file it has already finished assembling. Nothing between this
        // point and the end of the iteration suspends, so one re-read covers
        // all of them.
        if (isTransferComplete(roomId, target.peerId, transferId)) {
          delivered = true;
          break;
        }
        // An evicted idle entry can read as zero. Only a strictly newer
        // publication authorizes a resume, never an unknown or older value.
        if (nextGeneration <= generation) break;
        const nextEpc = peerConnections.find((candidate) =>
          isResumableAuthenticatedTransport(candidate, roomId, target.peerId),
        );
        if (
          !nextEpc ||
          (nextEpc.coverRuntime === runtime &&
            !(
              pqEpoch !== undefined &&
              nextEpc.pqHealingState &&
              nextEpc.pqHealingState.epoch > pqEpoch
            )) ||
          !coverRuntimeAdmitsScheduledJobs(nextEpc.coverRuntime)
        )
          break;
        // Settle the retired job so nothing can ask it for another cell, and so
        // its message key is wiped even on the paths that replace an edge
        // without destroying the previous runtime. `complete` adds no frame and
        // emits no wire CANCEL — a CANCEL here would delete the very partial
        // this resume exists to finish filling.
        try {
          runtime?.complete(channelMessageLabel);
        } catch (settleError) {
          // Already destroyed by the teardown that caused this resume.
          debugLog(settleError);
        }
        currentEpc = nextEpc;
        resumes += 1;
      }
      if (delivered) {
        // Confirmed. The job may still hold cells it never needs to send:
        // settle it now (`complete` emits no frame), so it stops asking for
        // them and its message key and PQ root are wiped at delivery, not at
        // the cycle boundary that would otherwise retire it as
        // capacity-exhausted.
        try {
          jobRuntime?.complete(channelMessageLabel);
        } catch (settleError) {
          // Already destroyed: its teardown settled the job.
          debugLog(settleError);
        }
      } else if (!isTransferCancelled(roomId, target.peerId, transferId)) {
        // Tell the receiver, before anything else destroys what could still
        // fill its partial. Without this the sender reported failure while the
        // receiver kept an unfillable N/M transfer forever — a re-send cannot
        // fill it, because decoy chunks are fresh randomness and the Merkle
        // root differs (C3).
        if (
          outboxLease &&
          (!signal?.aborted ||
            signal.reason instanceof OutboxOwnershipLostError)
        )
          currentEpc.coverRuntime?.complete(channelMessageLabel);
        else cancelScheduledSend(currentEpc, channelMessageLabel);
      }
      return delivered
        ? { peerId: target.peerId, status: "delivered" }
        : {
            peerId: target.peerId,
            status: "failed",
            phase: "transfer",
            reason: new Error(
              isTransferCancelled(roomId, target.peerId, transferId)
                ? "Message transfer cancelled by peer"
                : "scheduled delivery not confirmed",
            ),
          };
    } catch (reason) {
      // A throw after the job was admitted (a resume whose durable ratchet
      // advance fails, say) leaves the receiver holding a partial that only our
      // CANCEL can clear — the same C3 obligation the timeout path has.
      if (admitted && !isTransferCancelled(roomId, target.peerId, transferId)) {
        try {
          if (
            outboxLease &&
            (!signal?.aborted ||
              signal.reason instanceof OutboxOwnershipLostError)
          )
            currentEpc.coverRuntime?.complete(channelMessageLabel);
          else cancelScheduledSend(currentEpc, channelMessageLabel);
        } catch (cancelError) {
          console.error(cancelError);
        }
      }
      return {
        peerId: target.peerId,
        status: "failed",
        phase: "transfer",
        reason,
      };
    } finally {
      if (
        outboxLease &&
        signal?.aborted &&
        !(signal.reason instanceof OutboxOwnershipLostError)
      )
        queueScheduledCancel(currentEpc, channelMessageLabel);
      untrackScheduledSend(currentEpc, merkleRootHex, transferId);
    }
  };
  // Every peer's send is observed whatever it throws, and each outcome keeps
  // its target's place.
  const outcomes = (await Promise.allSettled(targets.map(sendToTarget))).map(
    (settled, index): PeerDeliveryOutcome =>
      settled.status === "fulfilled"
        ? settled.value
        : {
            peerId: targets[index].peerId,
            status: "failed",
            phase: "transfer",
            reason: settled.reason,
          },
  );
  return { outcomes, startedTransfers };
};

export const handleSendMessage = async (
  data: string | File | undefined,
  api: BaseQueryApi,
  label: string,
  roomId: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  transferId: string,
  minChunks = 1,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
): Promise<SendMessageResult | undefined> => {
  const transfer = claimTransfer(roomId, transferId);
  let session: OutboxSession | undefined;
  let prepared = false;
  let failure: unknown;
  try {
    const state = api.getState() as State;
    const room = state.rooms.find((r) => r.id === roomId);
    if (!room || room.signalingActive === false)
      throw new Error("No active room with id " + roomId);
    const senderPublicKey = state.keyPair.publicKey;
    const policyHex = uint8ArrayToHex(encodeRoomPolicyV1(room.policy));
    let manifest: OutboxManifest;
    let chunkHashes: Uint8Array;
    const ackedByPublicKey = new Map<string, number[]>();
    const owner = createTransferId();
    if (data === undefined) {
      const claimed = await outboxRequest({
        kind: "claim",
        transferId,
        owner,
        senderPublicKey,
        roomId,
        roomUrl: room.url,
        policyHex,
      });
      if (
        !claimed.accepted ||
        !claimed.manifest ||
        !claimed.lease ||
        !claimed.chunkHashes
      )
        return;
      manifest = claimed.manifest;
      prepared = true;
      chunkHashes = new Uint8Array(claimed.chunkHashes);
      for (const ack of claimed.acknowledgments ?? []) {
        const indexes: number[] = [];
        for (let i = 0; i < manifest.totalChunks; i++)
          if (ack.bitmap[i >>> 3] & (1 << (i & 7))) indexes.push(i);
        ackedByPublicKey.set(ack.publicKey, indexes);
      }
      session = startOutboxSession(
        claimed.lease,
        roomId,
        manifest.leaseUntil,
        transfer.signal,
        stillAuthorized,
      );
    } else {
      const channel = room.channels.find((c) => c.label === label);
      if (!channel) throw new Error("No channel with label " + label);
      const membership = [...room.peers, ...(room.knownPeers ?? [])];
      const recipients = channel.peerIds
        .map((peerId) => {
          const publicKey =
            membership.find((p) => p.peerId === peerId)?.peerPublicKey ??
            peerConnections.find(
              (p) => p.roomId === roomId && p.withPeerId === peerId,
            )?.withPeerPublicKey;
          if (!publicKey)
            throw new Error("Outbound recipient identity is unknown");
          return { peerId, publicKey };
        })
        .filter(
          (peer, index, peers) =>
            peers.findIndex((p) => p.publicKey === peer.publicKey) === index,
        );
      const totalSize =
        typeof data === "string"
          ? new TextEncoder().encode(data).length
          : data.size;
      const totalChunks = planMessageChunkCount(
        totalSize,
        minChunks,
        chunkSize,
        percentageFilledChunk,
      );
      const created = await outboxRequest({
        kind: "create",
        input: {
          transferId,
          owner,
          senderPublicKey,
          roomId,
          roomUrl: room.url,
          policyHex,
          channelLabel: label,
          filename:
            typeof data === "string" ? "message" : data.name.slice(0, 255),
          totalSize,
          totalChunks,
          stagedBytes: estimateOutboundStagingBytes(
            totalSize,
            totalChunks,
            chunkSize,
          ),
          recipients,
        },
      });
      if (!created.manifest || !created.lease)
        throw new Error("Unable to reserve durable sender staging");
      manifest = created.manifest;
      session = startOutboxSession(
        created.lease,
        roomId,
        manifest.leaseUntil,
        transfer.signal,
        stillAuthorized,
      );
      const split = await splitToChunks(
        data,
        api,
        label,
        room,
        merkleModule,
        { ...transfer, signal: session.signal, outboxLease: session.lease },
        minChunks,
        chunkSize,
        percentageFilledChunk,
        metadataSchemaVersion,
      );
      throwIfTransferAborted(session.signal);
      const published = await outboxRequest({
        kind: "publish",
        lease: session.lease,
        merkleRootHex: split.merkleRootHex,
        hashHex: split.hashHex,
        chunkHashes: split.chunkHashes.buffer as ArrayBuffer,
      });
      if (!published.manifest)
        throw new Error("Unable to publish complete outbound staging");
      manifest = published.manifest;
      chunkHashes = split.chunkHashes;
      prepared = true;
    }
    function stillAuthorized(): boolean {
      const latest = api.getState() as State;
      const currentRoom = latest.rooms.find((r) => r.id === roomId);
      return (
        latest.keyPair.publicKey === senderPublicKey &&
        !!currentRoom &&
        currentRoom.signalingActive !== false &&
        currentRoom.url === room!.url &&
        uint8ArrayToHex(encodeRoomPolicyV1(currentRoom.policy)) === policyHex
      );
    }
    if (manifest.channelLabel !== label)
      throw new Error("Pending message channel binding changed");
    const signal = session.signal;
    throwIfTransferAborted(signal);
    const { merkleRootHex, hashHex, totalChunks } = manifest;
    const merkleRoot = hexToUint8Array(merkleRootHex);
    transfer.bindMerkleRoot(merkleRootHex);
    transfer.bindHash(hashHex);
    const targets: PeerSendTarget[] = manifest.recipients
      .filter((r) => !r.delivered && !r.cancelled)
      .map((recipient) => {
        const epc = peerConnections.find(
          (p) =>
            p.roomId === roomId &&
            p.withPeerPublicKey === recipient.publicKey &&
            p.connectionState !== "closed" &&
            p.connectionState !== "failed",
        );
        return { peerId: epc?.withPeerId ?? recipient.peerId, epc };
      });
    for (const target of targets) {
      clearTransfer(roomId, target.peerId, transferId);
      for (const index of room.policy.coverMode === "scheduled"
        ? (ackedByPublicKey.get(target.epc?.withPeerPublicKey ?? "") ?? [])
        : [])
        markChunkAcked(roomId, target.peerId, transferId, index);
    }
    const channelMessageLabel = await compileChannelMessageLabel(
      label,
      merkleRootHex,
    );
    // One OutboundMessage for every peer of this message: its Merkle proof
    // levels are built once and closed when this delivery settles.
    const fanout = await withOutboundMessage(
      {
        transferId,
        hashHex,
        merkleRoot,
        totalChunks,
        chunkHashes,
        merkleModule,
      },
      (message) =>
        room.policy.coverMode === "scheduled"
          ? sendScheduled(
              roomId,
              label,
              room.policy,
              targets,
              message,
              encryptionModule,
              signal,
              undefined,
              peerConnections,
              {},
              session!.lease,
            )
          : runPeerSendFanout(
              targets,
              ({ epc }) =>
                handleOpenChannel(
                  { channel: channelMessageLabel, epc, roomId, dataChannels },
                  api,
                ),
              async ({ peerId, epc }, channel) => {
                await sendWithReconcile(
                  channel,
                  api,
                  roomId,
                  epc,
                  message,
                  peerId,
                  encryptionModule,
                  peerConnections,
                  dataChannels,
                  signal,
                  session!.lease,
                );
                await persistOutboundReceipt({
                  roomId,
                  peerId,
                  peerPublicKey: epc.withPeerPublicKey,
                  transferId,
                  merkleRootHex,
                });
              },
              signal,
            ),
    );
    for (const outcome of fanout.outcomes) {
      if (outcome.status !== "delivered") continue;
      const recipient = targets.find(
        (target) => target.peerId === outcome.peerId,
      );
      if (recipient?.epc)
        await persistOutboundReceipt({
          roomId,
          peerId: outcome.peerId,
          peerPublicKey: recipient.epc.withPeerPublicKey,
          transferId,
          merkleRootHex,
        });
    }
    const result: SendMessageResult = { transferId, merkleRootHex, ...fanout };
    throwIfTransferAborted(signal);
    if (
      targets.length > 0 &&
      !result.outcomes.some((outcome) => outcome.status === "delivered")
    )
      throw new MessageDeliveryError(
        result,
        "Message is pending; no recipient confirmed delivery in this attempt",
      );
    return result;
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    session?.finish();
    if (session) {
      try {
        if (!prepared || transfer.signal.aborted)
          await outboxRequest({
            kind: "remove",
            transferId,
            lease: session.lease,
          });
        else
          await outboxRequest({
            kind: "release",
            lease: session.lease,
            lastError:
              failure instanceof Error
                ? failure.message
                : failure
                  ? String(failure)
                  : undefined,
          });
      } catch (error) {
        debugLog(error);
      }
    }
    transfer.finish();
  }
};
