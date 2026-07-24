import {
  handleReceiveMessage,
  type ReceiveMessageResult,
} from "./handleReceiveMessage";
import {
  getRatchetGate,
  isCurrentRatchetGateLease,
} from "./ratchetGate";
import { sendReceiptFrame } from "./receiptFrame";
import { queueScheduledReceipt } from "./coverTransfer";

import { closeReceiveFile } from "../db/api";

import { uint8ArrayToHex } from "../utils/uint8array";

import {
  setMessage,
  setMessageAllChunks,
  incrementMessageStats,
} from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";

const k32 = (u8: Uint8Array) => {
  if (u8.byteLength < 32) {
    return `${String(u8.byteLength)}:${uint8ArrayToHex(u8)}`;
  }

  const head = new DataView(u8.buffer, u8.byteOffset, 16);
  const tail = new DataView(u8.buffer, u8.byteOffset + u8.byteLength - 16, 16);

  const h1 = head.getBigUint64(0, false).toString(16).padStart(16, "0");
  const h2 = head.getBigUint64(8, false).toString(16).padStart(16, "0");
  const t1 = tail.getBigUint64(0, false).toString(16).padStart(16, "0");
  const t2 = tail.getBigUint64(8, false).toString(16).padStart(16, "0");

  return h1 + h2 + t1 + t2;
};

const processingLocks = new Map<string, Promise<void>>();
const queuedBytesByEdge = new Map<string, number>();

/**
 * True while this room/peer edge still has queued inbound chunk frames or an
 * in-flight frame handler. The sparse-PQ orchestrator drains to quiescence
 * before an epoch transition so old-epoch first-chunks are not orphaned.
 */
export const hasQueuedEdgeReceiveWork = (
  roomId: string,
  peerId: string,
): boolean => {
  const key = edgeQueueKey(roomId, peerId);
  return (
    (queuedBytesByEdge.get(key) ?? 0) > 0 || processingLocks.has(key)
  );
};

export const waitForEdgeReceiveQuiescence = async (
  roomId: string,
  peerId: string,
): Promise<void> => {
  const key = edgeQueueKey(roomId, peerId);
  for (;;) {
    const inFlight = processingLocks.get(key);
    if (!inFlight && (queuedBytesByEdge.get(key) ?? 0) === 0) return;
    if (inFlight) await inFlight.catch(() => undefined);
    else await new Promise((resolve) => setTimeout(resolve, 10));
  }
};
const queuedBytesByChannel = new WeakMap<Uint8Array[], number>();
const queuedReceiptsByEdge = new Map<string, number>();

export const MAX_QUEUED_FRAMES_PER_CHANNEL = 64;
export const MAX_QUEUED_BYTES_PER_EDGE = 16 * 1024 * 1024;
export const MAX_QUEUED_RECEIPTS_PER_CHANNEL = 2_048;
export const MAX_QUEUED_RECEIPTS_PER_EDGE = 8_192;

const edgeQueueKey = (roomId: string, peerId: string): string =>
  `${String(roomId.length)}:${roomId}${peerId}`;

export interface MessageProcessingState {
  value: boolean;
  released?: boolean;
  idleWaiters?: Set<() => void>;
}

const settleMessageQueueIdle = (
  queue: Uint8Array[],
  state: MessageProcessingState,
): void => {
  if (state.value || queue.length > 0) return;
  const waiters = state.idleWaiters;
  state.idleWaiters = undefined;
  if (waiters) for (const resolve of waiters) resolve();
};

export const waitForQueuedMessageFrames = (
  queue: Uint8Array[],
  state: MessageProcessingState,
): Promise<void> => {
  if (!state.value && queue.length === 0) return Promise.resolve();
  return new Promise<void>((resolve) => {
    state.idleWaiters ??= new Set();
    state.idleWaiters.add(resolve);
  });
};

const adjustQueuedBytes = (
  queue: Uint8Array[],
  roomId: string,
  peerId: string,
  delta: number,
): void => {
  const nextChannel = Math.max(0, (queuedBytesByChannel.get(queue) ?? 0) + delta);
  if (nextChannel === 0) queuedBytesByChannel.delete(queue);
  else queuedBytesByChannel.set(queue, nextChannel);

  const key = edgeQueueKey(roomId, peerId);
  const nextEdge = Math.max(0, (queuedBytesByEdge.get(key) ?? 0) + delta);
  if (nextEdge === 0) queuedBytesByEdge.delete(key);
  else queuedBytesByEdge.set(key, nextEdge);
};

export const releaseQueuedMessageFrames = (
  queue: Uint8Array[],
  roomId: string,
  peerId: string,
  state?: MessageProcessingState,
): void => {
  if (state) state.released = true;
  const bytes = queue.reduce((total, frame) => total + frame.byteLength, 0);
  queue.length = 0;
  if (bytes > 0) adjustQueuedBytes(queue, roomId, peerId, -bytes);
  if (state) settleMessageQueueIdle(queue, state);
};

const withProcessingLock = async <T>(
  key: string,
  fn: () => Promise<T>,
): Promise<T> => {
  const prev = processingLocks.get(key) ?? Promise.resolve();

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  const tail = prev.then(() => gate);
  processingLocks.set(key, tail);

  await prev;

  try {
    return await fn();
  } finally {
    release();

    if (processingLocks.get(key) === tail) {
      processingLocks.delete(key);
    }
  }
};

export interface ReceiptProcessingQueue {
  readonly roomId: string;
  readonly peerId: string;
  readonly pending: Uint8Array[];
  readonly seen: Set<string>;
  draining: boolean;
  released: boolean;
}

export const createReceiptProcessingQueue = (
  roomId: string,
  peerId: string,
): ReceiptProcessingQueue => ({
  roomId,
  peerId,
  pending: [],
  seen: new Set<string>(),
  draining: false,
  released: false,
});

const adjustQueuedReceipts = (
  state: ReceiptProcessingQueue,
  delta: number,
): void => {
  const key = edgeQueueKey(state.roomId, state.peerId);
  const next = Math.max(0, (queuedReceiptsByEdge.get(key) ?? 0) + delta);
  if (next === 0) queuedReceiptsByEdge.delete(key);
  else queuedReceiptsByEdge.set(key, next);
};

export const releaseQueuedReceipts = (
  state: ReceiptProcessingQueue,
): void => {
  if (state.released) return;
  state.released = true;
  const count = state.pending.length;
  state.pending.length = 0;
  state.seen.clear();
  if (count > 0) adjustQueuedReceipts(state, -count);
};

const drainReceipts = async (
  state: ReceiptProcessingQueue,
  processReceipt: (receipt: Uint8Array) => Promise<void>,
): Promise<void> => {
  if (state.draining || state.released) return;
  state.draining = true;
  const lockKey = edgeQueueKey(state.roomId, state.peerId);
  try {
    for (;;) {
      if (state.released) break;
      const receipt = state.pending.shift();
      if (!receipt) break;
      adjustQueuedReceipts(state, -1);
      try {
        await withProcessingLock(lockKey, () => processReceipt(receipt));
      } finally {
        // Deduplicate only while queued/in flight. A later retransmit must be
        // allowed to retry after a transient worker/storage failure.
        state.seen.delete(k32(receipt));
      }
    }
  } catch (error) {
    // One malformed/unresolvable authenticated receipt must not strand every
    // later acknowledgement behind a permanently rejected drain promise.
    console.error(error);
  } finally {
    state.draining = false;
    if (!state.released && state.pending.length > 0)
      void drainReceipts(state, processReceipt);
  }
};

/**
 * Queue one already-classified 64-byte receipt token. This is deliberately a
 * bounded data queue, not one promise per onmessage event. At most one handler
 * executes per room/peer edge, even when many message channels are open.
 */
export const enqueueReceipt = (
  receipt: Uint8Array,
  state: ReceiptProcessingQueue,
  processReceipt: (receipt: Uint8Array) => Promise<void>,
): boolean => {
  if (state.released) return false;

  const fingerprint = k32(receipt);
  if (state.seen.has(fingerprint)) return true;

  const edgeCount =
    queuedReceiptsByEdge.get(edgeQueueKey(state.roomId, state.peerId)) ?? 0;
  if (
    state.pending.length >= MAX_QUEUED_RECEIPTS_PER_CHANNEL ||
    edgeCount >= MAX_QUEUED_RECEIPTS_PER_EDGE
  )
    return false;

  state.seen.add(fingerprint);
  // Keep flood-dedup memory finite. Receipt semantics remain independently
  // idempotent in reconcile.ts when an old token is observed again.
  if (state.seen.size > MAX_QUEUED_RECEIPTS_PER_CHANNEL * 2)
    state.seen.clear();

  state.pending.push(receipt);
  adjustQueuedReceipts(state, 1);
  if (!state.draining) void drainReceipts(state, processReceipt);
  return true;
};

type PerFrameReceiptResult = Pick<
  ReceiveMessageResult,
  "chunkHash" | "chunkIndex" | "chunkSize" | "totalSize"
>;

/**
 * Emit exactly one receipt-shaped frame for every inbound chunk frame. Real
 * cells use their rooted token; cover/dropped cells use an unlinkable random
 * token so an observer cannot infer which slot carried bytes.
 */
export const sendReceiveFrameReceipt = (
  result: PerFrameReceiptResult,
  channel: IRTCDataChannel | undefined,
): boolean => {
  if (
    result.totalSize > 0 &&
    result.chunkHash.length === crypto_hash_sha512_BYTES &&
    result.chunkIndex > -1 &&
    result.chunkSize > 0
  )
    return channel ? sendReceiptFrame(channel, result.chunkHash) : false;

  if (channel?.readyState !== "open") return false;
  const decoyReceipt = new Uint8Array(crypto_hash_sha512_BYTES);
  crypto.getRandomValues(decoyReceipt);
  return sendReceiptFrame(channel, decoyReceipt);
};

const processMessage = async (
  data: Uint8Array,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  merkleRoot: Uint8Array,
  extChannel: IRTCDataChannel | undefined,
  epc: IRTCPeerConnection | undefined,
  receiveMessageModule: LibCrypto,
  signal?: AbortSignal,
): Promise<{ receivedFullSize: boolean }> => {
  if (signal?.aborted) return { receivedFullSize: false };
  if (epc) {
    try {
      const transportGateLease = epc.ratchetGateLease;
      if (
        !isCurrentRatchetGateLease(roomId, peerId, transportGateLease)
      )
        return { receivedFullSize: false };
      // Do not decrypt until the PACE + Double-Ratchet handshake has seeded the
      // per-peer ratchet (the `main` channel opens this gate). A chunk that
      // races ahead of the handshake waits here rather than being dropped; a
      // failed handshake rejects the gate, caught below.
      await getRatchetGate(roomId, peerId);
      if (signal?.aborted) return { receivedFullSize: false };
      if (
        !isCurrentRatchetGateLease(roomId, peerId, transportGateLease)
      )
        return { receivedFullSize: false };

      const receiveResult = await handleReceiveMessage(
        data,
        roomId,
        channelLabel,
        epc,
        merkleRoot,
        receiveMessageModule,
        signal,
      );
      const {
        date,
        chunkSize,
        chunkIndex,
        receivedFullSize,
        chunkAlreadyExists,
        totalSize,
        messageType,
        filename,
        messageHash,
      } = receiveResult;

      if (signal?.aborted) return { receivedFullSize: false };

      // Immediate mode acks each frame with a 65-byte receipt on its channel.
      // Scheduled mode never uses immediate receipts: acknowledgement rides a
      // cover slot instead (a terminal receipt on completion, below).
      if (!epc?.coverRuntime) sendReceiveFrameReceipt(receiveResult, extChannel);

      const hashHex = uint8ArrayToHex(messageHash);

      if (receivedFullSize) {
        // Scheduled mode: confirm the whole message with ONE terminal receipt
        // cover cell (token == transfer root) so the sender's send resolves.
        // It substitutes into a reverse cover slot, never an immediate frame.
        if (epc?.coverRuntime)
          queueScheduledReceipt(epc, merkleRoot, merkleRoot);
      }

      if (receivedFullSize) {
        // Flush + close the OPFS write handle before flipping the UI to 100% so
        // readMessage can open the finished file without hitting the write lock.
        // No-op for text (no handle) and for a re-observed completion.
        await closeReceiveFile(merkleRootHex);

        api.dispatch(
          setMessageAllChunks({
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: peerId,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: date.getTime(),
            alsoSendFinishedMessage: true,
          }),
        );

        if (extChannel) sendReceiptFrame(extChannel, messageHash);
      } else if (chunkSize > 0 && chunkIndex > -1 && !chunkAlreadyExists) {
        api.dispatch(
          setMessage({
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: peerId,
            chunkSize,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: date.getTime(),
          }),
        );
      }

      // Telemetry: count every frame received (incl. decoys), flag the reals —
      // lets the UI show total ≫ real (the obfuscation working). Dispatched
      // AFTER the message is created above so the increment lands. Progress %
      // stays over the real message (savedSize / totalSize), unchanged.
      api.dispatch(
        incrementMessageStats({
          roomId,
          merkleRootHex,
          real: chunkSize > 0 && chunkIndex > -1 && !chunkAlreadyExists,
        }),
      );

      return { receivedFullSize };
    } catch (error) {
      console.error(error);

      return { receivedFullSize: false };
    }
  }

  return { receivedFullSize: false };
};

const drain = async (
  queue: Uint8Array[],
  seen: Set<string>,
  drainingRef: MessageProcessingState,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  merkleRoot: Uint8Array,
  extChannel: IRTCDataChannel | undefined,
  epc: IRTCPeerConnection | undefined,
  receiveMessageModule: LibCrypto,
  signal?: AbortSignal,
) => {
  if (drainingRef.value || drainingRef.released || signal?.aborted) return;
  drainingRef.value = true;
  const lockKey = edgeQueueKey(roomId, peerId);
  try {
    for (;;) {
      if (drainingRef.released || signal?.aborted) break;
      const chunk = queue.pop();
      if (!chunk) break;
      adjustQueuedBytes(queue, roomId, peerId, -chunk.byteLength);

      // const { receivedFullSize } =
      await withProcessingLock(lockKey, async () =>
        processMessage(
          chunk,
          api,
          roomId,
          peerId,
          channelLabel,
          merkleRootHex,
          merkleRoot,
          extChannel,
          epc,
          receiveMessageModule,
          signal,
        ),
      );

      // if (receivedFullSize) {
      //   queue = [];
      //   seen = new Set<string>();
      //
      //   break;
      // }
    }
  } finally {
    drainingRef.value = false;
    if (
      queue.length > 0 &&
      !drainingRef.released &&
      !signal?.aborted
    )
      void drain(
        queue,
        seen,
        drainingRef,
        api,
        roomId,
        peerId,
        channelLabel,
        merkleRootHex,
        merkleRoot,
        extChannel,
        epc,
        receiveMessageModule,
        signal,
      );
    else settleMessageQueueIdle(queue, drainingRef);
  }
};

export const enqueue = (
  data: Uint8Array,
  queue: Uint8Array[],
  seen: Set<string>,
  drainingRef: MessageProcessingState,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  merkleRoot: Uint8Array,
  extChannel: IRTCDataChannel | undefined,
  epc: IRTCPeerConnection | undefined,
  receiveMessageModule: LibCrypto,
  signal?: AbortSignal,
): boolean => {
  if (drainingRef.released || signal?.aborted) return false;
  const k = k32(data);
  if (seen.has(k)) return true; // drop duplicate-in-queue

  const edgeBytes = queuedBytesByEdge.get(edgeQueueKey(roomId, peerId)) ?? 0;
  if (
    queue.length >= MAX_QUEUED_FRAMES_PER_CHANNEL ||
    edgeBytes + data.byteLength > MAX_QUEUED_BYTES_PER_EDGE
  )
    return false;

  seen.add(k);

  // Dedup state is disposable. Keep it bounded well below an OOM-sized history.
  const MAX_SEEN_SIZE = 4096;
  if (seen.size > MAX_SEEN_SIZE) seen.clear();

  queue.push(data);
  adjustQueuedBytes(queue, roomId, peerId, data.byteLength);

  if (!drainingRef.value)
    void drain(
      queue,
      seen,
      drainingRef,
      api,
      roomId,
      peerId,
      channelLabel,
      merkleRootHex,
      merkleRoot,
      extChannel,
      epc,
      receiveMessageModule,
      signal,
    );

  return true;
};
