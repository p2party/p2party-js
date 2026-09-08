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
import { getMerkleProof } from "../cryptography/merkle";
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
} from "./reconcile";
import { MAX_QUEUED_FRAMES_PER_CHANNEL } from "./handleMessageQueueing";
import { sealChunk } from "./messageChunkCrypto";
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
  CHANNEL_OPEN_POLL_MS,
} from "../utils/constants";

import { deleteDBSendQueue, getDBNewChunk, setDBNewChunk } from "../db/api";
import { roomSendQueueLabel } from "../utils/sendQueueKey";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { PqMessageKeyContext } from "../cryptography/pqMessageKey";
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
  readonly pollMs: number;
  readonly isOpen: () => boolean;
  readonly inFlight: () => number;
  readonly signal?: AbortSignal;
}

/**
 * Resolve once in-flight drops below the window, the channel leaves "open",
 * or receipt progress stalls for stallTimeoutMs. Any receipt progress while
 * still over the window resets the stall clock. Throws only on transfer abort.
 */
export const waitForReceiptWindow = async (
  params: ReceiptWindowParams,
): Promise<void> => {
  let lastInFlight = params.inFlight();
  let lastProgressAt = Date.now();
  while (params.isOpen() && params.inFlight() >= params.windowSize) {
    throwIfTransferAborted(params.signal);
    const inFlight = params.inFlight();
    if (inFlight < lastInFlight) {
      lastInFlight = inFlight;
      lastProgressAt = Date.now();
    }
    if (Date.now() - lastProgressAt >= params.stallTimeoutMs) return;
    await new Promise((resolve) => setTimeout(resolve, params.pollMs));
    throwIfTransferAborted(params.signal);
  }
  throwIfTransferAborted(params.signal);
};

const sendChunks = async (
  channel: IRTCDataChannel,
  // v4: the CLASSICAL message key + header derived ONCE for the whole message
  // by the caller (`ratchetEncryptDurably`). Every chunk of the message —
  // across the initial pass AND every selective-retransmit round — is sealed
  // under this same key with a FRESH random nonce (streaming-safe; no
  // per-message frame cache needed). `pqContext` is the caller-owned copy of
  // the PQ message context captured with the step; sealChunk combines it with
  // an owned per-chunk copy of the classical key.
  messageKey: Uint8Array,
  header: RatchetHeader,
  pqContext: PqMessageKeyContext | null,
  chunksLen: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  transferId: string,
  hashHex: string,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  signal?: AbortSignal,
  // When set (reconcile: selective retransmit / resume), resend ONLY the un-acked
  // real chunks — skip decoys and already-acked reals.
  reconcileAcked?: Set<number>,
  // Live count of receipted chunks for this transfer edge; enables the
  // sender-side receipt window. Absent → legacy SCTP-only pacing.
  getAckedRealCount?: () => number,
  outboxLease?: OutboxLease,
) => {
  throwIfTransferAborted(signal);
  const { merkleRootHex } = await decompileChannelMessageLabel(channel.label);
  if (merkleRootHex !== uint8ArrayToHex(merkleRoot))
    throw new Error("Outbound channel label does not match its Merkle root");

  // Receipts landing during this pass shrink the window; acks that predate the
  // pass (resume replays) must not count against frames sent in this pass.
  const ackedAtPassStart = getAckedRealCount?.() ?? 0;
  let sentRealThisPass = 0;

  const indexes = Array.from({ length: chunksLen }, (_, i) => i);
  const indexesRandomized = fisherYatesShuffle(indexes);

  for (let i = 0; i < chunksLen; i++) {
    throwIfTransferAborted(signal);
    const iRandom = indexesRandomized[i];

    const unencryptedChunk = await getDBNewChunk(transferId, iRandom);
    throwIfTransferAborted(signal);
    if (!unencryptedChunk)
      throw new Error(`Missing staged outbound chunk ${String(iRandom)}`);

    const metadataArray = new Uint8Array(unencryptedChunk.metadata);
    const metadata = deserializeMetadata(metadataArray);
    if (
      metadata.chunkIndex !== iRandom ||
      unencryptedChunk.chunkIndex !== iRandom
    )
      throw new Error("Outbound chunk index does not match its staging key");

    // Real-vs-decoy is read from the chunk's own metadata (SSOT) — a decoy has
    // chunkEnd − chunkStart > totalSize.
    const isRealChunk =
      metadata.chunkEndIndex > metadata.chunkStartIndex &&
      metadata.chunkEndIndex - metadata.chunkStartIndex <= metadata.totalSize;
    // Reconcile: resend only un-acked REAL chunks. Decoys are cover and never
    // resent; acked reals are skipped.
    if (reconcileAcked !== undefined) {
      if (!isRealChunk || reconcileAcked.has(metadata.chunkIndex)) continue;
    }

    // Hold real frames inside the receipt window so a fast link cannot outrun
    // the receiver's decrypt+store drain into its queue-budget channel close.
    if (isRealChunk && getAckedRealCount) {
      await waitForReceiptWindow({
        windowSize: SEND_RECEIPT_WINDOW,
        stallTimeoutMs: SEND_WINDOW_STALL_MS,
        pollMs: CHANNEL_OPEN_POLL_MS,
        isOpen: () => (channel.readyState as string) === "open",
        inFlight: () =>
          sentRealThisPass -
          Math.max(0, getAckedRealCount() - ackedAtPassStart),
        signal,
      });
    }

    const merkleProof = new Uint8Array(PROOF_LEN);
    if (unencryptedChunk.merkleProof.byteLength === 0) {
      const m = await getMerkleProof(
        chunkHashes,
        hexToUint8Array(unencryptedChunk.leafHash),
        merkleModule,
        PROOF_LEN,
      );
      throwIfTransferAborted(signal);

      merkleProof.set(m);
    } else {
      merkleProof.set(new Uint8Array(unencryptedChunk.merkleProof));
    }

    const receiptToken =
      unencryptedChunk.receiptToken.length === crypto_hash_sha512_BYTES * 2
        ? unencryptedChunk.receiptToken
        : uint8ArrayToHex(
            await createChunkReceiptToken(
              merkleRoot,
              metadata.chunkIndex,
              hexToUint8Array(unencryptedChunk.leafHash),
            ),
          );
    throwIfTransferAborted(signal);

    // Persist proof + scoped receipt lookup BEFORE putting the frame on wire.
    // If quota/storage fails, propagating the error is the only recoverable
    // behaviour: a sent frame whose resend source was not committed can never
    // participate correctly in reconnect reconciliation.
    if (
      unencryptedChunk.merkleProof.byteLength === 0 ||
      unencryptedChunk.merkleRoot !== merkleRootHex ||
      unencryptedChunk.receiptToken !== receiptToken
    ) {
      await setDBNewChunk(
        {
          transferId,
          hash: hashHex,
          merkleRoot: merkleRootHex,
          leafHash: unencryptedChunk.leafHash,
          receiptToken,
          chunkIndex: iRandom,
          data: unencryptedChunk.data,
          metadata: unencryptedChunk.metadata,
          merkleProof: merkleProof.buffer,
        },
        outboxLease,
      );
    }

    if (
      DECRYPTED_LEN !==
      metadataArray.length +
        merkleProof.length +
        new Uint8Array(unencryptedChunk.data).length
    )
      throw new Error("Outbound staged chunk has invalid cell length");

    const chunk = await concatUint8Arrays([
      metadataArray,
      merkleProof,
      new Uint8Array(unencryptedChunk.data),
    ]);
    throwIfTransferAborted(signal);

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
    while (
      (channel.readyState as string) === "open" &&
      channel.bufferedAmount >= MAX_BUFFERED_AMOUNT
    ) {
      await new Promise((resolve) => setTimeout(resolve, CHANNEL_OPEN_POLL_MS));
      throwIfTransferAborted(signal);
    }

    if ((channel.readyState as string) !== "open") {
      debugLog(
        "Cannot send message because channel is " +
          channel.readyState +
          " and bufferedAmount is " +
          String(channel.bufferedAmount),
      );

      break;
    }

    let message: Uint8Array;
    try {
      message = sealChunk(
        messageKey,
        header,
        chunk,
        merkleRoot,
        encryptionModule,
        pqContext ?? undefined,
      );
    } catch (error) {
      throw new Error("Could not seal outbound message chunk", {
        cause: error,
      });
    }

    throwIfTransferAborted(signal);
    try {
      channel.send(message.buffer as ArrayBuffer);
      if (isRealChunk) sentRealThisPass++;
    } catch (error) {
      // The channel can close between the readyState check and send(). Return to
      // the reconcile loop so it can reopen/rekey instead of rejecting the whole
      // logical send at this unavoidable async transport race.
      if ((channel.readyState as string) !== "open") break;
      throw error;
    }
  }
  // protocol-v3: no box wasm scratch to free — `sealChunk` allocates + frees its
  // own transient buffers per chunk; the message key is owned + wiped by the
  // caller (sendWithReconcile) after the last retransmit round.
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
      await deleteDBSendQueue(
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
      // suspended -- e.g. a backgrounded tab, or stopped). That is local and
      // typically temporary: it resolves on its own once the tab is
      // foregrounded/online again, unlike a dead peer.
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
const sendWithReconcile = async (
  channel: IRTCDataChannel,
  api: BaseQueryApi,
  roomId: string,
  epc: IRTCPeerConnection,
  chunksLen: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  transferId: string,
  hashHex: string,
  peerId: string,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  signal?: AbortSignal,
  outboxLease?: OutboxLease,
): Promise<void> => {
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
  await deleteDBSendQueue(roomSendQueueLabel(roomId, channel.label), peerId);
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
    const stepped = await ratchetEncryptDurably(epc, roomId, encryptionModule);
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
  const runTransfer = async (): Promise<void> => {
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
      messageKey,
      header,
      pqContext,
      chunksLen,
      chunkHashes,
      merkleRoot,
      transferId,
      hashHex,
      encryptionModule,
      merkleModule,
      signal,
      undefined,
      () => getAckedChunkCount(roomId, peerId, transferId),
      outboxLease,
    );

    let retries = 0;
    let resumeAttempts = 0;
    let completed = false;
    while (retries < MAX_RETRANSMITS) {
      const done = await waitForCompletion(
        roomId,
        peerId,
        transferId,
        RETRANSMIT_TIMEOUT_MS * (retries + 1),
        signal,
      );
      throwIfTransferAborted(signal);
      if (done) {
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
          await persistOutboundCancellation({
            roomId,
            peerId,
            peerPublicKey: currentEpc.withPeerPublicKey,
            transferId,
            merkleRootHex: uint8ArrayToHex(merkleRoot),
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
          RECONNECT_RESUME_TIMEOUT_MS,
          signal,
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
            ratchetEncryptDurably,
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
        currentEpc = rebound.epc;
        transportGateLease = rebound.lease;
        messageKey = rebound.messageKey;
        header = rebound.header;
        pqContext = rebound.pqContext ?? null;
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

      // Reconcile: resend only the reals the receiver hasn't acked yet. Same
      // message key + header + PQ context (the ratchet is NOT re-stepped); a
      // fresh nonce per re-seal keeps it safe and the receiver's cached key
      // still opens it.
      await sendChunks(
        currentChannel,
        messageKey,
        header,
        pqContext,
        chunksLen,
        chunkHashes,
        merkleRoot,
        transferId,
        hashHex,
        encryptionModule,
        merkleModule,
        signal,
        getAckedChunks(roomId, peerId, transferId),
        () => getAckedChunkCount(roomId, peerId, transferId),
        outboxLease,
      );
      retries++;

      // Telemetry: a retransmit round happened — lets the UI show reliability.
      api.dispatch(
        incrementMessageStats({ roomId, sha512Hex: hashHex, retransmit: true }),
      );
    }
    if (!completed)
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
    // The message key + owned PQ context copy are dead once every retransmit
    // round for this message is done (or given up) — wipe them. The ratchet
    // has already advanced past the key.
    messageKey.fill(0);
    pqContext?.rootKey.fill(0);
    clearTransfer(roomId, peerId, transferId);
  }
};

// Seal exactly one staged chunk into its uniform 65,490-byte cell under the
// message's per-message key/header + PQ context. Mirrors sendChunks' per-chunk
// staging but for a single index, so a scheduled slot can lazily produce one
// cell without a burst.
const makeScheduledSlotSealer =
  (
    transferId: string,
    hashHex: string,
    chunkHashes: Uint8Array,
    merkleRoot: Uint8Array,
    merkleRootHex: string,
    messageKey: Uint8Array,
    header: RatchetHeader,
    pqContext: PqMessageKeyContext | null,
    encryptionModule: LibCrypto,
    merkleModule: LibCrypto,
    outboxLease?: OutboxLease,
    signal?: AbortSignal,
  ) =>
  async (chunkIndex: number): Promise<Uint8Array | null> => {
    throwIfTransferAborted(signal);
    const unencryptedChunk = await getDBNewChunk(transferId, chunkIndex);
    if (!unencryptedChunk) return null;
    const metadataArray = new Uint8Array(unencryptedChunk.metadata);
    const metadata = deserializeMetadata(metadataArray);

    const merkleProof = new Uint8Array(PROOF_LEN);
    if (unencryptedChunk.merkleProof.byteLength === 0) {
      merkleProof.set(
        await getMerkleProof(
          chunkHashes,
          hexToUint8Array(unencryptedChunk.leafHash),
          merkleModule,
          PROOF_LEN,
        ),
      );
    } else {
      merkleProof.set(new Uint8Array(unencryptedChunk.merkleProof));
    }

    const receiptToken =
      unencryptedChunk.receiptToken.length === crypto_hash_sha512_BYTES * 2
        ? unencryptedChunk.receiptToken
        : uint8ArrayToHex(
            await createChunkReceiptToken(
              merkleRoot,
              metadata.chunkIndex,
              hexToUint8Array(unencryptedChunk.leafHash),
            ),
          );
    if (
      unencryptedChunk.merkleProof.byteLength === 0 ||
      unencryptedChunk.merkleRoot !== merkleRootHex ||
      unencryptedChunk.receiptToken !== receiptToken
    ) {
      await setDBNewChunk(
        {
          transferId,
          hash: hashHex,
          merkleRoot: merkleRootHex,
          leafHash: unencryptedChunk.leafHash,
          receiptToken,
          chunkIndex,
          data: unencryptedChunk.data,
          metadata: unencryptedChunk.metadata,
          merkleProof: merkleProof.buffer,
        },
        outboxLease,
      );
    }

    const chunk = await concatUint8Arrays([
      metadataArray,
      merkleProof,
      new Uint8Array(unencryptedChunk.data),
    ]);
    throwIfTransferAborted(signal);
    return sealChunk(
      messageKey,
      header,
      chunk,
      merkleRoot,
      encryptionModule,
      pqContext ?? undefined,
    );
  };

/**
 * Can this edge's cover runtime still admit a scheduled job?
 *
 * A scheduled job is dequeued only at a cycle open, and `CoverScheduler`
 * refuses to open one while suspended or stopped. Enqueuing into either and
 * then awaiting the schedule-derived delivery bound burns that whole budget —
 * 321 s on the shipped "5 min cycles" preset — for a job nothing was going to
 * send, and `sendScheduled` fans out serially, so it stalls every later peer
 * in the room behind it.
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
  ) => Promise<boolean>;
  /** How long to watch for a replacement cover runtime before giving up (C8). */
  readonly resumeWaitMs?: number;
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
  totalChunks: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  merkleRootHex: string,
  transferId: string,
  hashHex: string,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
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
  const waitForGate = dependencies.waitForGate ?? waitForRatchetGate;
  const ratchetStep = dependencies.ratchetStep ?? ratchetEncryptDurably;
  const waitForDelivery =
    dependencies.waitForDelivery ?? waitForScheduledDelivery;
  const resumeWaitMs = dependencies.resumeWaitMs ?? RECONNECT_RESUME_TIMEOUT_MS;
  const outcomes: PeerDeliveryOutcome[] = [];
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

  // DISCLOSED: this fan-out is SERIAL, so every peer waits behind the one
  // before it, and one peer's worst case is not one idle budget. It is up to
  // (1 + MAX_SCHEDULED_SEND_RESUMES) budgets plus as many resume watches
  // (RECONNECT_RESUME_TIMEOUT_MS each) — three budgets and two watches on the
  // shipped cap — before the next peer is even attempted. On the "5 min cycles"
  // preset that is about thirty-two minutes for one peer.
  //
  // And with the suspension hold above it has no upper bound at all while the
  // page stays hidden. That is deliberate and it is not per-peer starvation:
  // visibilitychange / pagehide / freeze / offline are PAGE-wide, so every edge
  // in the room is suspended together — there is no peer being starved of a
  // schedule that is running for someone else. The wait ends when the tab comes
  // back, or when `signal` aborts.
  //
  // Each edge has its own scheduler, so serial fan-out adds latency for later
  // peers even when their own lanes have capacity. Concurrent per-peer sends
  // remain a separate scheduling change.
  for (const target of targets) {
    if (signal?.aborted) {
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "cancelled",
      });
      continue;
    }
    const epc = target.epc;
    if (
      !epc ||
      !(await waitForConnectedEdge(epc, PEER_ADMISSION_WAIT_MS, signal))
    ) {
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "not-connected",
      });
      continue;
    }
    // The transport is connected, so this is not a dead peer -- it is this
    // edge's own scheduled-cover pipeline (missing, suspended, e.g. a
    // backgrounded tab, or stopped) refusing to admit a job. Report that
    // distinctly: it is a local condition the caller can expect to clear on
    // its own, not a reason to give up on the peer.
    if (!coverRuntimeAdmitsScheduledJobs(epc.coverRuntime)) {
      outcomes.push({
        peerId: target.peerId,
        status: "skipped",
        reason: "cover-unavailable",
      });
      continue;
    }
    let currentEpc = epc;
    let channelMessageLabel = "";
    let admitted = false;
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
        const sealer = makeScheduledSlotSealer(
          transferId,
          hashHex,
          chunkHashes,
          merkleRoot,
          merkleRootHex,
          stepped.messageKey,
          stepped.header,
          stepped.pqContext,
          encryptionModule,
          merkleModule,
          outboxLease,
          signal,
        );
        // The sealer closure above holds `stepped.messageKey` and the PQ
        // context root for exactly as long as the scheduler can still ask this
        // job for a cell. Wiping them on the delivery timeout — what this did
        // before C3 — did not stop the still-admitted job: it kept emitting
        // cells sealed under an all-zero key, which the receiver can never open
        // and a re-send can never replace. The wipe therefore belongs to job
        // settlement, the one moment after which nextCell is never called
        // again. That is also why a resume cannot carry this sealer across the
        // edge: the teardown that causes the resume settles the job, so by then
        // this key is already zero. Each attempt owns its own generation's
        // secrets and its own wipe.
        let wiped = false;
        const wipeMessageSecrets = (): void => {
          if (wiped) return;
          wiped = true;
          stepped.messageKey.fill(0);
          stepped.pqContext?.rootKey.fill(0);
        };
        const runtime = currentEpc.coverRuntime;
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
        delivered = await waitForDelivery({
          isComplete: () =>
            isTransferComplete(roomId, target.peerId, transferId),
          isInvalidated: () =>
            isTransferCancelled(roomId, target.peerId, transferId) ||
            coverEdgeGeneration(roomId, target.peerId) > generation,
          progress: () =>
            scheduledSendProgress(currentEpc.coverRuntime, channelMessageLabel),
          // A backgrounded tab, a pagehide, a freeze or an offline event
          // suspends this edge's scheduler while it KEEPS the job. The signal
          // above freezes, but the send is healthy: charging the idle budget
          // through that gap cancels it, and the CANCEL deletes the partial the
          // peer is still holding. Suspension is not a stall.
          isSuspended: () => scheduledCoverIsSuspended(currentEpc.coverRuntime),
          idleTimeoutMs: deliveryIdleTimeoutMs,
          signal,
        });
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
      if (
        !delivered &&
        !isTransferCancelled(roomId, target.peerId, transferId)
      ) {
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
      outcomes.push(
        delivered
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
            },
      );
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
      outcomes.push({
        peerId: target.peerId,
        status: "failed",
        phase: "transfer",
        reason,
      });
    } finally {
      if (
        outboxLease &&
        signal?.aborted &&
        !(signal.reason instanceof OutboxOwnershipLostError)
      )
        queueScheduledCancel(currentEpc, channelMessageLabel);
      untrackScheduledSend(currentEpc, merkleRootHex, transferId);
    }
  }
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
    const fanout =
      room.policy.coverMode === "scheduled"
        ? await sendScheduled(
            roomId,
            label,
            room.policy,
            targets,
            totalChunks,
            chunkHashes,
            merkleRoot,
            merkleRootHex,
            transferId,
            hashHex,
            encryptionModule,
            merkleModule,
            signal,
            undefined,
            peerConnections,
            {},
            session.lease,
          )
        : await runPeerSendFanout(
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
                totalChunks,
                chunkHashes,
                merkleRoot,
                transferId,
                hashHex,
                peerId,
                encryptionModule,
                merkleModule,
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
