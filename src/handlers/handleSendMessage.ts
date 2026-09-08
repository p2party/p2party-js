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
import { deleteMessage, incrementMessageStats } from "../reducers/roomSlice";
import {
  clearTransfer,
  isTransferComplete,
  waitForCompletion,
  getAckedChunks,
  getAckedChunkCount,
} from "./reconcile";
import { MAX_QUEUED_FRAMES_PER_CHANNEL } from "./handleMessageQueueing";
import { sealChunk } from "./messageChunkCrypto";
import { isRatchetGateWaitTimeout, waitForRatchetGate } from "./ratchetGateWait";
import { isCurrentRatchetGateLease, isRatchetGateOpen } from "./ratchetGate";
import {
  markChannelClosedLocally,
  wasChannelClosedLocally,
} from "../api/webrtc/localChannelClose";
import { isPqApplicationTrafficBlocked } from "./pqHealingOrchestrator";
import {
  cancelScheduledSend,
  enqueueScheduledSend,
  trackScheduledSend,
} from "./coverEdge";
import {
  scheduledDeliveryTimeoutMs,
  scheduledSendProgressToken,
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
  CHANNEL_OPEN_POLL_MS,
} from "../utils/constants";

import {
  deleteDBNewChunk,
  deleteReceiveTransfer,
  deleteDBSendQueue,
  getDBNewChunk,
  setDBNewChunk,
} from "../db/api";
import { roomSendQueueLabel } from "../utils/sendQueueKey";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { PqMessageKeyContext } from "../cryptography/pqMessageKey";
import type { RatchetHeader } from "../cryptography/ratchet";
import type { RatchetGateLease } from "./ratchetGate";
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
      await setDBNewChunk({
        transferId,
        hash: hashHex,
        merkleRoot: merkleRootHex,
        leafHash: unencryptedChunk.leafHash,
        receiptToken,
        chunkIndex: iRandom,
        data: unencryptedChunk.data,
        metadata: unencryptedChunk.metadata,
        merkleProof: merkleProof.buffer,
      });
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
        | "not-connected"
        | "cover-unavailable"
        | "unauthenticated"
        | "cancelled";
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
        )
          throw new Error("Message transfer cancelled by peer");

        if (resumeAttempts >= MAX_RESUME_ATTEMPTS) break;
        resumeAttempts++;
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
    await runWithTerminalChannelClose(() => currentChannel, runTransfer);
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
  ) =>
  async (chunkIndex: number): Promise<Uint8Array | null> => {
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
      await setDBNewChunk({
        transferId,
        hash: hashHex,
        merkleRoot: merkleRootHex,
        leafHash: unencryptedChunk.leafHash,
        receiptToken,
        chunkIndex,
        data: unencryptedChunk.data,
        metadata: unencryptedChunk.metadata,
        merkleProof: merkleProof.buffer,
      });
    }

    const chunk = await concatUint8Arrays([
      metadataArray,
      merkleProof,
      new Uint8Array(unencryptedChunk.data),
    ]);
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
 * Scheduled-cover send: instead of opening a per-message DataChannel and
 * bursting, step the ratchet once for the message and enqueue a lazy cover job
 * on each peer edge's cover runtime. The scheduler substitutes one chunk cell
 * per slot into the already-running cover lanes; the tail is dummy. Delivery is
 * confirmed by the receiver's terminal scheduled receipt (markTransferComplete).
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
): Promise<PeerSendFanoutResult> => {
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
    try {
      await waitForRatchetGate(roomId, target.peerId, signal);
      if (!epc.ratchetState)
        throw new Error("v4 scheduled send: no ratchet state");
      await waitForPqTrafficAdmission(epc, signal);
      const stepped = await ratchetEncryptDurably(
        epc,
        roomId,
        encryptionModule,
      );
      const channelMessageLabel = await compileChannelMessageLabel(
        channelLabel,
        merkleRootHex,
      );
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
      );
      // The sealer closure above holds `stepped.messageKey` and the PQ context
      // root for exactly as long as the scheduler can still ask this job for a
      // cell. Wiping them on the delivery timeout — what this did before C3 —
      // did not stop the still-admitted job: it kept emitting cells sealed
      // under an all-zero key, which the receiver can never open and a re-send
      // can never replace. The wipe therefore belongs to job settlement, the
      // one moment after which nextCell is never called again.
      let wiped = false;
      const wipeMessageSecrets = (): void => {
        if (wiped) return;
        wiped = true;
        stepped.messageKey.fill(0);
        stepped.pqContext?.rootKey.fill(0);
      };
      try {
        const enqueued = enqueueScheduledSend({
          epc,
          channelMessageLabel,
          totalChunks,
          merkleRoot,
          sealSlotCell: sealer,
          getAckedChunks: () =>
            getAckedChunks(roomId, target.peerId, transferId),
        });
        if (!enqueued)
          throw new Error("v4 scheduled send: edge has no cover runtime");
        // Registered synchronously with the enqueue, so the job cannot settle
        // in between and leave the message key alive for the page's lifetime.
        epc.coverRuntime?.onJobSettled(channelMessageLabel, wipeMessageSecrets);
      } catch (enqueueError) {
        // Nothing ever holds the sealer, so its secrets die here.
        wipeMessageSecrets();
        throw enqueueError;
      }
      trackScheduledSend(epc, roomId, target.peerId, merkleRootHex, transferId);
      startedTransfers += 1;
      onTransferStarted?.();
      // Delivery confirmation: over reliable ordered lanes the receiver signals
      // completion with a terminal scheduled receipt. Bound the wait by this
      // send's own PROGRESS, not by elapsed time — a job admitted only at a
      // cycle open, behind every other job in the room, is not a failed job,
      // and cancelling it now deletes a partial that is still filling.
      const delivered = await waitForScheduledDelivery({
        isComplete: () => isTransferComplete(roomId, target.peerId, transferId),
        progressToken: () =>
          scheduledSendProgressToken(epc.coverRuntime, channelMessageLabel),
        idleTimeoutMs: deliveryIdleTimeoutMs,
        signal,
      });
      if (!delivered) {
        // Tell the receiver, before anything else destroys what could still
        // fill its partial. Without this the sender reported failure while the
        // receiver kept an unfillable N/M transfer forever — a re-send cannot
        // fill it, because decoy chunks are fresh randomness and the Merkle
        // root differs (C3).
        cancelScheduledSend(epc, channelMessageLabel);
      }
      outcomes.push(
        delivered
          ? { peerId: target.peerId, status: "delivered" }
          : {
              peerId: target.peerId,
              status: "failed",
              phase: "transfer",
              reason: new Error("scheduled delivery not confirmed"),
            },
      );
    } catch (reason) {
      outcomes.push({
        peerId: target.peerId,
        status: "failed",
        phase: "transfer",
        reason,
      });
    }
  }
  return { outcomes, startedTransfers };
};

export const handleSendMessage = async (
  data: string | File,
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
  let merkleRootForFailureCleanup = "";
  let localMessageCommitted = false;
  let wireWorkStarted = false;
  try {
    throwIfTransferAborted(transfer.signal);
    const { rooms } = api.getState() as State;

    const roomIndex = rooms.findIndex((r) => r.id === roomId);
    if (roomIndex === -1) throw new Error("No room with id " + roomId);

    if (roomIndex > -1) {
      const channelIndex = rooms[roomIndex].channels.findIndex(
        (c) => c.label === label,
      );
      if (channelIndex === -1)
        throw new Error("No channel with label " + label);

      const { merkleRoot, merkleRootHex, hashHex, totalChunks, chunkHashes } =
        await splitToChunks(
          data,
          api,
          label,
          rooms[roomIndex],
          merkleModule,
          transfer,
          minChunks,
          chunkSize,
          percentageFilledChunk,
          metadataSchemaVersion,
        );

      transfer.bindMerkleRoot(merkleRootHex);
      merkleRootForFailureCleanup = merkleRootHex;
      throwIfTransferAborted(transfer.signal);

      if (
        merkleRoot.length === 0 ||
        hashHex.length === 0 ||
        totalChunks === 0 ||
        chunkHashes.length === 0
      )
        return;
      localMessageCommitted = true;

      const channelMessageLabel = await compileChannelMessageLabel(
        label,
        merkleRootHex,
      );

      const targets = rooms[roomIndex].channels[channelIndex].peerIds.map(
        (peerId): PeerSendTarget => ({
          peerId,
          epc: peerConnections.find(
            (candidate) =>
              candidate.roomId === roomId && candidate.withPeerId === peerId,
          ),
        }),
      );

      const scheduledRoom = rooms[roomIndex].policy.coverMode === "scheduled";
      const fanout = scheduledRoom
        ? await sendScheduled(
            roomId,
            label,
            rooms[roomIndex].policy,
            targets,
            totalChunks,
            chunkHashes,
            merkleRoot,
            merkleRootHex,
            transfer.transferId,
            hashHex,
            encryptionModule,
            merkleModule,
            transfer.signal,
            () => {
              wireWorkStarted = true;
            },
          )
        : await runPeerSendFanout(
            targets,
            ({ epc }) =>
              handleOpenChannel(
                { channel: channelMessageLabel, epc, roomId, dataChannels },
                api,
              ),
            ({ peerId, epc }, channel) =>
              sendWithReconcile(
                channel,
                api,
                roomId,
                epc,
                totalChunks,
                chunkHashes,
                merkleRoot,
                transfer.transferId,
                hashHex,
                peerId,
                encryptionModule,
                merkleModule,
                peerConnections,
                dataChannels,
                transfer.signal,
              ),
            transfer.signal,
            () => {
              wireWorkStarted = true;
            },
          );
      const result: SendMessageResult = {
        transferId: transfer.transferId,
        merkleRootHex,
        ...fanout,
      };

      throwIfTransferAborted(transfer.signal);
      const delivered = result.outcomes.filter(
        (outcome) => outcome.status === "delivered",
      ).length;
      if (result.startedTransfers === 0)
        throw new MessageDeliveryError(
          result,
          "No authenticated connected peers accepted the send",
        );
      if (delivered === 0)
        throw new MessageDeliveryError(
          result,
          "Message was not delivered to any peer",
        );

      // Mixed success is a completed room send, not a reason to erase the
      // sender's history. The caller can surface every peer's setup/transfer
      // outcome and decide whether to retry only the failed edges.
      return result;
    }
    return undefined;
  } catch (error) {
    if (
      shouldDeleteLocalMessageAfterFailure(
        localMessageCommitted,
        wireWorkStarted,
        transfer.signal.aborted,
      )
    ) {
      if (merkleRootForFailureCleanup.length > 0) {
        await deleteReceiveTransfer(merkleRootForFailureCleanup);
      }
      api.dispatch(deleteMessage({ roomId, transferId: transfer.transferId }));
    }
    if (transfer.signal.aborted)
      throw transfer.signal.reason instanceof Error
        ? transfer.signal.reason
        : new Error("Message transfer cancelled");
    console.trace(error);
    throw error;
  } finally {
    await deleteDBNewChunk({ transferId: transfer.transferId });
    transfer.finish();
  }
};
