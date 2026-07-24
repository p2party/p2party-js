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
import { clearTransfer, waitForCompletion, getAckedChunks } from "./reconcile";
import { sealChunk } from "./messageChunkCrypto";
import { getRatchetGate } from "./ratchetGate";
import { isPqApplicationTrafficBlocked } from "./pqHealingOrchestrator";
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
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

// export const wait = (milliseconds: number) => {
//   return new Promise((resolve) => {
//     setTimeout(resolve, milliseconds);
//   });
// };

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
) => {
  throwIfTransferAborted(signal);
  const { merkleRootHex } = await decompileChannelMessageLabel(channel.label);
  if (merkleRootHex !== uint8ArrayToHex(merkleRoot))
    throw new Error("Outbound channel label does not match its Merkle root");

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

    // Reconcile: resend only un-acked REAL chunks. Real-vs-decoy is read from
    // the chunk's own metadata (SSOT) — a decoy has chunkEnd − chunkStart >
    // totalSize. Decoys are cover and never resent; acked reals are skipped.
    if (reconcileAcked !== undefined) {
      const isReal =
        metadata.chunkEndIndex > metadata.chunkStartIndex &&
        metadata.chunkEndIndex - metadata.chunkStartIndex <= metadata.totalSize;
      if (!isReal || reconcileAcked.has(metadata.chunkIndex)) continue;
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
      unencryptedChunk.receiptToken.length ===
      crypto_hash_sha512_BYTES * 2
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
      await new Promise((resolve) =>
        setTimeout(resolve, CHANNEL_OPEN_POLL_MS),
      );
      throwIfTransferAborted(signal);
    }

    if ((channel.readyState as string) !== "open") {
      console.log(
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
    const epc = peerConnections.find(
      (p) =>
        p.roomId === roomId &&
        p.withPeerId === peerId &&
        p.connectionState === "connected",
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

type WaitForRatchetGate = (roomId: string, peerId: string) => Promise<void>;
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
 * Reopening only its DataChannel on the SAME RTCPeerConnection retains the
 * ratchet session, so the per-message key/header remain valid. A replacement
 * RTCPeerConnection, however, performs a fresh hybrid handshake and owns an
 * unrelated ratchet. It must advance that ratchet once and reseal the missing
 * plaintext chunks; replaying the old ciphertext/key/header cannot decrypt.
 *
 * Exported only so the transport-identity and key-erasure contract has a focused
 * unit test. It is not part of the package's public root exports.
 */
export const bindTransferCipherToConnection = async (
  transfer: TransferCipher,
  nextEpc: IRTCPeerConnection,
  roomId: string,
  module: LibCrypto,
  waitForGate: WaitForRatchetGate = getRatchetGate,
  ratchetStep: DurableRatchetStep = ratchetEncryptDurably,
  signal?: AbortSignal,
): Promise<TransferCipher> => {
  throwIfTransferAborted(signal);
  if (transfer.epc === nextEpc) return transfer;

  await waitWithTransferAbort(
    waitForGate(roomId, nextEpc.withPeerId),
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
    messageKey: stepped.messageKey,
    header: stepped.header,
    pqContext: stepped.pqContext,
  };
};

export const isAuthenticatedPeerCancel = (
  currentEpc: IRTCPeerConnection,
  peerConnections: IRTCPeerConnection[],
  roomId: string,
  peerId: string,
): boolean =>
  currentEpc.connectionState === "connected" &&
  peerConnections.some(
    (candidate) =>
      candidate === currentEpc &&
      candidate.roomId === roomId &&
      candidate.withPeerId === peerId,
  );

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
      reason: "not-connected" | "unauthenticated" | "cancelled";
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
  const outcomes: Array<
    PeerDeliveryOutcome | Promise<PeerDeliveryOutcome>
  > = [];
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

    if (!target.epc || target.epc.connectionState !== "connected") {
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
        Promise.resolve(started).then<
          PeerDeliveryOutcome,
          PeerDeliveryOutcome
        >(
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
          ): outcome is Extract<
            PeerDeliveryOutcome,
            { status: "failed" }
          > => outcome.status === "failed",
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

  // This path no longer persists ciphertext. Remove any queue records left by an
  // older runtime before this channel can drain them; plaintext newChunks are the
  // sole durable resend source.
  await deleteDBSendQueue(
    roomSendQueueLabel(roomId, channel.label),
    peerId,
  );
  throwIfTransferAborted(signal);

  // protocol-v3: do not send until the PACE + Double-Ratchet handshake has seeded
  // this peer's ratchet (the `main` channel opens the gate). A rejected gate =
  // failed handshake → abort this peer's send.
  try {
    await waitWithTransferAbort(getRatchetGate(roomId, peerId), signal);
  } catch (error) {
    throw new Error("v3 send: ratchet gate rejected", { cause: error });
  }
  if (!epc.ratchetState)
    throw new Error("v3 send: no ratchet state for peer");

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
    const stepped = await ratchetEncryptDurably(
      epc,
      roomId,
      encryptionModule,
    );
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
    if (
      !(await waitForOpen(
        currentChannel,
        undefined,
        undefined,
        signal,
      ))
    )
      throw new Error("Message DataChannel did not open before send timeout");
    throwIfTransferAborted(signal);

    // Initial pass: all chunks (real + decoy).
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
        // while its authenticated RTCPeerConnection remains current and
        // connected, that close is the peer's immediate-mode CANCEL signal.
        // Resume is reserved for a replacement PC after a transport failure.
        if (
          isAuthenticatedPeerCancel(
            currentEpc,
            peerConnections,
            roomId,
            peerId,
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
        const rebound = await bindTransferCipherToConnection(
          { epc: currentEpc, messageKey, header },
          resumed.epc,
          roomId,
          encryptionModule,
          getRatchetGate,
          ratchetEncryptDurably,
          signal,
        );
        currentEpc = rebound.epc;
        messageKey = rebound.messageKey;
        header = rebound.header;
        pqContext = rebound.pqContext ?? null;
        currentChannel = resumed.channel;
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
              candidate.roomId === roomId &&
              candidate.withPeerId === peerId,
          ),
        }),
      );

      const fanout = await runPeerSendFanout(
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
