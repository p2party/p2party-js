import { debugLog } from "../utils/debug";
import {
  IMMEDIATE_RESUME_PROTOCOL,
  FRAME_TYPE_IMMEDIATE_DISPOSITION,
  bindImmediateDisposition,
  immediateCloseMeansPause,
  acceptImmediateDisposition,
  sendImmediateResumeCapability,
} from "./immediateDisposition";
import { handleReadReceipt } from "./handleReadReceipt";
import {
  createReceiptProcessingQueue,
  enqueue,
  enqueueReceipt,
  releaseQueuedMessageFrames,
  releaseQueuedReceipts,
  waitForQueuedMessageFrames,
} from "./handleMessageQueueing";
import {
  setHandshakeChannel,
  clearHandshakeChannel,
  deliverHandshakeFrame,
  runHandshake,
  parseFingerprintFromSdp,
} from "./handleHandshake";
import { buildChannelInput } from "./handshakeCore";
import { classifyFrame } from "./frameType";
import {
  RECEIPT_REPLAY_BATCH_SIZE,
  sendReceiptFrame,
  sendReceiptFramesPaced,
} from "./receiptFrame";
import {
  getRatchetGate,
  isCurrentRatchetGateLease,
  isRatchetGateOpen,
  rejectRatchetGate,
} from "./ratchetGate";
import { admitPreAuthenticatedFrame } from "./ratchetGateWait";
import {
  markChannelClosedLocally,
  wasChannelClosedLocally,
} from "../api/webrtc/localChannelClose";
import {
  classifyHandshakeFailure,
  isTerminalHandshakeFailure,
} from "./handshakeFailure";
import {
  handleInboundPqControlFrame,
  installPqHealingOrchestrator,
} from "./pqHealingOrchestrator";
import { installCoverEdge } from "./coverEdge";
import { requestPeersAfterEdgeTeardown } from "./edgeTeardownFollowUp";

import webrtcApi from "../api/webrtc";
import { clearRebindAuthenticationDeadline } from "../api/webrtc/rebindDeadline";

import {
  setChannel,
  setPeerCoverStatus,
  setPeerHandshakeStatus,
} from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import {
  deleteReceiveTransfer,
  getDBAllChunkLeafHashes,
  getDBMessageData,
  getPinAttemptState,
} from "../db/api";

import { hexToUint8Array } from "../utils/uint8array";
import { createChunkReceiptToken } from "../utils/receiptToken";
import { getRoomPin } from "../roomPinVault";
import { hashRoomPolicyV1 } from "../roomPolicy";
import {
  assertPinAttemptAllowed,
  clearPinAttempts,
  recordPinFailure,
} from "../roomPinAttempts";
import { decompileChannelMessageLabel } from "../utils/channelLabel";
import {
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_COVER,
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_PQ_CONTROL,
  FRAME_TYPE_RECEIPT,
  PARKED_PRE_AUTH_FRAME_OVERHEAD_BYTES,
  PRE_AUTH_FRAME_PARK_MS,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";
import {
  isIdentityInitiator,
  shouldAcceptIncomingMain,
} from "../utils/identityRole";
import { MAX_DATA_CHANNEL_LABEL_CHARS } from "../utils/signalingBounds";
import { isRemoteCancelClose } from "./transferAbort";
import {
  forgetCompletedReceiveMessageKey,
  forgetMappedReceiveMessageKey,
} from "./receiveMessageKeyLifetime";
import {
  registerCoverChannelUntilClose,
  unregisterCoverChannel,
} from "./coverChannelRegistry";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";
import type { HandshakeLease } from "./handleHandshake";
import type { RatchetGateLease } from "./ratchetGate";
import type { PreAuthFrameDecision } from "./ratchetGateWait";

export const MAX_MESSAGE_CHANNELS_PER_EDGE = 64;
const ROOM_CHANNEL_CONTEXT_DOMAIN = new TextEncoder().encode(
  "p2party/room-channel/v1\u0000",
);

const buildRoomChannelId = (
  roomUrl: string,
  channelLabel: string,
  policyHash: Uint8Array,
): Uint8Array => {
  const roomCapability = hexToUint8Array(roomUrl);
  if (roomCapability.length !== 32)
    throw new Error("Room capability must be 32 bytes");
  if (policyHash.length !== 32)
    throw new Error("Room policy hash must be 32 bytes");
  const label = new TextEncoder().encode(channelLabel);
  const output = new Uint8Array(
    ROOM_CHANNEL_CONTEXT_DOMAIN.length +
      roomCapability.length +
      policyHash.length +
      label.length,
  );
  let offset = 0;
  output.set(ROOM_CHANNEL_CONTEXT_DOMAIN, offset);
  offset += ROOM_CHANNEL_CONTEXT_DOMAIN.length;
  output.set(roomCapability, offset);
  offset += roomCapability.length;
  output.set(policyHash, offset);
  offset += policyHash.length;
  output.set(label, offset);
  return output;
};

export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  roomId: string;
  dataChannels: IRTCDataChannel[];
  /** True only for a channel delivered by RTCPeerConnection.ondatachannel. */
  incoming?: boolean;
}

export const handleOpenChannel = async (
  {
    channel,
    epc,
    roomId,
    dataChannels,
    incoming = false,
  }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  const { keyPair, rooms } = api.getState() as State;

  const roomIndex = rooms.findIndex((r) => r.id === roomId);

  const queue: Uint8Array[] = [];
  const seen = new Set<string>();
  const drainingRef = { value: false };
  const receiveAbort = new AbortController();
  const receiptQueue = createReceiptProcessingQueue(roomId, epc.withPeerId);

  if (typeof channel === "string") {
    const channelIndex = dataChannels.findIndex(
      (dc) =>
        dc.label === channel &&
        dc.withPeerId === epc.withPeerId &&
        dc.roomIds.includes(roomId),
    );

    if (channelIndex > -1 && dataChannels[channelIndex].readyState === "open")
      return dataChannels[channelIndex];
  }

  const label = typeof channel === "string" ? channel : channel.label;
  if (
    label.length === 0 ||
    label.length > MAX_DATA_CHANNEL_LABEL_CHARS ||
    (!label.includes("~") && new TextEncoder().encode(label).length > 32)
  ) {
    if (typeof channel !== "string" && channel.readyState !== "closed")
      channel.close();
    throw new Error("Rejected invalid or oversized DataChannel label");
  }

  // Exactly the lower canonical Ed25519 identity creates `main`. If that same
  // side accepts another remotely-created copy, two async handshakes can race
  // for the same inbox/gate/persistence edge. Reject the duplicate at ingress.
  if (
    incoming &&
    label === "main" &&
    !shouldAcceptIncomingMain(keyPair.publicKey, epc.withPeerPublicKey)
  ) {
    if (typeof channel !== "string" && channel.readyState !== "closed")
      channel.close();
    throw new Error(
      "Rejected incoming main DataChannel on the designated opener side",
    );
  }
  if (
    !incoming &&
    label === "main" &&
    !isIdentityInitiator(keyPair.publicKey, epc.withPeerPublicKey)
  )
    throw new Error("Only the designated identity may create main DataChannel");

  if (
    label === "main" &&
    epc.mainChannel &&
    epc.mainChannel.readyState !== "closing" &&
    epc.mainChannel.readyState !== "closed"
  ) {
    if (!incoming) return epc.mainChannel;
    if (epc.mainChannel !== channel) {
      if (typeof channel !== "string" && channel.readyState !== "closed")
        channel.close();
      throw new Error("Rejected duplicate main DataChannel");
    }
  }

  const dataChannel =
    typeof channel === "string"
      ? epc.createDataChannel(channel, {
          ordered: channel === "main",
          protocol:
            channel.includes("~") && epc.coverRuntime === undefined
              ? IMMEDIATE_RESUME_PROTOCOL
              : "raw",
          // negotiated: true,
          // id: dataChannelsWithPeer.length + 1,
          // maxRetransmits: 3,
        })
      : channel;
  dataChannel.binaryType = "arraybuffer";

  const extChannel = dataChannel as IRTCDataChannel;
  extChannel.withPeerId = epc.withPeerId;
  extChannel.roomIds = [roomId];
  if (extChannel.label === "main") epc.mainChannel = extChannel;
  // In a scheduled-cover room every non-main lane IS a cover lane (real chunks,
  // PQ control, receipts, CANCEL, and dummy cells all substitute as cells).
  // Track those in `coverChannels`, kept separate from `messageChannels` so
  // continuous cover lanes never block healing quiescence or the per-edge
  // message-channel budget. Cells route below purely by their type byte.
  const isCoverLane =
    extChannel.label !== "main" && epc.coverRuntime !== undefined;
  let unregisterConcreteCoverChannel = (): void => {
    unregisterCoverChannel(epc.coverChannels, dataChannels, extChannel);
  };
  if (isCoverLane) {
    epc.coverChannels ??= new Set<IRTCDataChannel>();
    try {
      unregisterConcreteCoverChannel = registerCoverChannelUntilClose(
        epc.coverChannels,
        extChannel,
        dataChannels,
      );
    } catch (error) {
      if (extChannel.readyState !== "closed") extChannel.close();
      throw error;
    }
  } else if (extChannel.label !== "main") {
    epc.messageChannels ??= new Set<IRTCDataChannel>();
    if (
      !epc.messageChannels.has(extChannel) &&
      epc.messageChannels.size >= MAX_MESSAGE_CHANNELS_PER_EDGE
    ) {
      if (extChannel.readyState !== "closed") extChannel.close();
      throw new Error("Too many message DataChannels on one peer edge");
    }
    epc.messageChannels.add(extChannel);
  }
  const transportGateLease = epc.ratchetGateLease;
  const awaitAuthenticatedTransport = async (): Promise<boolean> => {
    if (!isCurrentRatchetGateLease(roomId, epc.withPeerId, transportGateLease))
      return false;
    await getRatchetGate(roomId, epc.withPeerId);
    return isCurrentRatchetGateLease(
      roomId,
      epc.withPeerId,
      transportGateLease,
    );
  };
  // Capture both owners while configuring this concrete main channel, before
  // onopen/onclose can race a replacement transport. A late callback from an
  // old connecting channel therefore retains stale leases; it can neither take
  // over the replacement inbox/gate nor disconnect the replacement edge.
  const ratchetGateLease: RatchetGateLease | undefined =
    extChannel.label === "main" ? epc.ratchetGateLease : undefined;
  const handshakeLease: HandshakeLease | undefined =
    extChannel.label === "main"
      ? setHandshakeChannel(
          roomId,
          epc.withPeerId,
          extChannel,
          rooms[roomIndex]?.policy.pqMode ?? "hybrid-mlkem768",
          isIdentityInitiator(keyPair.publicKey, epc.withPeerPublicKey),
        )
      : undefined;
  let parsedLabel: Awaited<ReturnType<typeof decompileChannelMessageLabel>>;
  try {
    parsedLabel = await decompileChannelMessageLabel(label);
  } catch (error) {
    const labelError =
      error instanceof Error ? error : new Error(String(error));
    epc.messageChannels?.delete(extChannel);
    unregisterConcreteCoverChannel();
    if (epc.mainChannel === extChannel) epc.mainChannel = undefined;
    if (handshakeLease)
      clearHandshakeChannel(roomId, epc.withPeerId, labelError, handshakeLease);
    if (extChannel.readyState !== "closed") extChannel.close();
    throw labelError;
  }
  const { channelLabel, merkleRoot, merkleRootHex } = parsedLabel;
  if (!isCoverLane && merkleRootHex !== "")
    bindImmediateDisposition(extChannel, merkleRoot, incoming, () =>
      isRatchetGateOpen(roomId, epc.withPeerId, transportGateLease),
    );
  if (isCoverLane && extChannel.readyState === "closed") {
    unregisterConcreteCoverChannel();
    releaseQueuedReceipts(receiptQueue);
    throw new Error("Cover DataChannel closed during label decoding");
  }

  let resourcesReleased = false;
  let auxiliaryResourcesReleased = false;
  const releaseAuxiliaryResources = (): void => {
    if (auxiliaryResourcesReleased) return;
    auxiliaryResourcesReleased = true;
    releaseQueuedReceipts(receiptQueue);
    epc.messageChannels?.delete(extChannel);
    if (isCoverLane) unregisterConcreteCoverChannel();
  };
  const releaseProtocolResources = (): void => {
    if (resourcesReleased) return;
    resourcesReleased = true;
    if (!receiveAbort.signal.aborted)
      receiveAbort.abort(new Error("Message channel processing stopped"));
    releaseQueuedMessageFrames(queue, roomId, epc.withPeerId, drainingRef);
    releaseAuxiliaryResources();
  };
  extChannel.releaseProtocolResources = releaseProtocolResources;

  let cancellationRequested = false;
  let cancellationPromise: Promise<void> | undefined;
  let cancellationRemoved = false;
  const cancelReceiveTransfer = (remote = false): Promise<void> => {
    if (cancellationPromise) return cancellationPromise;
    cancellationRequested = true;
    releaseProtocolResources();
    cancellationPromise = (async () => {
      // If a decrypt/store was already active, let it observe the abort and
      // cross (or decline) its durability boundary first. The worker deletion
      // then queues behind that same root's store lock, leaving no orphan.
      await waitForQueuedMessageFrames(queue, drainingRef);
      if (merkleRootHex === "") return;

      if (remote) {
        cancellationRemoved = await deleteReceiveTransfer(merkleRootHex, {
          roomId,
          fromPeerId: epc.withPeerId,
          incompleteOnly: true,
        });
        if (cancellationRemoved)
          await forgetMappedReceiveMessageKey(epc, roomId, merkleRootHex);
      } else {
        await forgetMappedReceiveMessageKey(epc, roomId, merkleRootHex);
        await deleteReceiveTransfer(merkleRootHex);
        cancellationRemoved = true;
      }
    })();
    return cancellationPromise;
  };
  if (extChannel.label !== "main")
    extChannel.cancelReceiveTransfer = () => cancelReceiveTransfer();

  // extChannel.onclosing = () => {
  //   debugLog(`Channel with label ${extChannel.label} is closing.`);
  // };

  extChannel.onclose = async () => {
    debugLog(`Channel with label ${extChannel.label} has closed.`);

    // protocol-v3: the receive path no longer pre-allocates box wasm scratch on
    // the channel (decrypt is per-frame via the ratchet), so there is nothing to
    // free here. The per-edge ratchet state + messageKey cache live on `epc` and
    // are reclaimed on peer teardown, not per per-message channel.

    // A scheduled cover lane closes at EVERY fixed cycle boundary regardless of
    // transfer state — never a cancel. Drop it from the cover set; if it
    // carried a now-complete real message, durably retire that receive key.
    if (isCoverLane) {
      releaseAuxiliaryResources();
      await waitForQueuedMessageFrames(queue, drainingRef);
      if (merkleRootHex !== "") {
        try {
          const progress = await getDBMessageData(merkleRootHex);
          await forgetCompletedReceiveMessageKey(
            epc,
            roomId,
            merkleRootHex,
            progress,
          );
        } catch (error) {
          console.error(error);
        }
      }
      releaseProtocolResources();
      return;
    }

    if (extChannel.label === "main") {
      releaseProtocolResources();
      if (epc.handshakeTerminalFailure !== undefined) {
        // The handshake failed for a reason no fresh transport can fix, and the
        // catch has already closed both the channel and the transport. Tearing
        // the edge down here would additionally deletePeer, which is what drops
        // a rejected joiner from the roster before the app can attach the
        // failure to anyone.
        return;
      }
      if (
        ratchetGateLease &&
        !isCurrentRatchetGateLease(roomId, epc.withPeerId, ratchetGateLease)
      )
        return;
      if (handshakeLease)
        clearHandshakeChannel(
          roomId,
          epc.withPeerId,
          new Error("Main data channel closed"),
          handshakeLease,
        );
      // The main channel owns the authenticated ratchet transport. Losing it
      // invalidates every message channel on this room/peer edge; tear the
      // entire edge down so reconnect creates a fresh gate + handshake.
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate({
          roomId,
          peerId: epc.withPeerId,
        }),
      );
      // A main that closed on its own is a transport failure (a deliberate
      // disconnect nulls this handler before closing, and a replaced
      // transport's stale lease returned above), so re-dial under the
      // dedicated "redial" budget: the "join" budget may have just been
      // consumed by a socket reconnect's roster request, which would swallow
      // the one re-dial that can rebuild this edge.
      requestPeersAfterEdgeTeardown(api, roomId);
    } else {
      if (!dataChannels.includes(extChannel)) return;
      // SCTP delivers queued `message` events before `close`, but our decrypt /
      // durable-store work is asynchronous. Do not mistake a normal sender FIN
      // for CANCEL merely because those already-delivered frames are still
      // draining locally.
      releaseAuxiliaryResources();
      await waitForQueuedMessageFrames(queue, drainingRef);
      let deleteIncompleteReceive = false;
      let receiveProgress:
        Awaited<ReturnType<typeof getDBMessageData>> | undefined;
      if (cancellationRequested) {
        try {
          await cancellationPromise;
          deleteIncompleteReceive = cancellationRemoved;
        } catch (error) {
          console.error(error);
        }
      } else if (merkleRootHex !== "") {
        try {
          receiveProgress = await getDBMessageData(merkleRootHex);
          const authenticatedTransportStillAlive =
            epc.connectionState === "connected" &&
            isCurrentRatchetGateLease(
              roomId,
              epc.withPeerId,
              transportGateLease,
            );
          // ONE assignment, deliberately: both reasons to call a close a cancel
          // share the same two disqualifiers, and a second branch that set this
          // flag independently is how the local-close test came to be missing
          // from one of them.
          //
          // - A close THIS side performed is never the peer cancelling. Our own
          //   guards close this channel (pre-authentication, receipt-queue
          //   budget, receive-queue budget) and the sender already refuses to
          //   read those as a cancel (isAuthenticatedPeerCancel); the receiver
          //   must refuse too, or our own guard deletes our own partial file.
          //   This is the one direction the marker CAN discriminate: it is
          //   RAM-local and never transmitted, so it says nothing about a close
          //   the PEER performed.
          // - In scheduled-cover mode a lane closes at every fixed cycle
          //   boundary regardless of transfer state, so a channel close is
          //   NEVER the cancel signal — an explicit encrypted CANCEL cover cell
          //   is. Only an immediate-mode live-edge close means remote cancel.
          deleteIncompleteReceive =
            !wasChannelClosedLocally(extChannel) &&
            !immediateCloseMeansPause(extChannel) &&
            epc.coverRuntime === undefined &&
            (isRemoteCancelClose(
              receiveProgress,
              epc.withPeerId,
              authenticatedTransportStillAlive,
            ) ||
              // An authenticated key may have advanced before the first storage
              // write. A live-edge close still cancels that zero-byte transfer.
              (!receiveProgress &&
                authenticatedTransportStillAlive &&
                (epc.messageKeyByMerkleRoot?.has(merkleRootHex) ?? false)));
        } catch (error) {
          // Preserve partial state on storage uncertainty; a reconnect can still
          // resume it, while deleting here would be irreversible.
          console.error(error);
          deleteIncompleteReceive = false;
        }
      }
      if (deleteIncompleteReceive) {
        try {
          await cancelReceiveTransfer(true);
          deleteIncompleteReceive = cancellationRemoved;
        } catch (error) {
          console.error(error);
          deleteIncompleteReceive = false;
        }
      } else {
        if (merkleRootHex !== "") {
          try {
            await forgetCompletedReceiveMessageKey(
              epc,
              roomId,
              merkleRootHex,
              receiveProgress,
            );
          } catch (error) {
            // Keep the RAM binding when durable retirement fails. Peer teardown
            // still wipes it, and the durable key remains resumable meanwhile.
            console.error(error);
          }
        }
        releaseProtocolResources();
      }
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          roomId,
          peerId: epc.withPeerId,
          label: extChannel.label,
          channel: extChannel,
          alsoDeleteData: deleteIncompleteReceive,
        }),
      );
    }
  };

  extChannel.onerror = async (e) => {
    console.error(e);

    if (extChannel.label === "main") {
      if (
        ratchetGateLease &&
        !isCurrentRatchetGateLease(roomId, epc.withPeerId, ratchetGateLease)
      )
        return;
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate({
          roomId,
          peerId: epc.withPeerId,
        }),
      );
    } else {
      if (!dataChannels.includes(extChannel)) {
        releaseProtocolResources();
        if (extChannel.readyState !== "closed") extChannel.close();
        return;
      }
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          roomId,
          peerId: epc.withPeerId,
          label: extChannel.label,
          channel: extChannel,
        }),
      );
    }

    // Either teardown above may have closed the whole edge (a main error
    // always does; a per-message channel error does once the peer has no
    // channel left), and disconnectFromPeer nulls every handler before
    // closing, so this is the only re-dial the edge gets. It goes under the
    // dedicated "redial" budget for the same reason main's onclose does: the
    // "join" budget may have just been consumed by a socket reconnect's
    // roster request. A replaced transport's stale lease returned above.
    requestPeersAfterEdgeTeardown(api, roomId);
  };

  // Bytes currently pinned by frames parked waiting for this transport's gate
  // to settle. The guard below used to close on the FIRST early frame, so an
  // unauthenticated peer could pin one frame's memory; parking must not turn
  // that into an unbounded amount. Counted in bytes because the frames that
  // legitimately arrive early are 65-byte receipts by the thousand while the
  // frames a flooder would send are 65,490-byte cells.
  let parkedPreAuthBytes = 0;
  extChannel.onmessage = async (e) => {
    const data = new Uint8Array(e.data as ArrayBuffer);
    if (
      extChannel.label !== "main" &&
      !isRatchetGateOpen(roomId, epc.withPeerId, transportGateLease)
    ) {
      // A resumed channel can carry the peer's replayed receipts before THIS
      // side's gate has settled: both gates open inside an async IndexedDB
      // persist, and the identity responder completes on SENDING finish while
      // the initiator completes on RECEIVING it. Closing here was read back as
      // the peer's CANCEL and destroyed both sides' partial transfer (C7), so
      // park a frame whose gate is merely pending. A stale lease, a rejected
      // gate and an exhausted park budget all still close, exactly as before;
      // an exhausted park CEILING drops the frame instead, because a close
      // there would be the same deletion by another route (C-1).
      //
      // What parking THIS frame costs: its own bytes, or the fixed cost of a
      // suspended handler and its timer, whichever is larger.
      const parkCost = Math.max(
        data.length,
        PARKED_PRE_AUTH_FRAME_OVERHEAD_BYTES,
      );
      parkedPreAuthBytes += parkCost;
      let decision: PreAuthFrameDecision;
      try {
        decision = await admitPreAuthenticatedFrame(
          roomId,
          epc.withPeerId,
          transportGateLease,
          PRE_AUTH_FRAME_PARK_MS,
          parkedPreAuthBytes,
        );
      } finally {
        parkedPreAuthBytes -= parkCost;
      }
      // Dropping bounds the pinned memory exactly as closing did, without
      // emitting anything the peer can mistake for a cancellation. The peer
      // resends whatever this frame carried.
      if (decision === "drop") return;
      if (decision === "close") {
        console.error("Rejected application data before peer authentication");
        releaseProtocolResources();
        markChannelClosedLocally(extChannel);
        if (extChannel.readyState !== "closed") extChannel.close();
        return;
      }
    }

    const classified = classifyFrame(data);
    if (classified.type === FRAME_TYPE_IMMEDIATE_DISPOSITION) {
      if (
        !isCoverLane &&
        merkleRootHex !== "" &&
        acceptImmediateDisposition(extChannel, data) === "cancel"
      ) {
        // The sender observes the channel-scoped flag when close wakes its
        // reconcile loop. Do not abort other recipients of the same send.
        try {
          // The worker rechecks after queued writes drain: a completed file or
          // a local self-copy is never removable by a remote cancellation.
          await cancelReceiveTransfer(true);
        } catch (error) {
          console.error("Could not retire cancelled incoming transfer", error);
        } finally {
          if (extChannel.readyState !== "closed") extChannel.close();
        }
      }
      return;
    }
    if (extChannel.label !== "main" && classified.type === FRAME_TYPE_RECEIPT) {
      const accepted = enqueueReceipt(
        classified.payload,
        receiptQueue,
        async (receipt) => {
          if (!isRatchetGateOpen(roomId, epc.withPeerId, transportGateLease))
            return;
          await handleReadReceipt(
            receipt,
            extChannel.label,
            extChannel.withPeerId,
            roomId,
            api,
          );
        },
      );
      if (!accepted) {
        console.error(
          "Closing message DataChannel: receipt queue budget exceeded",
        );
        releaseProtocolResources();
        markChannelClosedLocally(extChannel);
        if (extChannel.readyState !== "closed") extChannel.close();
      }

      return;
    }

    // protocol-v3 message-chunk frame: leading FRAME_TYPE_CHUNK tag + the exact
    // v3 wire length (header 62 ‖ ciphertext DECRYPTED_LEN ‖ AEAD tag 16 = 65490,
    // 46B shorter than the box scheme's MESSAGE_LEN frame).
    if (
      classified.type === FRAME_TYPE_CHUNK &&
      data.length === WIRE_CHUNK_FRAME_LEN
    ) {
      const accepted = enqueue(
        data,
        queue,
        seen,
        drainingRef,
        api,
        roomId,
        extChannel.withPeerId,
        channelLabel,
        merkleRootHex,
        merkleRoot,
        extChannel,
        epc,
        epc.receiveMessageModule,
        receiveAbort.signal,
      );
      if (!accepted) {
        console.error(
          "Closing message DataChannel: receive queue budget exceeded",
        );
        releaseProtocolResources();
        markChannelClosedLocally(extChannel);
        if (extChannel.readyState !== "closed") extChannel.close();
      }

      return;
    }

    // protocol-v4 sparse-PQ control cells ride the authenticated persistent
    // `main` channel in immediate mode and substitute into cover lanes in a
    // scheduled room. The full 65,490-byte cell — including its type byte — is
    // the AEAD-authenticated unit, so the orchestrator receives the unstripped
    // frame. Routing requires the open ratchet gate: control cells are
    // meaningless before the edge is authenticated.
    if (
      (extChannel.label === "main" || isCoverLane) &&
      classified.type === FRAME_TYPE_PQ_CONTROL &&
      data.length === WIRE_CHUNK_FRAME_LEN
    ) {
      if (!isRatchetGateOpen(roomId, epc.withPeerId, transportGateLease)) {
        console.error("Rejected PQ control cell before peer authentication");
        return;
      }
      void handleInboundPqControlFrame(epc, roomId, data);
      return;
    }

    // protocol-v4 scheduled cover cells (dummy / CANCEL / scheduled receipt)
    // ride the peer's cover lanes. The CoverRuntime authenticates each cell
    // before its subtype exists and dispatches CANCEL/receipt bound to the
    // transfer root; an unauthentic cell is dropped. Only present on scheduled
    // room edges.
    if (
      classified.type === FRAME_TYPE_COVER &&
      data.length === WIRE_CHUNK_FRAME_LEN &&
      epc.coverRuntime
    ) {
      if (!isRatchetGateOpen(roomId, epc.withPeerId, transportGateLease)) {
        console.error("Rejected cover cell before peer authentication");
        return;
      }
      epc.coverRuntime.processInboundCoverCell(data);
      return;
    }

    // protocol-v3 handshake frames ride the persistent `main` channel only and
    // carry a leading 1-byte FRAME_TYPE_HANDSHAKE tag. Per-message channels
    // never carry these.
    if (extChannel.label === "main") {
      const { type, payload } = classified;
      if (type === FRAME_TYPE_HANDSHAKE) {
        if (
          handshakeLease &&
          !deliverHandshakeFrame(
            roomId,
            epc.withPeerId,
            payload,
            handshakeLease,
          )
        ) {
          console.error(
            "Closing main DataChannel: malformed or surplus handshake frame",
          );
          releaseProtocolResources();
          if (extChannel.readyState !== "closed") extChannel.close();
        }
        return;
      }
    }

    console.error(new Error("Wrong data length received"));
  };

  extChannel.onopen = () => {
    if (
      extChannel.label !== "main" &&
      !isCurrentRatchetGateLease(roomId, epc.withPeerId, transportGateLease)
    ) {
      releaseProtocolResources();
      if (extChannel.readyState !== "closed") extChannel.close();
      return;
    }
    debugLog(
      `Channel with label "${extChannel.label}" and client ${epc.withPeerId} is open.`,
    );

    if (!dataChannels.includes(extChannel)) dataChannels.push(extChannel);

    if (merkleRootHex === "" && channelLabel.length > 0) {
      api.dispatch(
        setChannel({ roomId, label, peerId: extChannel.withPeerId }),
      );
    }

    // protocol-v3: no box wasm scratch is pre-allocated on the channel anymore —
    // the receive path decrypts each v3 chunk frame per-frame off the peer's
    // ratchet (handleReceiveMessage → decryptMessageChunk), allocating its own
    // transient wasm buffers inside the receiveMessageModule per call. The peer's
    // Ed25519 pub / our secret key are no longer needed on the receive hot path
    // (the ratchet AEAD replaces the box asymmetric decrypt + signature check).

    // protocol-v3: drive the authenticated hybrid-PQ + Double-Ratchet
    // handshake
    // ONLY on the persistent `main` channel (per-message channels carry no
    // handshake frames). Register this channel as the peer's handshake inbox,
    // build the byte-identical channel-input (CI) transcript, then fire-and-forget
    // runHandshake — it verifies the DTLS fingerprints, runs the
    // triple-confirmation core,
    // and (only on success) seeds + persists the ratchet and opens the per-peer
    // gate. Any failure tears down this room-peer transport; v3 has no legacy
    // crypto fallback.
    if (extChannel.label === "main") {
      void (async () => {
        let pin: Uint8Array | undefined;
        let pinRoom = false;
        let handshakeStarted = false;
        api.dispatch(
          setPeerHandshakeStatus({
            roomId,
            peerId: epc.withPeerId,
            peerPublicKey: epc.withPeerPublicKey,
            status: "authenticating",
          }),
        );
        try {
          if (!ratchetGateLease || !handshakeLease)
            throw new Error("Main channel has no transport ownership lease");

          const room = rooms[roomIndex];
          if (!room) throw new Error("Handshake room is unavailable");

          if (room.policy.authMode === "pin") {
            pinRoom = true;
            pin = getRoomPin(room.url);
            if (!pin) throw new Error("PIN room has no local PIN");
          }

          if (pinRoom)
            await assertPinAttemptAllowed(roomId, epc.withPeerPublicKey);

          // Role tie-break on the stable Ed25519 identity edge.
          const amInitiator = isIdentityInitiator(
            keyPair.publicKey,
            epc.withPeerPublicKey,
          );
          const selfIdentityEd25519 = hexToUint8Array(keyPair.publicKey);
          const peerIdentityEd25519 = hexToUint8Array(epc.withPeerPublicKey);
          const selfFingerprint = parseFingerprintFromSdp(
            epc.localDescription?.sdp ?? "",
          );
          const peerFingerprint = parseFingerprintFromSdp(
            epc.remoteDescription?.sdp ?? "",
          );
          const policyHash = await hashRoomPolicyV1(room.policy);
          const channelInput = buildChannelInput({
            channelId: buildRoomChannelId(
              room.url,
              extChannel.label,
              policyHash,
            ),
            ikInitiator: amInitiator
              ? selfIdentityEd25519
              : peerIdentityEd25519,
            ikResponder: amInitiator
              ? peerIdentityEd25519
              : selfIdentityEd25519,
            fpInitiator: amInitiator ? selfFingerprint : peerFingerprint,
            fpResponder: amInitiator ? peerFingerprint : selfFingerprint,
            pqMode: room.policy.pqMode,
          });

          handshakeStarted = true;
          await runHandshake(
            epc,
            roomId,
            room.policy.authMode,
            room.policy.pqMode,
            pin ?? null,
            channelInput,
            epc.receiveMessageModule,
            handshakeLease,
            ratchetGateLease,
          );
          // This transport has now proven an authentication, so the in-place
          // re-bind budget it may have spent is refunded: a long-lived edge
          // that legitimately re-binds once per reconnect is never pushed into
          // a replacement, while consecutive re-binds that authenticate
          // nothing still converge on one (decideRemoteTransportChangeResponse).
          epc.remoteTransportRebinds = 0;
          // ...and the deadline that re-bind armed has been met, so it is
          // released here too: an authenticated edge must never be torn down
          // by a timer that only exists to bound a re-bind in progress.
          clearRebindAuthenticationDeadline(epc);
          api.dispatch(
            setPeerHandshakeStatus({
              roomId,
              peerId: epc.withPeerId,
              peerPublicKey: epc.withPeerPublicKey,
              status: "authenticated",
            }),
          );

          // The handshake installed epc.pqHealingState; give it its live
          // WebRTC owner. In immediate mode control cells use this main
          // channel; retry exhaustion or a forked control slot fails the
          // authenticated edge (close → the normal reconnect machinery runs a
          // fresh hybrid handshake — never an epoch/suite fallback).
          installPqHealingOrchestrator(epc, roomId, {
            sendControlFrame: (frame) => {
              if (extChannel.readyState !== "open") return false;
              extChannel.send(frame.buffer as ArrayBuffer);
              return true;
            },
            failEdge: (reason) => {
              console.error(reason);
              if (extChannel.readyState !== "closed") extChannel.close();
              if (epc.connectionState !== "closed") epc.close();
            },
          });

          // In a scheduled-cover room, start the room-phased cover runtime for
          // this edge. It opens exactly `coverLanes` outbound lanes per cycle
          // boundary and continuously emits authenticated dummy cells; real
          // messages / PQ controls / receipts / CANCEL substitute into slots.
          installCoverEdge({
            epc,
            roomId,
            policy: room.policy,
            policyHash,
            amInitiator,
            module: epc.receiveMessageModule,
            onStatusChange: ({ status }) => {
              // Surface starting|active|degraded|suspended|stopped so a UI can
              // show live cover state and never claim cover during a browser
              // gap. Fires on every transition including the terminal
              // "stopped" from edge teardown/reinstall.
              api.dispatch(
                setPeerCoverStatus({
                  roomId,
                  peerId: epc.withPeerId,
                  status,
                }),
              );
            },
          });
          if (pinRoom)
            await clearPinAttempts(roomId, epc.withPeerPublicKey).catch(
              (clearError) => {
                console.error(
                  "Could not clear successful PIN attempt state:",
                  clearError,
                );
              },
            );
        } catch (error) {
          const handshakeError =
            error instanceof Error ? error : new Error(String(error));
          // A superseded attempt owns nothing. When the edge was re-bound IN
          // PLACE for a new remote DTLS certificate
          // (resetEdgeAuthenticationForNewRemoteTransport), the reset rejected
          // this transcript on purpose and handed the edge a fresh gate lease
          // while KEEPING the RTCPeerConnection. The rejection then arrives
          // here on a still-connected transport, so the checks below would
          // read it as a genuine transport failure: a "failed" status over the
          // "authenticating" the reset just set, a close of the connection the
          // reset meant to keep, and a re-dial of an edge that is already
          // healing. Let it die quietly instead — only this concrete channel,
          // which the replacement no longer uses, is closed.
          if (
            ratchetGateLease &&
            !isCurrentRatchetGateLease(roomId, epc.withPeerId, ratchetGateLease)
          ) {
            debugLog(
              `Superseded handshake attempt for ${epc.withPeerId} in ${roomId} failed after its transport was replaced: ${handshakeError.message}`,
            );
            if (extChannel.readyState !== "closed") extChannel.close();
            return;
          }
          // Captured before this catch closes anything: a transport that is
          // ALREADY closed here was torn down by someone else while the
          // handshake was in flight (a deliberate disconnectFromPeer, purge or
          // leave, an address-book removal, a grace-timer or ICE-failure
          // teardown, or the replacement of a stale transport), and that
          // teardown rejected the handshake as a side effect. Such a path
          // owns the peer's status (deletePeer already dropped it with the
          // roster entry) and its own follow-up, so this catch must neither
          // record a "failed" status for a peer no longer on the roster nor
          // re-dial an edge the user may have just dropped on purpose. A
          // genuine handshake failure always finds the transport still open.
          const transportAlreadyClosed = epc.connectionState === "closed";
          if (
            pinRoom &&
            handshakeStarted &&
            /key-confirmation/i.test(handshakeError.message)
          ) {
            await recordPinFailure(roomId, epc.withPeerPublicKey).catch(
              (backoffError) => {
                console.error(
                  "Could not persist PIN attempt state:",
                  backoffError,
                );
              },
            );
          }
          // Surface WHY the edge failed so a UI never shows an eternal waiting
          // state, and do it from a typed reason rather than a message regex:
          // the framing rejection in deliverHandshakeFrame is a policy/suite
          // disagreement, not a transport fault (C2).
          const { reason: failureReason, retryAfter: classifiedRetryAfter } =
            classifyHandshakeFailure(handshakeError, {
              handshakeStarted,
              pinRoom,
            });
          let retryAfter = classifiedRetryAfter;
          if (failureReason === "pin-mismatch" && pinRoom) {
            try {
              const attemptState = await getPinAttemptState(
                roomId,
                epc.withPeerPublicKey,
              );
              if (attemptState && attemptState.retryAfter > Date.now())
                retryAfter = attemptState.retryAfter;
            } catch {
              // Backoff state is advisory; the failure reason still lands.
            }
          }
          if (!transportAlreadyClosed)
            api.dispatch(
              setPeerHandshakeStatus({
                roomId,
                peerId: epc.withPeerId,
                peerPublicKey: epc.withPeerPublicKey,
                status: "failed",
                reason: failureReason,
                retryAfter,
              }),
            );
          if (ratchetGateLease)
            rejectRatchetGate(
              roomId,
              epc.withPeerId,
              handshakeError,
              ratchetGateLease,
            );
          if (handshakeLease)
            clearHandshakeChannel(
              roomId,
              epc.withPeerId,
              handshakeError,
              handshakeLease,
            );
          console.error("protocol-v4 handshake failed:", handshakeError);
          if (isTerminalHandshakeFailure(failureReason)) {
            // A PIN or policy mismatch fails identically on every fresh
            // transport, so this teardown must not produce a re-dial. Detach
            // the handlers BEFORE closing, exactly as disconnectFromPeerQuery
            // does: with them attached the close event ran main.onclose, whose
            // only guard is the ratchet-gate lease — and rejectRatchetGate does
            // not replace that lease, so the guard passed and :422 re-dialled
            // unconditionally, walking the PIN backoff to its 300 s cap.
            epc.handshakeTerminalFailure = failureReason;
            // This onclose detach has no falsifying test of its own: the
            // main.onclose guard above (`epc.handshakeTerminalFailure !==
            // undefined`) already covers the case where onclose fires after
            // this line, and that guard's behaviour is pinned by its own
            // test. Kept anyway as defence in depth — if the guard is ever
            // removed or broken, losing this line too means the edge
            // re-dials forever against a peer that can never accept.
            extChannel.onclose = null;
            // onerror has no equivalent guard, so this detach is load-bearing
            // on its own; it is covered by a behavioural test.
            extChannel.onerror = null;
          }
          if (extChannel.readyState !== "closed") extChannel.close();
          if (epc.connectionState !== "closed") epc.close();
          // pc.close() fires no connectionstatechange, so no transport-level
          // follow-up ever re-dials for this edge; the main onclose above may
          // run too, and its re-dial then dedups under the same budget. Only
          // a transport failure is worth rebuilding the edge for: a PIN or
          // policy mismatch fails again on any fresh transport and a re-dial
          // would only burn another attempt against the PIN throttle.
          if (failureReason === "transport" && !transportAlreadyClosed)
            requestPeersAfterEdgeTeardown(api, roomId);
        } finally {
          pin?.fill(0);
        }
      })();
    }

    if (incoming && !isCoverLane && merkleRootHex !== "") {
      void awaitAuthenticatedTransport()
        .then((authenticated) => {
          if (authenticated) sendImmediateResumeCapability(extChannel);
        })
        .catch((error) => console.error(error));
    }

    // Resume-on-reconnect (receiver side): a full reconnect hands us a brand-new
    // per-message channel. Re-emit root/index/leaf-bound receipts for chunks we
    // already hold so the sender rebuilds its acked-set and resends ONLY what we
    // are still missing. Guarded to the RECEIVING end of a per-message channel:
    // "main" carries no merkleRoot, and the sender OPENED this channel (string
    // arg) so `channel` is an RTCDataChannel object only on the receiver's end.
    //
    // OBJ-4 CAVEAT (known, deferred): this burst emits one receipt per REAL
    // chunk held (decoys are never stored), so unlike live operation — where
    // every frame, real or decoy, draws a receipt (1:1) — the reconnect burst's
    // length reveals the real-chunk count to a passive DTLS traffic-analysis
    // observer. Same category as the already-deferred obj-4 timing/relay gaps;
    // the obj-4 hardening layer should pace these 1:1 with forward frames or pad
    // with decoy receipts. Content stays confidential (DTLS); only a size hint
    // leaks, only on reconnect.
    if (merkleRootHex !== "" && typeof channel !== "string") {
      void (async () => {
        try {
          if (!(await awaitAuthenticatedTransport())) return;
          const stored = await getDBAllChunkLeafHashes(merkleRootHex);
          if (stored.length === 0) return;

          let receiptBatch: Uint8Array[] = [];
          for (const { chunkIndex, leafHash } of stored) {
            if (leafHash?.length !== crypto_hash_sha512_BYTES * 2) continue;
            receiptBatch.push(
              await createChunkReceiptToken(
                merkleRoot,
                chunkIndex,
                hexToUint8Array(leafHash),
              ),
            );
            if (receiptBatch.length === RECEIPT_REPLAY_BATCH_SIZE) {
              if (!(await sendReceiptFramesPaced(extChannel, receiptBatch)))
                return;
              receiptBatch = [];
            }
          }
          if (
            receiptBatch.length > 0 &&
            !(await sendReceiptFramesPaced(extChannel, receiptBatch))
          )
            return;

          // If we already hold the whole message, re-emit the final message-hash
          // receipt too, so the sender reaches completion and closes cleanly.
          const md = await getDBMessageData(merkleRootHex);
          if (
            md &&
            md.totalSize > 0 &&
            md.savedSize === md.totalSize &&
            md.hash.length === crypto_hash_sha512_BYTES * 2
          ) {
            sendReceiptFrame(extChannel, hexToUint8Array(md.hash));
          }
        } catch (error) {
          console.error(error);
        }
      })();
    }
  };

  return extChannel;
};
