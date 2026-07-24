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

import webrtcApi from "../api/webrtc";

import { setChannel, setConnectingToPeers } from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import {
  deleteReceiveTransfer,
  getDBAllChunkLeafHashes,
  getDBMessageData,
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
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_RECEIPT,
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

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";
import type { HandshakeLease } from "./handleHandshake";
import type { RatchetGateLease } from "./ratchetGate";

// Track last reconnection attempt per room to prevent rapid reconnection loops
const lastReconnectAttempt = new Map<string, number>();
const RECONNECT_DEBOUNCE_MS = 2000;
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
          protocol: "raw",
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
  if (extChannel.label !== "main") {
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
    if (epc.mainChannel === extChannel) epc.mainChannel = undefined;
    if (handshakeLease)
      clearHandshakeChannel(roomId, epc.withPeerId, labelError, handshakeLease);
    if (extChannel.readyState !== "closed") extChannel.close();
    throw labelError;
  }
  const { channelLabel, merkleRoot, merkleRootHex } = parsedLabel;

  let resourcesReleased = false;
  let auxiliaryResourcesReleased = false;
  const releaseAuxiliaryResources = (): void => {
    if (auxiliaryResourcesReleased) return;
    auxiliaryResourcesReleased = true;
    releaseQueuedReceipts(receiptQueue);
    epc.messageChannels?.delete(extChannel);
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
  const cancelReceiveTransfer = (): Promise<void> => {
    if (cancellationPromise) return cancellationPromise;
    cancellationRequested = true;
    releaseProtocolResources();
    cancellationPromise = (async () => {
      // If a decrypt/store was already active, let it observe the abort and
      // cross (or decline) its durability boundary first. The worker deletion
      // then queues behind that same root's store lock, leaving no orphan.
      await waitForQueuedMessageFrames(queue, drainingRef);
      if (merkleRootHex === "") return;

      await forgetMappedReceiveMessageKey(epc, roomId, merkleRootHex);
      await deleteReceiveTransfer(merkleRootHex);
    })();
    return cancellationPromise;
  };
  if (extChannel.label !== "main")
    extChannel.cancelReceiveTransfer = cancelReceiveTransfer;

  // extChannel.onclosing = () => {
  //   console.log(`Channel with label ${extChannel.label} is closing.`);
  // };

  extChannel.onclose = async () => {
    console.log(`Channel with label ${extChannel.label} has closed.`);

    // protocol-v3: the receive path no longer pre-allocates box wasm scratch on
    // the channel (decrypt is per-frame via the ratchet), so there is nothing to
    // free here. The per-edge ratchet state + messageKey cache live on `epc` and
    // are reclaimed on peer teardown, not per per-message channel.

    if (extChannel.label === "main") {
      releaseProtocolResources();
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
      // Debounce reconnection attempts to prevent rapid loops
      const now = Date.now();
      const lastAttempt = lastReconnectAttempt.get(roomId) ?? 0;
      if (now - lastAttempt > RECONNECT_DEBOUNCE_MS) {
        lastReconnectAttempt.set(roomId, now);
        api.dispatch(setConnectingToPeers({ roomId, connectingToPeers: true }));
      } else {
        console.log(
          `Skipping reconnection for ${roomId} - debounce (${String(now - lastAttempt)}ms since last)`,
        );
      }
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
          deleteIncompleteReceive = true;
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
          deleteIncompleteReceive = isRemoteCancelClose(
            receiveProgress,
            epc.withPeerId,
            authenticatedTransportStillAlive,
          );
          // An authenticated key may have advanced before the first storage
          // write. A live-edge close still cancels that zero-byte transfer.
          if (
            !receiveProgress &&
            authenticatedTransportStillAlive &&
            epc.messageKeyByMerkleRoot?.has(merkleRootHex)
          )
            deleteIncompleteReceive = true;
        } catch (error) {
          // Preserve partial state on storage uncertainty; a reconnect can still
          // resume it, while deleting here would be irreversible.
          console.error(error);
          deleteIncompleteReceive = false;
        }
      }
      if (deleteIncompleteReceive) {
        try {
          await cancelReceiveTransfer();
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

    // Debounce reconnection attempts to prevent rapid loops
    const now = Date.now();
    const lastAttempt = lastReconnectAttempt.get(roomId) ?? 0;
    if (now - lastAttempt > RECONNECT_DEBOUNCE_MS) {
      lastReconnectAttempt.set(roomId, now);
      api.dispatch(setConnectingToPeers({ roomId, connectingToPeers: true }));
    } else {
      console.log(
        `Skipping reconnection for ${roomId} - debounce (${String(now - lastAttempt)}ms since last)`,
      );
    }
  };

  extChannel.onmessage = async (e) => {
    const data = new Uint8Array(e.data as ArrayBuffer);
    if (
      extChannel.label !== "main" &&
      !isRatchetGateOpen(roomId, epc.withPeerId, transportGateLease)
    ) {
      console.error("Rejected application data before peer authentication");
      releaseProtocolResources();
      if (extChannel.readyState !== "closed") extChannel.close();
      return;
    }

    const classified = classifyFrame(data);
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
        if (extChannel.readyState !== "closed") extChannel.close();
      }

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
    console.log(
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
          console.error("protocol-v3 handshake failed:", handshakeError);
          if (extChannel.readyState !== "closed") extChannel.close();
          if (epc.connectionState !== "closed") epc.close();
        } finally {
          pin?.fill(0);
        }
      })();
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
