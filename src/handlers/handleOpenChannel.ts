import { handleReadReceipt } from "./handleReadReceipt";
import { enqueue } from "./handleMessageQueueing";
import {
  setHandshakeChannel,
  deliverHandshakeFrame,
  runHandshake,
  buildChannelInput,
  parseFingerprintFromSdp,
} from "./handleHandshake";
import { classifyFrame } from "./frameType";

import webrtcApi from "../api/webrtc";

import { setChannel, setConnectingToPeers } from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { randomNumberInRange } from "../cryptography/utils";
import cryptoMemory from "../cryptography/memory";
import { wasmLoader } from "../cryptography/wasmLoader";

import {
  deleteDBSendQueue,
  getDBSendQueue,
  getDBAllChunkLeafHashes,
  getDBMessageData,
} from "../db/api";

import { hexToUint8Array } from "../utils/uint8array";
import { decompileChannelMessageLabel } from "../utils/channelLabel";
import {
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_HANDSHAKE,
  MAX_BUFFERED_AMOUNT,
  MESSAGE_LEN,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";

// Track last reconnection attempt per room to prevent rapid reconnection loops
const lastReconnectAttempt = new Map<string, number>();
const RECONNECT_DEBOUNCE_MS = 2000;

export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  roomId: string;
  dataChannels: IRTCDataChannel[];
}

export const handleOpenChannel = async (
  { channel, epc, roomId, dataChannels }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  const { keyPair, rooms } = api.getState() as State;

  const roomIndex = rooms.findIndex((r) => r.id === roomId);
  let peerRoomIndex = epc.rooms.findLastIndex((r) => r.roomId === roomId);
  if (peerRoomIndex === -1) {
    const wasmMemory = cryptoMemory.getReceiveMessageMemory();
    const receiveMessageModule = await wasmLoader(wasmMemory);
    // const receiveMessageModule = await libcrypto({
    //   wasmMemory,
    // });

    peerRoomIndex = epc.rooms.length;
    epc.rooms.push({
      roomId,
      receiveMessageModule,
    });
  }

  const queue: Uint8Array[] = [];
  const seen = new Set<string>();
  const drainingRef = { value: false };

  if (typeof channel === "string") {
    const channelIndex = dataChannels.findIndex(
      (dc) => dc.label === channel && dc.withPeerId === epc.withPeerId,
    );

    if (channelIndex > -1 && dataChannels[channelIndex].readyState === "open")
      return dataChannels[channelIndex];
  }

  const label = typeof channel === "string" ? channel : channel.label;
  const { channelLabel, merkleRoot, merkleRootHex } =
    await decompileChannelMessageLabel(label);

  const dataChannel =
    typeof channel === "string"
      ? epc.createDataChannel(channel, {
          ordered: false,
          protocol: "raw",
          // negotiated: true,
          // id: dataChannelsWithPeer.length + 1,
          // maxRetransmits: 3,
        })
      : channel;
  dataChannel.binaryType = "arraybuffer";
  dataChannel.bufferedAmountLowThreshold = MESSAGE_LEN;
  dataChannel.onbufferedamountlow = async () => {
    while (dataChannel.readyState === "open") {
      const sendQueue = await getDBSendQueue(label, epc.withPeerId);
      if (sendQueue.length === 0) break;

      while (
        sendQueue.length > 0 &&
        dataChannel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
        (dataChannel.readyState as string) === "open"
      ) {
        let pos = await randomNumberInRange(0, sendQueue.length);
        if (pos === sendQueue.length) pos = 0;

        const [item] = sendQueue.splice(pos, 1);
        if ((dataChannel.readyState as string) === "open") {
          dataChannel.send(item.encryptedData);
          await deleteDBSendQueue(label, epc.withPeerId, item.position);
        }
      }
    }
  };

  const extChannel = dataChannel as IRTCDataChannel;
  extChannel.withPeerId = epc.withPeerId;
  extChannel.roomIds = [roomId];

  // extChannel.onclosing = () => {
  //   console.log(`Channel with label ${extChannel.label} is closing.`);
  // };

  extChannel.onclose = async () => {
    console.log(`Channel with label ${extChannel.label} has closed.`);

    // protocol-v3: the receive path no longer pre-allocates box wasm scratch on
    // the channel (decrypt is per-frame via the ratchet), so there is nothing to
    // free here. The per-edge ratchet state + messageKey cache live on `epc` and
    // are reclaimed on peer teardown, not per per-message channel.

    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
        peerId: epc.withPeerId,
        label: extChannel.label,
      }),
    );

    if (extChannel.label === "main") {
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
    }
  };

  extChannel.onerror = async (e) => {
    console.error(e);

    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
        peerId: epc.withPeerId,
        label: extChannel.label,
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
  };

  extChannel.onmessage = async (e) => {
    const data = new Uint8Array(e.data as ArrayBuffer);

    if (roomIndex > -1 && data.length === crypto_hash_sha512_BYTES) {
      try {
        await handleReadReceipt(
          data,
          extChannel.label,
          extChannel.withPeerId,
          rooms[roomIndex],
          api,
        );
      } catch (error) {
        console.error(error);
      }

      return;
    }

    // protocol-v3 message-chunk frame: leading FRAME_TYPE_CHUNK tag + the exact
    // v3 wire length (header 62 ‖ ciphertext DECRYPTED_LEN ‖ AEAD tag 16 = 65490,
    // 46B shorter than the box scheme's MESSAGE_LEN frame). The 64B receipt test
    // above runs first, so a receipt whose first byte happens to be
    // FRAME_TYPE_CHUNK is never misrouted here.
    if (data.length === WIRE_CHUNK_FRAME_LEN && data[0] === FRAME_TYPE_CHUNK) {
      enqueue(
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
        epc.rooms[peerRoomIndex].receiveMessageModule,
      );

      return;
    }

    // protocol-v3 handshake frames ride the persistent `main` channel only and
    // carry a leading 1-byte FRAME_TYPE_HANDSHAKE tag. Their framed lengths
    // (HELLO 194B, CONFIRM 98B) never equal the 64B receipt or the v3 chunk
    // frame, so they only ever reach here. Strip exactly the 1-byte tag and hand
    // the payload to the waiting runHandshake; per-message channels never carry
    // these.
    if (extChannel.label === "main") {
      const { type, payload } = classifyFrame(data);
      if (type === FRAME_TYPE_HANDSHAKE) {
        deliverHandshakeFrame(epc.withPeerId, payload);
        return;
      }
    }

    console.error(new Error("Wrong data length received"));
  };

  extChannel.onopen = () => {
    console.log(
      `Channel with label "${extChannel.label}" and client ${epc.withPeerId} is open.`,
    );

    dataChannels.push(extChannel);

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

    // protocol-v3 (Stage 4/5): drive the PACE + Double-Ratchet handshake, but
    // ONLY on the persistent `main` channel (per-message channels carry no
    // handshake frames). Register this channel as the peer's handshake inbox,
    // build the byte-identical channel-input (CI) transcript, then fire-and-forget
    // runHandshake — it verifies the DTLS fingerprints, runs the two-round core,
    // and (only on success) seeds + persists the ratchet and opens the per-peer
    // gate; on any failure it rejects that gate internally. A handshake failure
    // MUST NOT throw out of onopen or disturb the still-live box-scheme
    // messaging, so the CI construction is wrapped and the promise is
    // `.catch`-logged. The ratchet is seeded here but NOT yet used for messages
    // (swapping messages onto it is Stage 5).
    if (extChannel.label === "main") {
      try {
        setHandshakeChannel(epc.withPeerId, extChannel);

        // Role tie-break on the STABLE Ed25519 identity edge — the SAME rule
        // runHandshake applies — so both peers assign initiator/responder
        // identically and thus build a byte-identical CI.
        const amInitiator = keyPair.publicKey < epc.withPeerPublicKey;
        const selfIdentityEd25519 = hexToUint8Array(keyPair.publicKey);
        const peerIdentityEd25519 = hexToUint8Array(epc.withPeerPublicKey);

        // DTLS fingerprints straight from each side's SDP: self = local
        // description, peer = remote description. parseFingerprintFromSdp throws
        // on a missing/malformed fingerprint, caught below (fail-safe).
        const selfFingerprint = parseFingerprintFromSdp(
          epc.localDescription?.sdp ?? "",
        );
        const peerFingerprint = parseFingerprintFromSdp(
          epc.remoteDescription?.sdp ?? "",
        );

        // CI = channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG (a=initiator,
        // b=responder). channelId = the shared "main" label both peers agree on.
        const channelInput = buildChannelInput({
          channelId: new TextEncoder().encode(extChannel.label),
          ikInitiator: amInitiator ? selfIdentityEd25519 : peerIdentityEd25519,
          ikResponder: amInitiator ? peerIdentityEd25519 : selfIdentityEd25519,
          fpInitiator: amInitiator ? selfFingerprint : peerFingerprint,
          fpResponder: amInitiator ? peerFingerprint : selfFingerprint,
        });

        void runHandshake(
          epc,
          "nopin",
          null,
          channelInput,
          epc.rooms[peerRoomIndex].receiveMessageModule,
        ).catch((error) => {
          // The per-peer ratchet gate is already rejected internally and nothing
          // was persisted; box-scheme messaging is unaffected, so log only.
          console.error("protocol-v3 handshake failed:", error);
        });
      } catch (error) {
        console.error("protocol-v3 handshake wiring failed:", error);
      }
    }

    // Resume-on-reconnect (receiver side): a full reconnect hands us a brand-new
    // per-message channel. Re-emit the leaf-hash receipts for the chunks we
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
          const stored = await getDBAllChunkLeafHashes(merkleRootHex);
          if (stored.length === 0) return;

          for (const { leafHash } of stored) {
            if (leafHash?.length !== crypto_hash_sha512_BYTES * 2) continue;
            // Backpressure: let the SCTP buffer drain (and yield the event loop
            // so drain callbacks run) instead of racing the ~16 MiB send cap on
            // a large have-set.
            while (
              extChannel.readyState === "open" &&
              extChannel.bufferedAmount >= MAX_BUFFERED_AMOUNT
            ) {
              await new Promise((resolve) => setTimeout(resolve, 0));
            }
            if (extChannel.readyState !== "open") return;
            extChannel.send(hexToUint8Array(leafHash).buffer);
          }

          // If we already hold the whole message, re-emit the final message-hash
          // receipt too, so the sender reaches completion and closes cleanly.
          const md = await getDBMessageData(merkleRootHex);
          if (
            md &&
            md.totalSize > 0 &&
            md.savedSize === md.totalSize &&
            md.hash.length === crypto_hash_sha512_BYTES * 2 &&
            extChannel.readyState === "open"
          ) {
            extChannel.send(hexToUint8Array(md.hash).buffer);
          }
        } catch (error) {
          console.error(error);
        }
      })();
    }
  };

  return extChannel;
};
