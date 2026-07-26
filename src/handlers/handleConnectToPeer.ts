import { debugLog } from "../utils/debug";
import { isUUID } from "class-validator";

import { handleQueuedIceCandidates } from "./handleQueuedIceCandidates";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";
import {
  findRoomIdentityAliases,
  findRoomPeerConnection,
} from "../api/webrtc/roomPeer";
import {
  getRoomIdentityMutex,
  releaseRoomIdentityMutex,
} from "../api/webrtc/negotiationLock";

import { defaultRTCConfig, setPeer } from "../reducers/roomSlice";

import cryptoMemory from "../cryptography/memory";
import { wasmLoader } from "../cryptography/wasmLoader";
import { resetRatchetGate } from "./ratchetGate";
import { claimRatchetPersistence } from "./ratchetPersist";
import { assertCanonicalEd25519Identity } from "../utils/identityRole";
import { PROTOCOL_VERSION } from "../utils/constants";
// import libcrypto from "../cryptography/libcrypto";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  RTCPeerConnectionParams,
} from "../api/webrtc/interfaces";
import type {
  WebSocketMessageDescriptionSend,
  WebSocketMessageCandidateSend,
} from "../utils/interfaces";

export interface IRTCPeerConnectionParams extends RTCPeerConnectionParams {
  peerConnections: IRTCPeerConnection[];
}

export const handleConnectToPeer = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    peerConnections,
    rtcConfig,
  }: IRTCPeerConnectionParams,
  api: BaseQueryApi,
): Promise<IRTCPeerConnection> => {
  const { keyPair, signalingServer } = api.getState() as State;

  rtcConfig ??= defaultRTCConfig;

  if (!isUUID(peerId)) throw new Error("PeerId is not a valid uuidv4");
  assertCanonicalEd25519Identity(keyPair.publicKey, "Self Ed25519 identity");
  assertCanonicalEd25519Identity(peerPublicKey, "Peer Ed25519 identity");
  if (peerPublicKey === keyPair.publicKey)
    throw new Error("Cannot connect to the same Ed25519 identity");

  const identityMutex = getRoomIdentityMutex(roomId, peerPublicKey);
  await identityMutex.acquire();
  try {
  // The signaling peerId may rotate, but a room may have only one live
  // transport for a stable Ed25519 identity. Tear down aliases before claiming
  // the edge's durable ratchet owner.
  const aliases = findRoomIdentityAliases(
    peerConnections,
    roomId,
    peerId,
    peerPublicKey,
  );
  for (const alias of aliases) {
    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({
        roomId,
        peerId: alias.withPeerId,
      }),
    );
  }

  let existing = findRoomPeerConnection(peerConnections, roomId, peerId);
  if (existing && existing.withPeerPublicKey !== peerPublicKey) {
    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({ roomId, peerId }),
    );
    existing = undefined;
  }
  if (existing) {
    await existing.initialization;
    return existing;
  }

  // A reconnect is a new cryptographic transport and must never inherit the
  // previous connection's resolved/rejected handshake promise.
  const ratchetGateLease = resetRatchetGate(
    roomId,
    peerId,
    new Error("Ratchet transport replaced by a new room/peer connection"),
  );

  const pc = new RTCPeerConnection(rtcConfig);
  const epc = pc as IRTCPeerConnection;
  epc.roomId = roomId;
  epc.withPeerId = peerId;
  epc.withPeerPublicKey = peerPublicKey;
  epc.makingOffer = false;
  epc.ignoreOffer = false;
  epc.iceCandidates = [] as RTCIceCandidateInit[];
  epc.ratchetGateLease = ratchetGateLease;
  // Claim the durable stable-identity edge before any await. This invalidates a
  // replaced connection's queued handshake/send writes immediately, rather
  // than waiting until the new main-channel handshake succeeds.
  claimRatchetPersistence(epc, roomId);
  // Reserve the transport synchronously before the first await. Two signaling
  // aliases for one stable identity therefore cannot both observe an empty
  // registry and become live ratchet owners.
  peerConnections.push(epc);

  const assertStillReserved = (): void => {
    if (!peerConnections.includes(epc))
      throw new Error("WebRTC transport was replaced during initialization");
  };
  const initialization = (async (): Promise<void> => {
    const receiveMessageWasmMemory = cryptoMemory.protocolV3Memory();
    const receiveMessageModule = await wasmLoader(receiveMessageWasmMemory);
    assertStillReserved();
    epc.receiveMessageModule = receiveMessageModule;

    if (signalingServer.isConnected) {
      await api.dispatch(
        signalingServerApi.endpoints.connectWithPeer.initiate({
          roomId,
          peerId,
          peerPublicKey,
        }),
      );
      assertStillReserved();
    }
  })();
  epc.initialization = initialization;
  try {
    await initialization;
  } catch (error) {
    const index = peerConnections.indexOf(epc);
    if (index > -1) peerConnections.splice(index, 1);
    if (epc.connectionState !== "closed") epc.close();
    throw error;
  } finally {
    epc.initialization = undefined;
  }

  epc.onnegotiationneeded = async () => {
    // Don't start a new negotiation if we're already making an offer or not in stable state
    if (epc.makingOffer || epc.signalingState !== "stable") {
      debugLog(
        `Skipping negotiation with ${peerId} - already making offer: ${String(epc.makingOffer)}, state: ${epc.signalingState}`,
      );
      return;
    }

    try {
      epc.makingOffer = true;
      await epc.setLocalDescription();

      if (epc.localDescription) {
        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "description",
              description: epc.localDescription,
              fromPeerId: keyPair.peerId,
              fromPeerPublicKey: keyPair.publicKey,
              toPeerId: peerId,
              roomId,
              protocolVersion: PROTOCOL_VERSION,
            } as WebSocketMessageDescriptionSend,
          }),
        );

        debugLog(
          `Negotiation was needed with ${peerId} and you sent a description ${epc.localDescription.type}.`,
        );
      }
    } catch (error) {
      console.error(error);
    } finally {
      epc.makingOffer = false;
    }
  };

  epc.onicecandidate = async ({ candidate }) => {
    if (candidate && candidate.candidate !== "") {
      await api.dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "candidate",
            candidate,
            fromPeerId: keyPair.peerId,
            toPeerId: peerId,
            roomId,
            protocolVersion: PROTOCOL_VERSION,
          } as WebSocketMessageCandidateSend,
        }),
      );
    }
  };

  epc.onicecandidateerror = (e) => {
    // epc.restartIce();
    console.error(e);
  };

  // Track ICE restart attempts to prevent rapid restarts
  let lastIceRestartTime = 0;
  const ICE_RESTART_DEBOUNCE_MS = 3000;
  let disconnectTimeout: ReturnType<typeof setTimeout> | undefined;

  epc.oniceconnectionstatechange = async () => {
    if (
      epc.iceConnectionState === "failed" ||
      epc.iceConnectionState === "disconnected"
    ) {
      const { signalingServer } = api.getState() as State;
      if (
        !signalingServer.isConnected &&
        !signalingServer.isEstablishingConnection &&
        signalingServer.serverUrl.length > 0
      ) {
        await api.dispatch(
          signalingServerApi.endpoints.connectWebSocket.initiate(
            signalingServer.serverUrl,
          ),
        );
      }

      const now = Date.now();

      if (now - lastIceRestartTime > ICE_RESTART_DEBOUNCE_MS) {
        lastIceRestartTime = now;
        debugLog(`ICE ${epc.iceConnectionState} with ${peerId}, restarting`);
        epc.restartIce();
      }
    }

    debugLog(
      `ICE candidate connection state with ${peerId} is ${epc.iceConnectionState}.`,
    );
  };

  epc.onicegatheringstatechange = () => {
    debugLog(
      `ICE gathering state with ${peerId} is ${epc.iceGatheringState}.`,
    );
  };

  epc.onsignalingstatechange = async () => {
    debugLog(`Signaling state with ${peerId} is ${epc.signalingState}.`);

    if (epc.signalingState === "stable" && epc.remoteDescription)
      await handleQueuedIceCandidates(epc);
  };

  epc.onconnectionstatechange = async () => {
    if (epc.connectionState === "disconnected") {
      if (disconnectTimeout) clearTimeout(disconnectTimeout);
      disconnectTimeout = setTimeout(() => {
        if (epc.connectionState !== "disconnected") return;

        void api.dispatch(
          webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId, roomId }),
        );

        console.error(
          `RTC Connection with peer ${peerId} in room ${roomId} has disconnected.`,
        );
      }, 8000);
    } else if (
      epc.connectionState === "closed" ||
      epc.connectionState === "failed"
    ) {
      if (disconnectTimeout) {
        clearTimeout(disconnectTimeout);
        disconnectTimeout = undefined;
      }

      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId, roomId }),
      );

      console.error(
        `RTC Connection with peer ${peerId} in room ${roomId} has ${epc.connectionState}.`,
      );

      if (epc.connectionState === "closed") {
        const { signalingServer } = api.getState() as State;
        if (signalingServer.isConnected) {
          await api.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "peers",
                fromPeerId: keyPair.peerId,
                roomId,
                protocolVersion: PROTOCOL_VERSION,
              },
            }),
          );
        }
      }
    } else {
      if (disconnectTimeout) {
        clearTimeout(disconnectTimeout);
        disconnectTimeout = undefined;
      }

      if (epc.connectionState === "connected") {
        api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));

        debugLog(
          `RTC Connection status with peer ${peerId} is ${epc.connectionState}.`,
        );

        // if (!initiator) {
        //   const { signalingServer } = api.getState() as State;
        //   if (signalingServer.isConnected) {
        //     api.dispatch(
        //       signalingServerApi.endpoints.sendMessage.initiate({
        //         content: {
        //           type: "peers",
        //           fromPeerId: keyPair.peerId,
        //           roomId,
        //         } as WebSocketMessagePeersRequest,
        //       }),
        //     );
        //   }
        // }
      }
    }
  };

    return epc;
  } finally {
    identityMutex.release();
    releaseRoomIdentityMutex(roomId, peerPublicKey);
  }
};
