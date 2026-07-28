import { debugLog } from "../utils/debug";
import { isUUID } from "class-validator";

import { handleQueuedIceCandidates } from "./handleQueuedIceCandidates";

import signalingServerApi, {
  sendRoomRequestMessage,
} from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";
import { repairIceTransportAfterCandidateFailure } from "../api/webrtc/iceRepair";
import {
  findRoomIdentityAliases,
  findRoomPeerConnection,
} from "../api/webrtc/roomPeer";
import { assertRoomEdgeBudget } from "../api/webrtc/roomEdgeBudget";
import {
  getRoomIdentityMutex,
  getRoomIceConfigurationMutex,
  releaseRoomIdentityMutex,
} from "../api/webrtc/negotiationLock";

import { setPeer } from "../reducers/roomSlice";

import cryptoMemory from "../cryptography/memory";
import { wasmLoader } from "../cryptography/wasmLoader";
import { resetRatchetGate } from "./ratchetGate";
import { claimRatchetPersistence } from "./ratchetPersist";
import { assertCanonicalEd25519Identity } from "../utils/identityRole";
import { assertTransportIdentityCurrent } from "../utils/transportIdentity";
import { PROTOCOL_VERSION } from "../utils/constants";
import { requestRoomFromSignaling } from "./requestRoom";
import { waitForFreshSocketProof } from "../utils/roomRequestCoordinator";
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
  { peerId, peerPublicKey, roomId, peerConnections }: IRTCPeerConnectionParams,
  api: BaseQueryApi,
): Promise<IRTCPeerConnection> => {
  const { keyPair: initialKeyPair } = api.getState() as State;

  if (!isUUID(peerId)) throw new Error("PeerId is not a valid uuidv4");
  assertCanonicalEd25519Identity(
    initialKeyPair.publicKey,
    "Self Ed25519 identity",
  );
  assertCanonicalEd25519Identity(peerPublicKey, "Peer Ed25519 identity");
  if (peerPublicKey === initialKeyPair.publicKey)
    throw new Error("Cannot connect to the same Ed25519 identity");

  const identityMutex = getRoomIdentityMutex(roomId, peerPublicKey);
  await identityMutex.acquire();
  try {
    const requireActiveRoom = () => {
      const room = (api.getState() as State).rooms.find(
        (candidate) =>
          candidate.id === roomId && candidate.signalingActive !== false,
      );
      if (!room)
        throw new Error(
          "Cannot create a WebRTC transport for an inactive room",
        );
      return room;
    };
    requireActiveRoom();

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
      requireActiveRoom();
      if (
        !peerConnections.includes(existing) ||
        existing.connectionState === "closed"
      )
        throw new Error("WebRTC transport was removed during initialization");
      return existing;
    }

    let epc!: IRTCPeerConnection;
    const roomUrl = requireActiveRoom().url;
    const roomIceConfigurationMutex = getRoomIceConfigurationMutex(roomUrl);
    await roomIceConfigurationMutex.acquire();
    try {
      // This is the final read after every preceding DB/mutex await. The room
      // response transaction holds the same mutex from live sweep through
      // Redux publication, so a PC is either swept before insertion or born
      // from the newly published SSOT configuration.
      const currentRoom = requireActiveRoom();
      if (currentRoom.url !== roomUrl)
        throw new Error("Room identity changed during transport creation");
      const currentRtcConfig = currentRoom.rtcConfig;
      const currentKeyPair = (api.getState() as State).keyPair;
      assertTransportIdentityCurrent(
        initialKeyPair.publicKey,
        currentKeyPair.publicKey,
      );
      assertRoomEdgeBudget(
        roomId,
        currentRoom.peers,
        peerConnections,
        peerPublicKey,
      );

      // A reconnect is a new cryptographic transport and must never inherit the
      // previous connection's resolved/rejected handshake promise.
      const ratchetGateLease = resetRatchetGate(
        roomId,
        peerId,
        new Error("Ratchet transport replaced by a new room/peer connection"),
      );

      const pc = new RTCPeerConnection(currentRtcConfig);
      epc = pc as IRTCPeerConnection;
      epc.roomId = roomId;
      epc.withPeerId = peerId;
      epc.withPeerPublicKey = peerPublicKey;
      epc.makingOffer = false;
      epc.ignoreOffer = false;
      epc.iceCandidates = [] as RTCIceCandidateInit[];
      epc.ratchetGateLease = ratchetGateLease;
      epc.ensureFreshIceConfiguration = async (): Promise<boolean> => {
        let state = api.getState() as State;
        const proof = waitForFreshSocketProof(state.signalingServer.isVerified);
        if (
          !state.signalingServer.isConnected &&
          !state.signalingServer.isEstablishingConnection
        ) {
          if (state.signalingServer.serverUrl.length === 0)
            throw new Error(
              "Cannot refresh ICE without a signaling server URL",
            );
          await api.dispatch(
            signalingServerApi.endpoints.connectWebSocket.initiate(
              state.signalingServer.serverUrl,
            ),
          );
        }

        await proof;
        state = api.getState() as State;
        if (
          !state.signalingServer.isConnected ||
          !state.signalingServer.isVerified
        )
          throw new Error("Signaling socket did not complete identity proof");
        const room = state.rooms.find(
          (candidate) =>
            candidate.id === roomId && candidate.signalingActive !== false,
        );
        if (!room) throw new Error("Cannot refresh ICE for an inactive room");

        // The promise resolves only after the correlated response has updated
        // Redux and every live PC in this room.
        await requestRoomFromSignaling(api, room.url, (request) =>
          sendRoomRequestMessage(api, request),
        );
        return true;
      };
      // Claim and registry insertion remain inside the room-config critical
      // section, so a response sweep cannot miss this concrete transport.
      claimRatchetPersistence(epc, roomId);
      peerConnections.push(epc);
    } finally {
      roomIceConfigurationMutex.release();
    }

    const assertStillReserved = (): void => {
      if (!peerConnections.includes(epc))
        throw new Error("WebRTC transport was replaced during initialization");
    };
    const initialization = (async (): Promise<void> => {
      const receiveMessageWasmMemory = cryptoMemory.protocolV3Memory();
      const receiveMessageModule = await wasmLoader(receiveMessageWasmMemory);
      assertStillReserved();
      epc.receiveMessageModule = receiveMessageModule;

      const currentSignaling = (api.getState() as State).signalingServer;
      if (currentSignaling.isConnected && currentSignaling.isVerified) {
        await api
          .dispatch(
            signalingServerApi.endpoints.connectWithPeer.initiate({
              roomId,
              peerId,
              peerPublicKey,
            }),
          )
          .unwrap();
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
          const currentKeyPair = (api.getState() as State).keyPair;
          await api
            .dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "description",
                  description: epc.localDescription,
                  fromPeerId: currentKeyPair.peerId,
                  fromPeerPublicKey: currentKeyPair.publicKey,
                  toPeerId: peerId,
                  roomId,
                  protocolVersion: PROTOCOL_VERSION,
                } as WebSocketMessageDescriptionSend,
              }),
            )
            .unwrap();

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
        const currentKeyPair = (api.getState() as State).keyPair;
        await api
          .dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "candidate",
                candidate,
                fromPeerId: currentKeyPair.peerId,
                toPeerId: peerId,
                roomId,
                protocolVersion: PROTOCOL_VERSION,
              } as WebSocketMessageCandidateSend,
            }),
          )
          .unwrap()
          .catch((error: unknown) => {
            console.warn(
              "p2party: ICE candidate signaling failed",
              error instanceof Error ? error.message : String(error),
            );
          });
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
    let iceRepairInFlight: Promise<"restarted" | "disconnected"> | undefined;
    const repairIce = (): Promise<"restarted" | "disconnected"> => {
      if (iceRepairInFlight) return iceRepairInFlight;
      iceRepairInFlight = repairIceTransportAfterCandidateFailure(
        epc,
        () => undefined,
      ).finally(() => {
        iceRepairInFlight = undefined;
      });
      return iceRepairInFlight;
    };

    epc.oniceconnectionstatechange = async () => {
      if (
        epc.iceConnectionState === "failed" ||
        epc.iceConnectionState === "disconnected"
      ) {
        const now = Date.now();

        if (now - lastIceRestartTime > ICE_RESTART_DEBOUNCE_MS) {
          lastIceRestartTime = now;
          debugLog(`ICE ${epc.iceConnectionState} with ${peerId}, restarting`);
          await repairIce().catch((error: unknown) => {
            console.warn(
              "p2party: ICE refresh/restart failed",
              error instanceof Error ? error.message : String(error),
            );
          });
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
        // Try to repair before giving up. "disconnected" is usually a transient
        // ICE failure -- a NAT binding expiring on an idle edge, a network
        // change -- and an ICE restart is the standard recovery. Tearing the
        // edge down was the only response, so a room that had been quiet for a
        // few minutes reported "not-connected" on the next send while the peer
        // was still listed in the roster and the UI still said two peers.
        //
        // The teardown below stays as the fallback: if the restart does not get
        // us back to connected within the grace period, the edge really is gone.
        await repairIce().catch(() => undefined);

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
            const currentKeyPair = (api.getState() as State).keyPair;
            await api
              .dispatch(
                signalingServerApi.endpoints.sendMessage.initiate({
                  content: {
                    type: "peers",
                    fromPeerId: currentKeyPair.peerId,
                    roomId,
                    protocolVersion: PROTOCOL_VERSION,
                  },
                }),
              )
              .unwrap()
              .catch(() => undefined);
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
