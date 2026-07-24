import { isUUID, isHexadecimal } from "class-validator";

import { handleChallenge } from "./handleChallenge";
import { establishSignaledConnection } from "./connectionSignal";

import webrtcApi from "../api/webrtc";
import signalingServerApi from "../api/signalingServerApi";

import {
  setRoom,
  setPeer,
  deletePeer,
  setChannel,
  defaultRTCConfig,
} from "../reducers/roomSlice";
import { setChallengeId } from "../reducers/keyPairSlice";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateReceive,
  WebSocketMessagePeersResponse,
  WebSocketMessageConnectionRequest,
  WebSocketMessageSuccessfulChallenge,
  WebSocketMessageError,
  WebSocketMessagePingRequest,
  WebSocketMessagePeerConnectionResponse,
  WebSocketMessagePeersRequest,
} from "../utils/interfaces";
import { getDBAddressBookEntry, getDBPeerIsBlacklisted } from "../db/api";
import { isCanonicalEd25519Identity } from "../utils/identityRole";
import { isProtocolVersionCompatible } from "../utils/protocolVersion";
import {
  isFreshV3Challenge,
  isV3ChallengeSuccess,
} from "../utils/signalingAuth";
import { PROTOCOL_VERSION } from "../utils/constants";
import {
  areBoundedDataChannelLabels,
  isBoundedDescription,
  isBoundedIceCandidate,
  MAX_SIGNALING_MESSAGE_CHARS,
} from "../utils/signalingBounds";

const lastPeersRepoll = new Map<string, number>();

const handleWebSocketMessage = async (
  event: MessageEvent,
  ws: WebSocket,
  api: BaseQueryApi,
) => {
  try {
    if (event.data === "PING") {
      ws.send("PONG");

      return;
    }

    // console.log(event.data);

    const serialized = String(event.data);
    if (serialized.length > MAX_SIGNALING_MESSAGE_CHARS) {
      console.error("Rejecting oversized signaling message");
      return;
    }
    const message = JSON.parse(serialized) as
      | WebSocketMessagePingRequest
      | WebSocketMessageChallengeRequest
      | WebSocketMessageRoomIdResponse
      | WebSocketMessageDescriptionReceive
      | WebSocketMessageCandidateReceive
      | WebSocketMessagePeersResponse
      | WebSocketMessageConnectionRequest
      | WebSocketMessageSuccessfulChallenge
      | WebSocketMessageError
      | WebSocketMessagePeerConnectionResponse;

    switch (message.type) {
      case "ping": {
        const { keyPair } = api.getState() as State;

        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "pong",
              fromPeerId: keyPair.peerId,
            },
          }),
        );

        break;
      }

      case "peerId": {
        if (!isFreshV3Challenge(message)) {
          console.error("Rejecting malformed or incompatible auth challenge");
          ws.close(1002, "protocol-v3 auth required");
          break;
        }
        const { keyPair } = api.getState() as State;

        // Protocol v3 has no reconnect bearer shortcut: every WebSocket proves
        // the Ed25519 identity against a fresh server nonce.
        await handleChallenge(keyPair, message.peerId, message.challenge, api);

        break;
      }

      case "roomId": {
        if (
          !isProtocolVersionCompatible(message.protocolVersion) ||
          !isUUID(message.roomId) ||
          !/^[0-9a-f]{64}$/.test(message.roomUrl)
        ) {
          console.error("Rejecting incompatible or malformed room response");
          break;
        }
        // Build rtcConfig with TURN credentials if provided by server
        let rtcConfig: RTCConfiguration | undefined;
        if (message.turnCredentials) {
          rtcConfig = {
            ...defaultRTCConfig,
            iceServers: [
              ...(defaultRTCConfig.iceServers ?? []),
              {
                urls: message.turnCredentials.urls,
                username: message.turnCredentials.username,
                credential: message.turnCredentials.credential,
              },
            ],
          };
        }

        api.dispatch(
          setRoom({
            id: message.roomId,
            url: message.roomUrl,
            rtcConfig,
          }),
        );

        break;
      }

      case "challenge": {
        if (!isV3ChallengeSuccess(message)) {
          console.error("Rejecting malformed or incompatible auth success");
          ws.close(1002, "protocol-v3 auth required");
          break;
        }
        api.dispatch(setChallengeId(message));

        break;
      }

      case "peerConnection": {
        if (
          !isProtocolVersionCompatible(message.protocolVersion) ||
          !isUUID(message.peer.id) ||
          !isCanonicalEd25519Identity(message.peer.publicKey)
        )
          break;
        const blacklisted = await getDBPeerIsBlacklisted(
          message.peer.id,
          message.peer.publicKey,
        );

        if (blacklisted) break;

        const { keyPair, rooms } = api.getState() as State;

        const roomIndex = rooms.findIndex((r) => r.id === message.roomId);

        if (roomIndex > -1 && rooms[roomIndex].onlyConnectWithKnownAddresses) {
          const inAddressBook = await getDBAddressBookEntry(
            message.peer.id,
            message.peer.publicKey,
          );

          if (!inAddressBook) break;
        }

        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "peerConnection",
              roomId: message.roomId,
              fromPeerId: keyPair.peerId,
              toPeerId: message.peer.id,
              protocolVersion: PROTOCOL_VERSION,
            },
          }),
        );

        break;
      }

      case "peers": {
        if (
          !isProtocolVersionCompatible(message.protocolVersion) ||
          !isUUID(message.roomId) ||
          !Array.isArray(message.peers)
        ) {
          console.error("Rejecting incompatible or malformed peer roster");
          break;
        }
        console.log("[handleWebSocketMessage] Received peers response:", {
          roomId: message.roomId,
          peersCount: message.peers.length,
          peers: message.peers,
        });
        const { keyPair, rooms } = api.getState() as State;
        const roomIndex = rooms.findIndex((r) => r.id === message.roomId);

        if (roomIndex > -1) {
          const serverPeerIds = new Set(
            message.peers
              .filter((peer) => isUUID(peer.id))
              .map((peer) => peer.id),
          );
          for (const peer of rooms[roomIndex].peers) {
            if (!serverPeerIds.has(peer.peerId))
              api.dispatch(
                deletePeer({ roomId: message.roomId, peerId: peer.peerId }),
              );
          }

          const len = message.peers.length;
          if (len === 0) {
            const { signalingServer } = api.getState() as State;
            const now = Date.now();
            const lastRepoll = lastPeersRepoll.get(message.roomId) ?? 0;
            if (
              signalingServer.isConnected &&
              signalingServer.isVerified &&
              isUUID(keyPair.peerId) &&
              now - lastRepoll > 5000
            ) {
              lastPeersRepoll.set(message.roomId, now);

              await api.dispatch(
                signalingServerApi.endpoints.sendMessage.initiate({
                  content: {
                    type: "peers",
                    fromPeerId: keyPair.peerId,
                    roomId: message.roomId,
                    protocolVersion: PROTOCOL_VERSION,
                  } as WebSocketMessagePeersRequest,
                }),
              );
            }
            break;
          }

          const canOnlyConnectToKnownPeers =
            rooms[roomIndex].onlyConnectWithKnownAddresses;

          for (let i = 0; i < len; i++) {
            if (
              message.peers[i].publicKey === keyPair.publicKey ||
              message.peers[i].id === keyPair.peerId ||
              !isUUID(message.peers[i].id) ||
              !isCanonicalEd25519Identity(message.peers[i].publicKey)
            )
              continue;

            api.dispatch(
              setPeer({
                roomId: message.roomId,
                peerId: message.peers[i].id,
                peerPublicKey: message.peers[i].publicKey,
              }),
            );

            const blacklisted = await getDBPeerIsBlacklisted(
              message.peers[i].id,
              message.peers[i].publicKey,
            );
            if (blacklisted) continue;

            if (canOnlyConnectToKnownPeers) {
              const p = await getDBAddressBookEntry(
                message.peers[i].id,
                message.peers[i].publicKey,
              );

              if (!p) continue;
            }

            await api.dispatch(
              webrtcApi.endpoints.connectWithPeer.initiate({
                roomId: message.roomId,
                peerId: message.peers[i].id,
                peerPublicKey: message.peers[i].publicKey,
                rtcConfig: rooms[roomIndex].rtcConfig,
              }),
            );
          }
        }

        break;
      }

      case "description": {
        if (
          !isProtocolVersionCompatible(message.protocolVersion) ||
          !isUUID(message.fromPeerId) ||
          !isCanonicalEd25519Identity(message.fromPeerPublicKey) ||
          !isUUID(message.roomId) ||
          !isBoundedDescription(message.description)
        ) {
          if (!isProtocolVersionCompatible(message.protocolVersion))
            console.error(
              `Rejecting SDP from ${message.fromPeerId}: incompatible protocol ` +
                `version ${String(message.protocolVersion)} (expected v3). No fallback.`,
            );
          break;
        }
        const blacklisted = await getDBPeerIsBlacklisted(
          message.fromPeerId,
          message.fromPeerPublicKey,
        );

        if (!blacklisted) {
          const { rooms } = api.getState() as State;
          const roomIndex = rooms.findIndex((r) => r.id === message.roomId);
          if (roomIndex === -1) break;

          const canOnlyConnectToKnownPeers =
            rooms[roomIndex].onlyConnectWithKnownAddresses;

          if (canOnlyConnectToKnownPeers) {
            const p = await getDBAddressBookEntry(
              message.fromPeerId,
              message.fromPeerPublicKey,
            );

            if (!p) break;
          }

          await api.dispatch(
            webrtcApi.endpoints.setDescription.initiate({
              peerId: message.fromPeerId,
              peerPublicKey: message.fromPeerPublicKey,
              roomId: message.roomId,
              description: message.description,
              rtcConfig: rooms[roomIndex].rtcConfig,
            }),
          );
        }

        break;
      }

      case "candidate": {
        if (
          !isProtocolVersionCompatible(message.protocolVersion) ||
          !isUUID(message.fromPeerId) ||
          !isUUID(message.roomId) ||
          !isBoundedIceCandidate(message.candidate)
        ) {
          console.error(
            `Rejecting ICE from ${message.fromPeerId}: incompatible protocol ` +
              `version ${String(message.protocolVersion)} (expected v3). No fallback.`,
          );
          break;
        }
        const blacklisted = await getDBPeerIsBlacklisted(message.fromPeerId);

        if (!blacklisted) {
          const { rooms } = api.getState() as State;
          const roomIndex = rooms.findIndex((r) => r.id === message.roomId);
          if (roomIndex === -1) break;

          const canOnlyConnectToKnownPeers =
            rooms[roomIndex].onlyConnectWithKnownAddresses;

          if (canOnlyConnectToKnownPeers) {
            const p = await getDBAddressBookEntry(message.fromPeerId);

            if (!p) break;
          }

          await api.dispatch(
            webrtcApi.endpoints.setCandidate.initiate({
              peerId: message.fromPeerId,
              roomId: message.roomId,
              candidate: message.candidate,
            }),
          );
        }

        break;
      }

      case "connection": {
        const { keyPair, rooms } = api.getState() as State;
        const roomIndex = rooms.findIndex((room) => room.id === message.roomId);
        if (
          isProtocolVersionCompatible(message.protocolVersion) &&
          isUUID(keyPair.peerId) &&
          isHexadecimal(keyPair.challenge) &&
          isHexadecimal(keyPair.signature) &&
          // keyPair.signature.length === 1024 &&
          keyPair.signature.length === 128 &&
          keyPair.challenge.length === 64 &&
          isUUID(message.fromPeerId) &&
          isCanonicalEd25519Identity(message.fromPeerPublicKey) &&
          message.fromPeerId !== keyPair.peerId &&
          message.fromPeerPublicKey !== keyPair.publicKey &&
          isUUID(message.roomId) &&
          roomIndex > -1 &&
          areBoundedDataChannelLabels(message.labels)
        ) {
          const blacklisted = await getDBPeerIsBlacklisted(
            message.fromPeerId,
            message.fromPeerPublicKey,
          );
          if (blacklisted) break;

          if (rooms[roomIndex].onlyConnectWithKnownAddresses) {
            const known = await getDBAddressBookEntry(
              message.fromPeerId,
              message.fromPeerPublicKey,
            );
            if (!known) break;
          }

          await establishSignaledConnection(
            message,
            rooms[roomIndex].rtcConfig,
            {
              recordPeer: (peer) => {
                api.dispatch(setPeer(peer));
              },
              recordChannel: (channel) => {
                api.dispatch(setChannel(channel));
                console.log(
                  `Connected with ${keyPair.peerId} on websocket channel ${channel.label}`,
                );
              },
              ensureConnection: async (params) => {
                await api.dispatch(
                  webrtcApi.endpoints.connectWithPeer.initiate(params),
                );
              },
            },
          );
        } else if (!isProtocolVersionCompatible(message.protocolVersion)) {
          console.error(
            `Rejecting peer ${message.fromPeerId}: incompatible protocol ` +
              `version ${String(message.protocolVersion)} (expected v3). No fallback.`,
          );
        }

        break;
      }

      case "error": {
        console.error(message);

        break;
      }

      default: {
        console.error("Unknown message type " + JSON.stringify(message));

        break;
      }
    }
  } catch (error) {
    console.error("[p2party] WebSocket message handling error:", error);
    return;
  }
};

export default handleWebSocketMessage;
