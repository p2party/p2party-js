import { debugLog } from "../utils/debug";
import { isUUID, isHexadecimal } from "class-validator";

import { handleChallenge } from "./handleChallenge";
import { establishSignaledConnection } from "./connectionSignal";
import { mergePeerRosterDelta } from "./peerRosterDelta";
import {
  commitRoomResponsePlan,
  isExactExpiredTurnGeneration,
  parseRoomResponseCorrelation,
  planRoomResponse,
} from "./roomResponse";
import { requestRoomFromSignaling } from "./requestRoom";

import webrtcApi from "../api/webrtc";
import {
  getRoomIceConfigurationMutex,
  releaseRoomIceConfigurationMutex,
  runRoomResponseCommitExclusive,
} from "../api/webrtc/negotiationLock";
import signalingServerApi, {
  sendRoomRequestMessage,
} from "../api/signalingServerApi";

import {
  setPeer,
  setChannel,
  setConnectingToPeers,
  expireRoomTurnCredentials,
  rollbackRoomResponse,
} from "../reducers/roomSlice";
import { setChallengeId } from "../reducers/keyPairSlice";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type { AcceptedRoomResponsePlan } from "./roomResponse";
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
  WebSocketMessageRoomLeftResponse,
} from "../utils/interfaces";
import { getDBAddressBookEntry, getDBPeerIsBlacklisted } from "../db/api";
import { isCanonicalEd25519Identity } from "../utils/identityRole";
import { isProtocolVersionCompatible } from "../utils/protocolVersion";
import {
  isFreshV3Challenge,
  isV3ChallengeSuccess,
} from "../utils/signalingAuth";
import { findActiveSignalingRoomIndex } from "../utils/signalingRoomLifecycle";
import { signalingPeerRequestDebouncer } from "../utils/signalingPeerRequestDebouncer";
import { PROTOCOL_VERSION } from "../utils/constants";
import {
  areCanonicalConnectionLabels,
  isBoundedDescription,
  isBoundedIceCandidate,
  MAX_SIGNALING_MESSAGE_CHARS,
} from "../utils/signalingBounds";
import {
  claimRoomResponse,
  clearRoomCredentialRefreshIfOwned,
  completeRoomResponse,
  finalizeRoomCredentialRefresh,
  isRoomCredentialRefreshReservationCurrent,
  isRoomResponseClaimCurrent,
  rejectRoomResponse,
  reserveRoomCredentialRefresh,
} from "../utils/roomRequestCoordinator";
import { classifySignalingHeartbeat } from "../utils/signalingIngressQueue";
import { acknowledgeRoomLeft } from "../utils/roomLeaveCoordinator";

const handleWebSocketMessage = async (
  event: MessageEvent,
  ws: WebSocket,
  api: BaseQueryApi,
  isCurrentSocket: () => boolean = () => true,
  // Reports each answered server heartbeat to the socket's liveness watchdog.
  // Passed in by the socket owner rather than imported, so this handler stays
  // free of any dependency on the live socket's state.
  onHeartbeat: () => void = () => undefined,
) => {
  try {
    if (!isCurrentSocket()) return;
    if (event.data === "PING") {
      if (!isCurrentSocket()) return;
      ws.send("PONG");
      onHeartbeat();

      return;
    }

    // debugLog(event.data);

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
      | WebSocketMessagePeerConnectionResponse
      | WebSocketMessageRoomLeftResponse;

    switch (message.type) {
      case "ping": {
        if (classifySignalingHeartbeat(event.data) !== "json") {
          console.error("Rejecting malformed signaling heartbeat");
          break;
        }
        const { keyPair } = api.getState() as State;

        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "pong",
              fromPeerId: keyPair.peerId,
            },
          }),
        );
        onHeartbeat();

        break;
      }

      case "roomLeft": {
        if (!acknowledgeRoomLeft(message, ws))
          console.error(
            "Rejecting unsolicited, stale, or malformed room leave acknowledgement",
          );
        break;
      }

      case "peerId": {
        if (!isFreshV3Challenge(message)) {
          console.error("Rejecting malformed or incompatible auth challenge");
          ws.close(1002, "protocol-v4 auth required");
          break;
        }
        const { keyPair } = api.getState() as State;

        // Protocol v3 has no reconnect bearer shortcut: every WebSocket proves
        // the Ed25519 identity against a fresh server nonce.
        const challengeResponse = await handleChallenge(
          keyPair,
          message.peerId,
          message.challenge,
          api,
          isCurrentSocket,
        );
        if (!challengeResponse || !isCurrentSocket()) break;
        ws.send(JSON.stringify(challengeResponse));

        break;
      }

      case "roomId": {
        // A relay is what lets two peers behind symmetric or carrier-grade NAT
        // reach each other at all; without one the edge simply fails to
        // connect, or flaps as soon as its direct path stops working.
        //
        // The signaling server chooses the relay, and a relay only ever sees
        // DTLS-encrypted frames, so this is not a new disclosure. What is
        // still refused is anything that is not a relay URI: an arbitrary
        // string here would be handed straight to the browser's ICE stack.
        const correlation = parseRoomResponseCorrelation(message);
        if (!correlation) {
          console.error("Rejecting malformed room response correlation");
          break;
        }
        const claim = claimRoomResponse(
          correlation.roomUrl,
          correlation.roomRequestId,
        );
        if (!claim) {
          console.error("Rejecting unsolicited or stale room response");
          break;
        }

        const { keyPair, rooms } = api.getState() as State;
        const initialPlan = planRoomResponse(
          message,
          rooms,
          claim,
          keyPair.publicKey,
        );
        if (!initialPlan.accepted) {
          rejectRoomResponse(
            claim.roomUrl,
            claim.roomRequestId,
            new Error(`roomRequest: ${initialPlan.reason}`),
          );
          console.error(
            initialPlan.reason === "malformed-turn-credentials"
              ? "Rejecting malformed TURN credentials"
              : "Rejecting incompatible or malformed room response",
          );
          break;
        }
        let plan: AcceptedRoomResponsePlan = initialPlan;

        let refreshReservation;
        try {
          refreshReservation = reserveRoomCredentialRefresh(
            plan.roomUrl,
            plan.expiresAtUnixSeconds,
          );
        } catch (error) {
          rejectRoomResponse(
            plan.roomUrl,
            plan.roomRequestId,
            error instanceof Error
              ? error
              : new Error("roomRequest: TURN refresh capacity is exhausted"),
          );
          break;
        }

        try {
          const hasCurrentRoomResponseLease = (): boolean =>
            isCurrentSocket() &&
            isRoomResponseClaimCurrent(claim) &&
            isRoomCredentialRefreshReservationCurrent(refreshReservation);
          const canPublishRoomResponse = (): boolean => {
            if (!hasCurrentRoomResponseLease()) return false;
            const currentRoom = (api.getState() as State).rooms.find(
              (room) => room.url === plan.roomUrl,
            );
            return (
              currentRoom !== undefined &&
              currentRoom.signalingActive !== false &&
              (!isUUID(currentRoom.id) || currentRoom.id === plan.roomId) &&
              currentRoom.roomResponseGeneration < plan.requestGeneration
            );
          };
          const committed = await runRoomResponseCommitExclusive(() =>
            getRoomIceConfigurationMutex(plan.roomUrl).runExclusive(
              async () => {
                const freshState = api.getState() as State;
                const replanned = planRoomResponse(
                  message,
                  freshState.rooms,
                  claim,
                  freshState.keyPair.publicKey,
                );
                if (!replanned.accepted)
                  throw new Error(`roomRequest: ${replanned.reason}`);
                plan = replanned;

                return await commitRoomResponsePlan(
                  plan,
                  async (roomId, rtcConfig, failurePolicy) => {
                    await api
                      .dispatch(
                        webrtcApi.endpoints.applyRoomConfiguration.initiate({
                          roomId,
                          rtcConfig,
                          restartIce: true,
                          failurePolicy,
                        }),
                      )
                      .unwrap();
                  },
                  canPublishRoomResponse,
                  () => {
                    api.dispatch(plan.action);
                    const appliedRoom = (api.getState() as State).rooms.find(
                      (room) => room.url === plan.roomUrl,
                    );
                    if (
                      !appliedRoom ||
                      appliedRoom.id !== plan.roomId ||
                      appliedRoom.roomResponseGeneration !==
                        plan.requestGeneration
                    )
                      return false;
                    if (!hasCurrentRoomResponseLease()) return false;

                    finalizeRoomCredentialRefresh(
                      refreshReservation,
                      plan.expiresAtUnixSeconds,
                      () =>
                        requestRoomFromSignaling(api, plan.roomUrl, (request) =>
                          sendRoomRequestMessage(api, request),
                        ),
                      async () => {
                        const expiresAtUnixSeconds = plan.expiresAtUnixSeconds;
                        if (expiresAtUnixSeconds === null) return;
                        await getRoomIceConfigurationMutex(
                          plan.roomUrl,
                        ).runExclusive(async () => {
                          api.dispatch(
                            expireRoomTurnCredentials({
                              roomUrl: plan.roomUrl,
                              expiresAtUnixSeconds,
                              requestGeneration: plan.requestGeneration,
                            }),
                          );
                          const room = (api.getState() as State).rooms.find(
                            (candidate) => candidate.url === plan.roomUrl,
                          );
                          if (!isExactExpiredTurnGeneration(room, plan)) return;
                          await api
                            .dispatch(
                              webrtcApi.endpoints.applyRoomConfiguration.initiate(
                                {
                                  roomId: room.id,
                                  rtcConfig: room.rtcConfig,
                                  restartIce: true,
                                  failurePolicy: "close",
                                },
                              ),
                            )
                            .unwrap();
                        });
                      },
                    );
                    return completeRoomResponse({
                      roomUrl: plan.roomUrl,
                      roomId: plan.roomId,
                      roomRequestId: plan.roomRequestId,
                      requestGeneration: plan.requestGeneration,
                      expiresAtUnixSeconds: plan.expiresAtUnixSeconds,
                    });
                  },
                  (roomUrl) =>
                    (api.getState() as State).rooms.find(
                      (room) => room.url === roomUrl,
                    ),
                  (previous) => {
                    api.dispatch(
                      rollbackRoomResponse({
                        roomUrl: plan.roomUrl,
                        failedRoomId: plan.roomId,
                        failedRequestGeneration: plan.requestGeneration,
                        previousRoomId: previous.id,
                        previousRequestGeneration:
                          previous.roomResponseGeneration,
                        previousTurnCredentials:
                          previous.signalingTurnCredentials,
                        previousSignalingActive: previous.signalingActive,
                      }),
                    );
                  },
                );
              },
            ),
          );
          if (!committed)
            throw new Error("roomRequest: atomic room transition was rejected");
        } catch (error) {
          clearRoomCredentialRefreshIfOwned(refreshReservation);
          releaseRoomIceConfigurationMutex(plan.roomUrl);
          rejectRoomResponse(
            plan.roomUrl,
            plan.roomRequestId,
            error instanceof Error
              ? error
              : new Error("roomRequest: failed to apply ICE configuration"),
          );
          break;
        }

        if (!isCurrentSocket()) break;
        api.dispatch(
          setConnectingToPeers({
            roomId: plan.roomId,
            connectingToPeers: true,
          }),
        );

        break;
      }

      case "challenge": {
        if (!isV3ChallengeSuccess(message)) {
          console.error("Rejecting malformed or incompatible auth success");
          ws.close(1002, "protocol-v4 auth required");
          break;
        }
        if (isCurrentSocket()) api.dispatch(setChallengeId(message));

        break;
      }

      case "peerConnection": {
        if (
          !isProtocolVersionCompatible(message.protocolVersion) ||
          !isUUID(message.peer.id) ||
          !isUUID(message.roomId, 4) ||
          !isCanonicalEd25519Identity(message.peer.publicKey)
        )
          break;
        const blacklisted = await getDBPeerIsBlacklisted(
          message.peer.id,
          message.peer.publicKey,
        );
        if (!isCurrentSocket()) break;

        if (blacklisted) break;

        const { keyPair, rooms } = api.getState() as State;

        const roomIndex = findActiveSignalingRoomIndex(rooms, message.roomId);
        if (roomIndex === -1) break;

        if (rooms[roomIndex].onlyConnectWithKnownAddresses) {
          const inAddressBook = await getDBAddressBookEntry(
            message.peer.id,
            message.peer.publicKey,
          );
          if (!isCurrentSocket()) break;

          if (!inAddressBook) break;
        }

        if (!isCurrentSocket()) break;
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
        debugLog("[handleWebSocketMessage] Received peers response:", {
          roomId: message.roomId,
          peersCount: message.peers.length,
          peers: message.peers,
        });
        const { keyPair, rooms } = api.getState() as State;
        const roomIndex = findActiveSignalingRoomIndex(rooms, message.roomId);

        if (roomIndex > -1) {
          // The server emits one accepted peer at a time. These are deltas,
          // never authoritative snapshots: an absent member is not a leave.
          const mergedPeers = mergePeerRosterDelta(
            rooms[roomIndex].peers,
            message.peers,
            keyPair,
          );
          for (const peer of mergedPeers)
            api.dispatch(setPeer({ roomId: message.roomId, ...peer }));

          const len = message.peers.length;
          if (len === 0) {
            const { signalingServer } = api.getState() as State;
            const now = Date.now();
            if (
              signalingServer.isConnected &&
              signalingServer.isVerified &&
              isUUID(keyPair.peerId) &&
              signalingPeerRequestDebouncer.shouldSend(
                "empty-roster",
                message.roomId,
                5000,
                now,
              )
            ) {
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

            const accepted = mergedPeers.some(
              (peer) =>
                peer.peerId === message.peers[i].id &&
                peer.peerPublicKey === message.peers[i].publicKey,
            );
            if (!accepted) continue;

            const blacklisted = await getDBPeerIsBlacklisted(
              message.peers[i].id,
              message.peers[i].publicKey,
            );
            if (!isCurrentSocket()) return;
            if (blacklisted) continue;

            if (canOnlyConnectToKnownPeers) {
              const p = await getDBAddressBookEntry(
                message.peers[i].id,
                message.peers[i].publicKey,
              );
              if (!isCurrentSocket()) return;

              if (!p) continue;
            }

            if (!isCurrentSocket()) return;
            await api.dispatch(
              webrtcApi.endpoints.connectWithPeer.initiate({
                roomId: message.roomId,
                peerId: message.peers[i].id,
                peerPublicKey: message.peers[i].publicKey,
                // Read RAW, not from mergedPeers: that projection drops the
                // field and skips peer ids it already knows. Advisory only —
                // the roster is re-sent on join, on re-dial and on reconcile,
                // and a signaling socket now reconnects on its own, so a
                // healthy edge routinely sees a changed generation here and
                // must survive it (C4).
                peerSocketGeneration: message.peers[i].socketGeneration,
                peerSocketGenerationSource: "roster",
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
                `version ${String(message.protocolVersion)} (expected v4). No fallback.`,
            );
          break;
        }
        const blacklisted = await getDBPeerIsBlacklisted(
          message.fromPeerId,
          message.fromPeerPublicKey,
        );
        if (!isCurrentSocket()) break;

        if (!blacklisted) {
          const { rooms } = api.getState() as State;
          const roomIndex = findActiveSignalingRoomIndex(rooms, message.roomId);
          if (roomIndex === -1) break;

          const canOnlyConnectToKnownPeers =
            rooms[roomIndex].onlyConnectWithKnownAddresses;

          if (canOnlyConnectToKnownPeers) {
            const p = await getDBAddressBookEntry(
              message.fromPeerId,
              message.fromPeerPublicKey,
            );
            if (!isCurrentSocket()) break;

            if (!p) break;
          }

          if (!isCurrentSocket()) break;
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
              `version ${String(message.protocolVersion)} (expected v4). No fallback.`,
          );
          break;
        }
        const blacklisted = await getDBPeerIsBlacklisted(message.fromPeerId);
        if (!isCurrentSocket()) break;

        if (!blacklisted) {
          const { rooms } = api.getState() as State;
          const roomIndex = findActiveSignalingRoomIndex(rooms, message.roomId);
          if (roomIndex === -1) break;

          const canOnlyConnectToKnownPeers =
            rooms[roomIndex].onlyConnectWithKnownAddresses;

          if (canOnlyConnectToKnownPeers) {
            const p = await getDBAddressBookEntry(message.fromPeerId);
            if (!isCurrentSocket()) break;

            if (!p) break;
          }

          if (!isCurrentSocket()) break;
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
        const roomIndex = findActiveSignalingRoomIndex(rooms, message.roomId);
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
          areCanonicalConnectionLabels(message.labels)
        ) {
          const blacklisted = await getDBPeerIsBlacklisted(
            message.fromPeerId,
            message.fromPeerPublicKey,
          );
          if (!isCurrentSocket()) break;
          if (blacklisted) break;

          if (rooms[roomIndex].onlyConnectWithKnownAddresses) {
            const known = await getDBAddressBookEntry(
              message.fromPeerId,
              message.fromPeerPublicKey,
            );
            if (!isCurrentSocket()) break;
            if (!known) break;
          }

          if (!isCurrentSocket()) break;
          await establishSignaledConnection(
            message,
            rooms[roomIndex].rtcConfig,
            {
              recordPeer: (peer) => {
                if (isCurrentSocket()) api.dispatch(setPeer(peer));
              },
              recordChannel: (channel) => {
                if (!isCurrentSocket()) return;
                api.dispatch(setChannel(channel));
                debugLog(
                  `Connected with ${keyPair.peerId} on websocket channel ${channel.label}`,
                );
              },
              ensureConnection: async (params) => {
                if (!isCurrentSocket()) return;
                await api
                  .dispatch(
                    webrtcApi.endpoints.connectWithPeer.initiate(params),
                  )
                  .unwrap();
              },
            },
          );
        } else if (!isProtocolVersionCompatible(message.protocolVersion)) {
          console.error(
            `Rejecting peer ${message.fromPeerId}: incompatible protocol ` +
              `version ${String(message.protocolVersion)} (expected v4). No fallback.`,
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
