import { debugLog } from "../utils/debug";
import { isUUID } from "../utils/formatValidation";

import { handleQueuedIceCandidates } from "./handleQueuedIceCandidates";
import { requestPeersAfterEdgeTeardown } from "./edgeTeardownFollowUp";
import { hasTerminalPeerHandshakeFailure } from "./handshakeFailure";

import signalingServerApi, {
  sendRoomRequestMessage,
  captureSignalingSendLease,
} from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";
import { teardownEdgeGeneration } from "../api/webrtc/disconnectFromPeerQuery";
import {
  repairIceTransportAfterCandidateFailure,
  type IceCandidateRepairResult,
} from "../api/webrtc/iceRepair";
import {
  findRoomIdentityAliases,
  findRoomPeerConnection,
} from "../api/webrtc/roomPeer";
import { assertRoomEdgeBudget } from "../api/webrtc/roomEdgeBudget";
import {
  hasNoNegotiatedDescription,
  hasUnansweredFirstOffer,
  PENDING_OFFER_TIMEOUT_MS,
} from "../api/webrtc/pendingOffer";
import {
  clearUnnegotiatedTransportRebuilds,
  mayRebuildUnnegotiatedTransport,
  recordUnnegotiatedTransportRebuild,
} from "../api/webrtc/unnegotiatedTransport";
import {
  getRoomIdentityMutex,
  getRoomIceConfigurationMutex,
  releaseRoomIdentityMutex,
} from "../api/webrtc/negotiationLock";

import { setPeer } from "../reducers/roomSlice";

import cryptoMemory from "../cryptography/memory";
import { wasmLoader } from "../cryptography/wasmLoader";
import { resetRatchetGate } from "./ratchetGate";
import { claimRatchetGeneration } from "./ratchetPersist";
import {
  assertCanonicalEd25519Identity,
  isIdentityInitiator,
} from "../utils/identityRole";
import { assertTransportIdentityCurrent } from "../utils/transportIdentity";
import {
  ICE_REPAIR_GRACE_MS,
  SIGNALING_PROTOCOL_VERSION,
} from "../utils/constants";
import { requestRoomFromSignaling } from "./requestRoom";
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
      if (
        hasTerminalPeerHandshakeFailure(
          room.handshakeStatusByPeer,
          peerId,
          peerPublicKey,
        )
      )
        throw new Error(
          "Terminal peer authentication failure requires deliberate retry",
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
        webrtcApi.endpoints.disconnectFromPeer.initiate(
          {
            roomId,
            peerId: alias.withPeerId,
          },
          { track: false },
        ),
      );
    }

    let existing = findRoomPeerConnection(peerConnections, roomId, peerId);
    if (existing && existing.withPeerPublicKey !== peerPublicKey) {
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate(
          { roomId, peerId },
          { track: false },
        ),
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
      epc.remoteTransportRebinds = 0;
      epc.ensureFreshIceConfiguration = async (): Promise<boolean> => {
        const state = api.getState() as State;
        // Only the signaling reconnect controller may reopen a dead socket.
        // A transport repair cannot override a terminal server refusal.
        if (
          !state.signalingServer.isConnected ||
          !state.signalingServer.isVerified
        )
          throw new Error("ICE repair requires a verified signaling socket");
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
        return false;
      };
      // Claim and registry insertion remain inside the room-config critical
      // section, so a response sweep cannot miss this concrete transport.
      claimRatchetGeneration(epc, roomId);
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
            signalingServerApi.endpoints.connectWithPeer.initiate(
              {
                roomId,
                peerId,
                peerPublicKey,
              },
              { track: false },
            ),
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
      // The same teardown as every other abandoned transport. A transport
      // that failed to initialize holds little (no channel exists yet), but
      // it did claim the edge's gate, which would otherwise stay pending for
      // every awaiter, and the edge's persisted ratchet row.
      teardownEdgeGeneration(epc, { dispatch: api.dispatch });
      throw error;
    } finally {
      epc.initialization = undefined;
    }

    // True once this transport has reached "connected" at least once. A silent
    // teardown re-dials the room only for such an edge: a transport that never
    // connected (no reachable relay, a peer behind an unfriendly NAT) would
    // otherwise re-dial, rebuild and fail again on every ICE failure with no
    // backoff. Not re-dialing there is what the failed branch always did.
    let wasConnected = false;

    // A fresh transport's first offer can be lost outright: the peer was still
    // on the roster but its socket had gone dark, so the server dropped the
    // frame with the socket. Nothing on this PC would ever fire again (no
    // remote description, so no ICE checks and no failure), and a later
    // `connection` frame from the peer would merely reuse it. Bound the wait:
    // tear the transport down and re-dial so the next roster round rebuilds
    // it against the peer's live socket.
    let pendingOfferWatchdog: ReturnType<typeof setTimeout> | undefined;
    const armPendingOfferWatchdog = (): void => {
      if (pendingOfferWatchdog) clearTimeout(pendingOfferWatchdog);
      pendingOfferWatchdog = setTimeout(() => {
        pendingOfferWatchdog = undefined;
        if (!peerConnections.includes(epc) || !hasUnansweredFirstOffer(epc))
          return;
        console.warn(
          `p2party: first offer to ${peerId} in room ${roomId} was never answered; rebuilding the transport`,
        );
        void api
          .dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate(
              { peerId, roomId },
              { track: false },
            ),
          )
          .then(() => {
            requestPeersAfterEdgeTeardown(api, roomId, peerId);
          });
      }, PENDING_OFFER_TIMEOUT_MS);
    };

    // A protocol RESPONDER creates no channel on a fresh transport, so nothing
    // negotiates and nothing watches it: no description means no ICE, no
    // failure and no rebind deadline. That is the state a second session for
    // one identity is stranded in (C1). Bounded, because against a
    // pre-generation server the peer will not rebuild its own side, and an
    // uncapped watchdog would then churn every PENDING_OFFER_TIMEOUT_MS
    // forever. Disjoint from the offer watchdog above: that one requires a
    // local offer, this one requires the absence of every description.
    let unnegotiatedWatchdog: ReturnType<typeof setTimeout> | undefined;
    const clearUnnegotiatedTransportWatchdog = (): void => {
      if (unnegotiatedWatchdog) clearTimeout(unnegotiatedWatchdog);
      unnegotiatedWatchdog = undefined;
    };
    const armUnnegotiatedTransportWatchdog = (): void => {
      clearUnnegotiatedTransportWatchdog();
      unnegotiatedWatchdog = setTimeout(() => {
        unnegotiatedWatchdog = undefined;
        if (!peerConnections.includes(epc) || !hasNoNegotiatedDescription(epc))
          return;
        if (!mayRebuildUnnegotiatedTransport(roomId, peerId)) {
          console.warn(
            `p2party: transport with ${peerId} in room ${roomId} never negotiated and its rebuild budget is spent`,
          );
          return;
        }
        recordUnnegotiatedTransportRebuild(roomId, peerId);
        console.warn(
          `p2party: transport with ${peerId} in room ${roomId} never negotiated; rebuilding`,
        );
        void api
          .dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate(
              { peerId, roomId },
              { track: false },
            ),
          )
          .then(() => {
            requestPeersAfterEdgeTeardown(api, roomId, peerId);
          });
      }, PENDING_OFFER_TIMEOUT_MS);
    };
    if (
      !isIdentityInitiator(
        (api.getState() as State).keyPair.publicKey,
        peerPublicKey,
      )
    )
      armUnnegotiatedTransportWatchdog();

    epc.onnegotiationneeded = async () => {
      // Don't start a new negotiation if we're already making an offer or not in stable state
      const canPublish = captureSignalingSendLease();
      const { signalingServer } = api.getState() as State;
      if (!peerConnections.includes(epc) || epc.signalingState === "closed")
        return;
      if (
        !canPublish ||
        !signalingServer.isConnected ||
        !signalingServer.isVerified
      ) {
        epc.resumeDeferredNegotiation = () => {
          epc.resumeDeferredNegotiation = undefined;
          void epc.onnegotiationneeded?.call(
            epc,
            new Event("negotiationneeded"),
          );
        };
        return;
      }
      if (epc.makingOffer || epc.signalingState !== "stable") {
        debugLog(
          `Skipping negotiation with ${peerId} - already making offer: ${String(epc.makingOffer)}, state: ${epc.signalingState}`,
        );
        return;
      }

      try {
        epc.makingOffer = true;
        await epc.setLocalDescription();
        // Only the first offer on a fresh transport is watched; an ICE-restart
        // offer keeps the previous remote description and is owned by the ICE
        // repair paths.
        if (!canPublish())
          throw new Error("Signaling socket changed while creating an offer");
        if (epc.localDescription) {
          const currentKeyPair = (api.getState() as State).keyPair;
          await api
            .dispatch(
              signalingServerApi.endpoints.sendMessage.initiate(
                {
                  content: {
                    type: "description",
                    description: epc.localDescription,
                    fromPeerId: currentKeyPair.peerId,
                    fromPeerPublicKey: currentKeyPair.publicKey,
                    toPeerId: peerId,
                    roomId,
                    protocolVersion: SIGNALING_PROTOCOL_VERSION,
                  } as WebSocketMessageDescriptionSend,
                },
                { track: false },
              ),
            )
            .unwrap();
          if (hasUnansweredFirstOffer(epc)) armPendingOfferWatchdog();

          debugLog(
            `Negotiation was needed with ${peerId} and you sent a description ${epc.localDescription.type}.`,
          );
        }
      } catch (error) {
        if (
          (epc.signalingState as string) === "have-local-offer" &&
          peerConnections.includes(epc)
        ) {
          try {
            await epc.setLocalDescription({ type: "rollback" });
          } catch {
            // This exact transport cannot negotiate again with an unsent offer.
            if (peerConnections.includes(epc))
              await api.dispatch(
                webrtcApi.endpoints.disconnectFromPeer.initiate(
                  {
                    roomId,
                    peerId,
                  },
                  { track: false },
                ),
              );
          }
          requestPeersAfterEdgeTeardown(api, roomId, peerId);
        }
        console.error(error);
      } finally {
        epc.makingOffer = false;
      }
    };

    epc.onicecandidate = async ({ candidate }) => {
      if (candidate && candidate.candidate !== "") {
        if (
          epc.getConfiguration().iceTransportPolicy === "relay" &&
          candidate.type !== "relay"
        )
          return;
        const currentKeyPair = (api.getState() as State).keyPair;
        await api
          .dispatch(
            signalingServerApi.endpoints.sendMessage.initiate(
              {
                content: {
                  type: "candidate",
                  candidate,
                  fromPeerId: currentKeyPair.peerId,
                  toPeerId: peerId,
                  roomId,
                  protocolVersion: SIGNALING_PROTOCOL_VERSION,
                } as WebSocketMessageCandidateSend,
              },
              { track: false },
            ),
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
    const clearDisconnectTimeout = (): void => {
      if (disconnectTimeout !== undefined) clearTimeout(disconnectTimeout);
      disconnectTimeout = undefined;
    };
    epc.clearTransportTimers = () => {
      if (pendingOfferWatchdog !== undefined)
        clearTimeout(pendingOfferWatchdog);
      pendingOfferWatchdog = undefined;
      clearUnnegotiatedTransportWatchdog();
      clearDisconnectTimeout();
    };
    let iceRepairInFlight: Promise<IceCandidateRepairResult> | undefined;
    const repairIce = (): Promise<IceCandidateRepairResult> => {
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
      if (epc.iceConnectionState === "disconnected") observeDisconnect();
      if (epc.iceConnectionState === "failed") {
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

    const stillBroken = (): boolean =>
      peerConnections.includes(epc) &&
      (epc.iceConnectionState === "failed" ||
        epc.iceConnectionState === "disconnected" ||
        epc.connectionState === "disconnected");
    const retireAfterRepair = (): void => {
      clearDisconnectTimeout();
      if (!stillBroken()) return;
      void api
        .dispatch(
          webrtcApi.endpoints.disconnectFromPeer.initiate(
            { roomId, peerId },
            { track: false },
          ),
        )
        .then(() => {
          if (wasConnected) requestPeersAfterEdgeTeardown(api, roomId, peerId);
        });
    };
    const observeDisconnect = (): void => {
      if (disconnectTimeout !== undefined) return;
      disconnectTimeout = setTimeout(() => {
        if (!stillBroken()) {
          clearDisconnectTimeout();
          return;
        }
        // Only this edge requests fresh credentials and restarts once the
        // ordinary disconnect grace has passed.
        void repairIce().catch((error: unknown) =>
          debugLog("ICE restart failed", error),
        );
        disconnectTimeout = setTimeout(retireAfterRepair, ICE_REPAIR_GRACE_MS);
      }, ICE_REPAIR_GRACE_MS);
    };
    epc.onconnectionstatechange = async () => {
      if (epc.connectionState === "disconnected") {
        observeDisconnect();
      } else if (
        epc.connectionState === "failed" &&
        epc.iceConnectionState === "failed"
      ) {
        if (disconnectTimeout === undefined)
          disconnectTimeout = setTimeout(
            retireAfterRepair,
            ICE_REPAIR_GRACE_MS,
          );
        await repairIce().catch((error: unknown) =>
          debugLog("ICE restart failed", error),
        );
      } else if (
        epc.connectionState === "closed" ||
        epc.connectionState === "failed"
      ) {
        if (disconnectTimeout) {
          clearTimeout(disconnectTimeout);
          disconnectTimeout = undefined;
        }
        clearUnnegotiatedTransportWatchdog();

        await api.dispatch(
          webrtcApi.endpoints.disconnectFromPeer.initiate(
            { peerId, roomId },
            { track: false },
          ),
        );

        console.error(
          `RTC Connection with peer ${peerId} in room ${roomId} has ${epc.connectionState}.`,
        );

        if (wasConnected) requestPeersAfterEdgeTeardown(api, roomId, peerId);
      } else {
        if (disconnectTimeout) {
          clearTimeout(disconnectTimeout);
          disconnectTimeout = undefined;
        }

        if (epc.connectionState === "connected") {
          wasConnected = true;
          // This transport negotiated and reached the peer: it is not the
          // stranded responder the budget exists for, so the edge starts from
          // a clean budget the next time it is rebuilt.
          clearUnnegotiatedTransportWatchdog();
          clearUnnegotiatedTransportRebuilds(roomId, peerId);
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
