import { debugLog } from "../../utils/debug";
import signalingServerApi from "../signalingServerApi";

import { runRoomPeerExclusive } from "./negotiationLock";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import {
  discardIceCandidatesForAttempt,
  takePendingIceCandidates,
} from "./pendingIceCandidates";
import {
  detectRemoteTransportChange,
  resetEdgeAuthenticationForNewRemoteTransport,
} from "./remoteTransportChange";
import { isIdentityInitiator } from "../../utils/identityRole";
import { PROTOCOL_VERSION } from "../../utils/constants";

import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";
import { handleOpenChannel } from "../../handlers/handleOpenChannel";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  RTCSetDescriptionParams,
  IRTCPeerConnection,
  IRTCIceCandidate,
  IRTCDataChannel,
} from "./interfaces";
import type { WebSocketMessageDescriptionSend } from "../../utils/interfaces";

export interface RTCSetDescriptionParamsExtension extends RTCSetDescriptionParams {
  peerConnections: IRTCPeerConnection[];
  iceCandidates: IRTCIceCandidate[];
  dataChannels: IRTCDataChannel[];
}

// A predicate rather than inline checks: the PC may close during the awaits
// in the query body, and TypeScript's control-flow narrowing from the early
// `signalingState === "closed"` return would otherwise flag the later re-check
// as unreachable.
const isTransportClosed = (epc: IRTCPeerConnection): boolean =>
  epc.signalingState === "closed" || epc.connectionState === "closed";

const webrtcSetDescriptionQuery: BaseQueryFn<
  RTCSetDescriptionParamsExtension,
  undefined
> = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    description,
    rtcConfig,
    peerConnections,
    iceCandidates,
    dataChannels,
  },
  api,
) => {
  return runRoomPeerExclusive(roomId, peerId, async () => {
    const { keyPair } = api.getState() as State;

    const connectionIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
    );

    const epc =
      connectionIndex > -1
        ? peerConnections[connectionIndex]
        : await handleConnectToPeer(
            {
              peerId,
              peerPublicKey,
              roomId,
              peerConnections,
              rtcConfig,
            },
            api,
          );

    if (
      connectionIndex === -1 ||
      peerConnections[connectionIndex].ondatachannel == undefined
    ) {
      epc.ondatachannel = async (e: RTCDataChannelEvent) => {
        try {
          const channel = await handleOpenChannel(
            {
              channel: e.channel,
              epc,
              roomId: epc.roomId,
              dataChannels,
              incoming: true,
            },
            api,
          );
          if (channel.label === "main") epc.mainChannel = channel;
        } catch (error) {
          console.error("Rejected incoming DataChannel:", error);
        }
      };
    }

    // Compare the incoming fingerprint against the remote description applied
    // RIGHT NOW, before any rollback/ignore decision below can touch it. A
    // different DTLS certificate means the peer rebuilt its RTCPeerConnection
    // while ours survived (e.g. it tore the edge down during a radio-off
    // freeze shorter than the ICE consent timeout); everything this side
    // authenticated against the old certificate must be reset once the
    // description is actually applied. A fresh PC has nothing to compare.
    const remoteTransportChanged =
      connectionIndex > -1 &&
      detectRemoteTransportChange(epc.remoteDescription?.sdp, description.sdp);

    const offerCollision =
      description.type === "offer" &&
      (epc.makingOffer || epc.signalingState !== "stable");
    // Polite peer has the lexicographically smaller peerId, EXCEPT that an
    // outstanding offer on a transport that has never had a remote description
    // has nothing to lose, so its owner always yields. Invariant behind that
    // exception: only the identity initiator offers on a fresh transport (the
    // responder creates no channel there, so onnegotiationneeded never fires
    // for it), hence both sides can never be in that state at once. Without
    // it, an impolite initiator that re-dialed while the peer was unreachable
    // (its first offer lost) would ignore the peer's own offer on wake and
    // hold its never-answered PC forever, while the peer's older PC sits in
    // have-local-offer waiting for an answer that never comes.
    const isPolite =
      epc.remoteDescription == null || keyPair.peerId < epc.withPeerId;
    const ignoreOffer = !isPolite && offerCollision;
    epc.ignoreOffer = ignoreOffer;

    const discardIceForAttempt = (): void => {
      discardIceCandidatesForAttempt(
        epc.iceCandidates,
        iceCandidates,
        roomId,
        peerId,
      );
    };

    if (ignoreOffer) {
      discardIceForAttempt();
      return { data: undefined };
    }

    // Polite peer must rollback its local description before accepting remote offer
    if (offerCollision && isPolite) {
      try {
        await epc.setLocalDescription({ type: "rollback" });
        debugLog(`Polite peer rolled back local description for ${peerId}`);
      } catch (e) {
        console.error(`Failed to rollback for ${peerId}:`, e);
      }
    }

    epc.iceCandidates.push(
      ...takePendingIceCandidates(iceCandidates, roomId, peerId),
    );

    if (findRoomPeerConnectionIndex(peerConnections, roomId, peerId) === -1)
      peerConnections.push(epc);

    if (epc.signalingState === "closed") {
      discardIceForAttempt();
      return { data: undefined };
    }

    if (
      description.type === "answer" &&
      epc.signalingState !== "have-local-offer"
    ) {
      console.warn(
        `Ignoring stale answer from ${peerId} in signaling state ${epc.signalingState}`,
      );
      discardIceForAttempt();
      return { data: undefined };
    }

    {
      if (remoteTransportChanged)
        resetEdgeAuthenticationForNewRemoteTransport({
          epc,
          roomId,
          peerId,
          api,
          reason: new Error(
            `Remote DTLS certificate changed (${roomId}, ${peerId})`,
          ),
        });
      try {
        await epc.setRemoteDescription(description);
      } catch (e: unknown) {
        // Handle ICE restart mismatch - if we receive an offer with new ICE credentials
        // but didn't request a restart, we need to accept the restart gracefully
        const error = e as { message?: string };
        if (
          description.type === "answer" &&
          error.message?.includes("Called in wrong state")
        ) {
          console.warn(`Ignoring late answer from ${peerId}: ${error.message}`);
          discardIceForAttempt();
          return { data: undefined };
        }

        if (error.message?.includes("ICE restart")) {
          console.warn(
            `ICE restart mismatch with ${peerId}, accepting remote restart`,
          );
          try {
            // Rollback and accept the restart
            if (epc.signalingState !== "stable") {
              await epc.setLocalDescription({ type: "rollback" });
            }
            await epc.setRemoteDescription(description);
          } catch (retryError) {
            console.error(
              `Failed to handle ICE restart for ${peerId}:`,
              retryError,
            );
            discardIceForAttempt();
            return { data: undefined };
          }
        } else {
          console.error(`setRemoteDescription failed for ${peerId}:`, e);
          discardIceForAttempt();
          return { data: undefined };
        }
      }
      if (description.type === "offer") {
        try {
          await epc.setLocalDescription();
        } catch (error) {
          console.error(`setLocalDescription failed for ${peerId}:`, error);
          discardIceForAttempt();
          return { data: undefined };
        }
        const answer = epc.localDescription;
        if (answer) {
          await api.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "description",
                description: answer,
                fromPeerId: keyPair.peerId,
                fromPeerPublicKey: keyPair.publicKey,
                toPeerId: peerId,
                roomId,
                protocolVersion: PROTOCOL_VERSION,
              } as WebSocketMessageDescriptionSend,
            }),
          );
        }
      }
    }

    // Open `main` for the identity initiator whenever this transport has no
    // live one. Deliberately NOT gated on connectionIndex > -1 or
    // connectionState === "connected": after a reconnect the responder may
    // legitimately offer first (its PC was rebuilt while ours survived, or
    // ours was just created from its inbound offer), so the initiator must
    // answer AND open main on that PC; and data channels may be created before
    // the transport reaches "connected" (SCTP opens them once DTLS completes).
    // When the transport reset above closed a stale main, epc.mainChannel is
    // already undefined, so this opens exactly one replacement per call.
    if (
      !isTransportClosed(epc) &&
      isIdentityInitiator(keyPair.publicKey, epc.withPeerPublicKey) &&
      (!epc.mainChannel ||
        epc.mainChannel.readyState === "closing" ||
        epc.mainChannel.readyState === "closed")
    ) {
      const channel = epc.createDataChannel("main", {
        // Handshake HELLO/CONFIRM frames are a strict transcript sequence.
        ordered: true,
        protocol: "raw",
      });
      epc.mainChannel = await handleOpenChannel(
        { channel, epc, roomId: epc.roomId, dataChannels },
        api,
      );
    }

    return { data: undefined };
  });
};

export default webrtcSetDescriptionQuery;
