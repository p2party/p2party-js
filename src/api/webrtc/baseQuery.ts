import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";
import { teardownCoverEdge } from "../../handlers/coverEdge";

import { getDBPeerIsBlacklisted } from "../../db/api";

import { attachDataChannelHandler } from "./dataChannelHandler";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import { runRoomPeerExclusive } from "./negotiationLock";
import { retireRemoteTransport } from "./retiredRemoteTransports";
import {
  isCanonicalSocketGeneration,
  markPeerSocketGenerationRetired,
  shouldRetireTransportForSocketGeneration,
} from "./peerSocketGeneration";
import { isIdentityInitiator } from "../../utils/identityRole";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  RTCPeerConnectionParams,
  IRTCPeerConnection,
  IRTCDataChannel,
} from "./interfaces";
import type { State } from "../../store";

export interface RTCPeerConnectionParamsExtend extends RTCPeerConnectionParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const clearConnectionHandlers = (epc: IRTCPeerConnection): void => {
  epc.ontrack = null;
  epc.ondatachannel = null;
  epc.onicecandidate = null;
  epc.onicecandidateerror = null;
  epc.onnegotiationneeded = null;
  epc.onsignalingstatechange = null;
  epc.onconnectionstatechange = null;
  epc.onicegatheringstatechange = null;
  epc.oniceconnectionstatechange = null;
};

const openMainChannel = async (
  epc: IRTCPeerConnection,
  dataChannels: IRTCDataChannel[],
  api: Parameters<typeof handleOpenChannel>[1],
): Promise<void> => {
  // Passing the newly-created channel object bypasses handleOpenChannel's
  // legacy peer+label lookup, which cannot distinguish identical labels in
  // different rooms.
  const channel = epc.createDataChannel("main", {
    // Handshake HELLO/CONFIRM frames are a strict transcript sequence.
    ordered: true,
    protocol: "raw",
  });
  epc.mainChannel = await handleOpenChannel(
    { channel, epc, roomId: epc.roomId, dataChannels },
    api,
  );
};

const webrtcBaseQuery: BaseQueryFn<
  RTCPeerConnectionParamsExtend,
  undefined
> = async (
  {
    peerId,
    peerPublicKey,
    roomId,
    rtcConfig,
    peerSocketGeneration,
    peerSocketGenerationSource,
    peerConnections,
    dataChannels,
  },
  api,
) => {
  return runRoomPeerExclusive(roomId, peerId, async () => {
    const { keyPair } = api.getState() as State;
    if (peerId === keyPair.peerId)
      throw new Error("Cannot create a connection with oneself.");
    const opensMain = isIdentityInitiator(keyPair.publicKey, peerPublicKey);

    const blacklisted = await getDBPeerIsBlacklisted(peerId);
    if (blacklisted) return { data: undefined };

    const connectionIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
    );

    if (connectionIndex > -1) {
      const epc = peerConnections[connectionIndex];
      // The peer's identity can reappear on a SECOND signaling socket (another
      // tab, a phrase-restored device): the server keeps the peerId and evicts
      // the old socket, so this transport is bound to a socket that no longer
      // exists. It will never fail on its own — no SDP, no ICE, no event — so
      // the generation is the only thing that can retire it (C1).
      const retiresForGeneration = shouldRetireTransportForSocketGeneration({
        roomId,
        peerId,
        recorded: epc.peerSocketGeneration,
        observed: peerSocketGeneration,
        source: peerSocketGenerationSource,
        connectionState: epc.connectionState,
      });
      if (
        !retiresForGeneration &&
        epc.connectionState !== "closed" &&
        epc.connectionState !== "failed"
      ) {
        // Adopt a generation we did not have: the first frame that names one
        // establishes the baseline this comparison needs. A generation that
        // DIFFERS is never adopted here — that would erase the very evidence
        // the peer's next `connection` frame has to act on.
        if (
          epc.peerSocketGeneration === undefined &&
          isCanonicalSocketGeneration(peerSocketGeneration)
        )
          epc.peerSocketGeneration = peerSocketGeneration;
        if (
          opensMain &&
          (!epc.mainChannel ||
            epc.mainChannel.readyState === "closing" ||
            epc.mainChannel.readyState === "closed")
        )
          await openMainChannel(epc, dataChannels, api);
        return { data: undefined };
      }

      // Remember the generation this transport was bound to, so a duplicate or
      // out-of-order introduction naming it cannot tear the REPLACEMENT down
      // on the way back: a UUIDv4 says nothing about which name is newer.
      if (retiresForGeneration)
        markPeerSocketGenerationRetired(
          roomId,
          peerId,
          epc.peerSocketGeneration,
        );

      // A replaced edge must stop claiming cover, same as a disconnected one,
      // and the remote certificate it was bound to is retired with it: an
      // answer the peer still produces on that transport must never bind the
      // replacement built below, which has no remote description of its own
      // to compare a fingerprint against (see retiredRemoteTransports).
      retireRemoteTransport(roomId, peerId, epc.remoteDescription?.sdp);
      teardownCoverEdge(epc);
      clearConnectionHandlers(epc);
      if (epc.connectionState !== "closed") epc.close();
      peerConnections.splice(connectionIndex, 1);
    }

    const epc = await handleConnectToPeer(
      { peerId, peerPublicKey, roomId, peerConnections, rtcConfig },
      api,
    );
    attachDataChannelHandler(epc, dataChannels, api);
    if (!peerConnections.includes(epc)) peerConnections.push(epc);
    if (isCanonicalSocketGeneration(peerSocketGeneration))
      epc.peerSocketGeneration = peerSocketGeneration;

    if (opensMain) await openMainChannel(epc, dataChannels, api);

    return { data: undefined };
  });
};

export default webrtcBaseQuery;
