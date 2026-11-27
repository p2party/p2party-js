import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";

import { getDBPeerIsBlacklisted } from "../../db/api";

import { attachDataChannelHandler } from "./dataChannelHandler";
import { teardownEdgeGeneration } from "./disconnectFromPeerQuery";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import { runRoomPeerExclusive } from "./negotiationLock";
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
import { allowPeerHandshakeRetry } from "../../reducers/roomSlice";

export interface RTCPeerConnectionParamsExtend extends RTCPeerConnectionParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

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

    const blacklisted = await getDBPeerIsBlacklisted(peerPublicKey);
    if (blacklisted) return { data: undefined };

    // A server `connection` follows the peer building a fresh transport. It
    // allows a corrected PIN on just that peer to retry our failed edge.
    // Advisory roster repeats do not carry this intent. The current wire does
    // not distinguish manual remote retries from remote socket reconnects;
    // both remain subject to the existing durable PIN attempt throttle.
    if (peerSocketGenerationSource === "connection")
      api.dispatch(allowPeerHandshakeRetry({ roomId, peerId, peerPublicKey }));

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

      // The retired generation goes through the same teardown as a
      // disconnected one: its ratchet, PQ runtime and message keys are wiped,
      // its PQ healing interval and scheduled cover stop, its channels are
      // detached and unregistered (a late close event from its main must not
      // run disconnectFromPeer against the replacement built below), and the
      // remote certificate it was bound to is retired: an answer the peer
      // still produces on that transport must never bind the replacement,
      // which has no remote description of its own to compare a fingerprint
      // against (see retiredRemoteTransports).
      //
      // The teardown also deletes the persisted ratchet row this generation
      // wrote and clears its handshake status, so a replacement that never
      // authenticates is not shown as authenticated. What disconnectFromPeer
      // additionally does is room/peer-wide and stays with the edge, which
      // lives on in the replacement: the negotiation lock is held by this very
      // operation, and the roster entry describes the peer, not the transport.
      teardownEdgeGeneration(epc, { dataChannels, dispatch: api.dispatch });
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
