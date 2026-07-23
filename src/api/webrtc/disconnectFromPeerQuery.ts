import {
  deleteChannel,
  deleteMessage,
  deletePeer,
} from "../../reducers/roomSlice";
import { wipeRatchet } from "../../cryptography/ratchet";
import { clearHandshakeChannel } from "../../handlers/handleHandshake";
import { rejectRatchetGate } from "../../handlers/ratchetGate";
import { releaseRoomPeerMutex } from "./negotiationLock";
import { discardPendingIceCandidates } from "./pendingIceCandidates";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCIceCandidate,
  IRTCPeerConnection,
  RTCDisconnectFromPeerParams,
} from "./interfaces";
import type { State } from "../../store";

export interface RTCDisconnectFromPeerParamsExtension extends RTCDisconnectFromPeerParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  iceCandidates: IRTCIceCandidate[];
}

const webrtcDisconnectPeerQuery: BaseQueryFn<
  RTCDisconnectFromPeerParamsExtension,
  undefined
> = (
  {
    peerId,
    roomId,
    alsoDeleteData,
    peerConnections,
    dataChannels,
    iceCandidates,
  },
  api,
) => {
  const terminalRoomIds = new Set<string>();
  for (let i = peerConnections.length - 1; i >= 0; i--) {
    const connection = peerConnections[i];
    if (
      connection.withPeerId !== peerId ||
      (roomId !== undefined && connection.roomId !== roomId)
    )
      continue;
    terminalRoomIds.add(connection.roomId);

    const teardownError = new Error(
      `Room/peer transport closed (${connection.roomId}, ${connection.withPeerId})`,
    );
    clearHandshakeChannel(
      connection.roomId,
      connection.withPeerId,
      teardownError,
    );
    rejectRatchetGate(
      connection.roomId,
      connection.withPeerId,
      teardownError,
    );
    if (connection.ratchetState) {
      wipeRatchet(connection.ratchetState);
      connection.ratchetState = undefined;
    }
    if (connection.messageKeyCache) {
      for (const messageKey of connection.messageKeyCache.values())
        messageKey.fill(0);
      connection.messageKeyCache.clear();
      connection.messageKeyCache = undefined;
    }
    connection.messageKeyByMerkleRoot?.clear();
    connection.messageKeyByMerkleRoot = undefined;
    connection.messageChannels?.clear();
    connection.messageChannels = undefined;
    connection.mainChannel = undefined;

    connection.ontrack = null;
    connection.ondatachannel = null;
    connection.onicecandidate = null;
    connection.onicecandidateerror = null;
    connection.onnegotiationneeded = null;
    connection.onsignalingstatechange = null;
    connection.onconnectionstatechange = null;
    connection.onicegatheringstatechange = null;
    connection.oniceconnectionstatechange = null;
    if (connection.connectionState !== "closed") connection.close();
    peerConnections.splice(i, 1);
  }

  if (roomId !== undefined) terminalRoomIds.add(roomId);
  for (const terminalRoomId of terminalRoomIds) {
    discardPendingIceCandidates(iceCandidates, terminalRoomId, peerId);
    releaseRoomPeerMutex(terminalRoomId, peerId);
  }

  // Omitting roomId is the explicitly peer-wide operation.
  api.dispatch(deletePeer({ peerId, roomId }));
  api.dispatch(deleteChannel({ peerId, roomId }));

  for (let i = dataChannels.length - 1; i >= 0; i--) {
    const channel = dataChannels[i];
    if (
      channel.withPeerId !== peerId ||
      (roomId !== undefined && !channel.roomIds.includes(roomId))
    )
      continue;

    channel.releaseProtocolResources?.();
    channel.onopen = null;
    channel.onclose = null;
    channel.onerror = null;
    channel.onclosing = null;
    channel.onmessage = null;
    channel.onbufferedamountlow = null;
    if (channel.readyState !== "closed") channel.close();
    dataChannels.splice(i, 1);
  }

  if (alsoDeleteData) {
    const { rooms } = api.getState() as State;
    const roomsLen = rooms.length;
    for (let i = 0; i < roomsLen; i++) {
      if (roomId !== undefined && rooms[i].id !== roomId) continue;

      const messagesLen = rooms[i].messages.length;
      for (let j = 0; j < messagesLen; j++) {
        if (rooms[i].messages[j].fromPeerId === peerId) {
          api.dispatch(
            deleteMessage({
              roomId: rooms[i].id,
              merkleRootHex: rooms[i].messages[j].merkleRootHex,
            }),
          );
        }
      }
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectPeerQuery;
