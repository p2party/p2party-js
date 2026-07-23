import { handleOpenChannel } from "../../handlers/handleOpenChannel";
import { handleConnectToPeer } from "../../handlers/handleConnectToPeer";

import { getDBPeerIsBlacklisted } from "../../db/api";

import { findRoomPeerConnectionIndex } from "./roomPeer";
import { getRoomPeerMutex } from "./negotiationLock";
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

const attachDataChannelHandler = (
  epc: IRTCPeerConnection,
  dataChannels: IRTCDataChannel[],
  api: Parameters<typeof handleOpenChannel>[1],
): void => {
  epc.ondatachannel = async (event: RTCDataChannelEvent) => {
    try {
      const channel = await handleOpenChannel(
        {
          channel: event.channel,
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
    peerConnections,
    dataChannels,
  },
  api,
) => {
  return getRoomPeerMutex(roomId, peerId).runExclusive(async () => {
    const { keyPair } = api.getState() as State;
    if (peerId === keyPair.peerId)
      throw new Error("Cannot create a connection with oneself.");
    const opensMain = isIdentityInitiator(
      keyPair.publicKey,
      peerPublicKey,
    );

    const blacklisted = await getDBPeerIsBlacklisted(peerId);
    if (blacklisted) return { data: undefined };

    const connectionIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
    );

    if (connectionIndex > -1) {
      const epc = peerConnections[connectionIndex];
      if (
        epc.connectionState !== "closed" &&
        epc.connectionState !== "failed"
      ) {
        if (
          opensMain &&
          (!epc.mainChannel ||
            epc.mainChannel.readyState === "closing" ||
            epc.mainChannel.readyState === "closed")
        )
          await openMainChannel(epc, dataChannels, api);
        return { data: undefined };
      }

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

    if (opensMain) await openMainChannel(epc, dataChannels, api);

    return { data: undefined };
  });
};

export default webrtcBaseQuery;
