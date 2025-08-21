import { deleteDB } from "../../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectParams,
} from "./interfaces";
import { deletePeer } from "../../reducers/roomSlice";

export interface RTCDisconnectParamsExtension extends RTCDisconnectParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectQuery: BaseQueryFn<
  RTCDisconnectParamsExtension,
  void,
  unknown
> = async ({ alsoDeleteDB, peerConnections, dataChannels }, api) => {
  const CHANNELS_LEN = dataChannels.length;
  for (let i = 0; i < CHANNELS_LEN; i++) {
    if (dataChannels[i].readyState !== "open") continue;

    // dataChannels[i].onopen = null;
    // dataChannels[i].onclose = null;
    // dataChannels[i].onerror = null;
    // dataChannels[i].onclosing = null;
    // dataChannels[i].onmessage = null;
    // dataChannels[i].onbufferedamountlow = null;
    dataChannels[i].close();
    // dataChannels.splice(i, 1);
  }

  const PEERS_LEN = peerConnections.length;
  for (let i = 0; i < PEERS_LEN; i++) {
    api.dispatch(deletePeer({ peerId: peerConnections[i].withPeerId }));
    // if (
    //   peerConnections[i].connectionState !== "connected" &&
    //   peerConnections[i].connectionState !== "failed"
    // )
    //   continue;

    peerConnections[i].ontrack = null;
    peerConnections[i].ondatachannel = null;
    peerConnections[i].onicecandidate = null;
    peerConnections[i].onicecandidateerror = null;
    peerConnections[i].onnegotiationneeded = null;
    peerConnections[i].onsignalingstatechange = null;
    peerConnections[i].onconnectionstatechange = null;
    peerConnections[i].onicegatheringstatechange = null;
    peerConnections[i].oniceconnectionstatechange = null;
    if (peerConnections[i].connectionState !== "closed")
      peerConnections[i].close();
    delete peerConnections[i];
    peerConnections.splice(i, 1);
  }

  if (alsoDeleteDB) await deleteDB();

  return { data: undefined };
};

export default webrtcDisconnectQuery;
