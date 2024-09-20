import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RootState } from "../store";

export interface IRTCPeerConnection extends RTCPeerConnection {
  peerIsInitiator: boolean; // If initiator then impolite
  withPeerId: string;
  withPeerPublicKey: string;
  makingOffer: boolean;
}

export interface IRTCIceCandidate extends RTCIceCandidate {
  withPeerId: string;
}

export interface IRTCSessionDescription extends RTCSessionDescription {
  withPeerId: string;
}

export interface SetPeerArgs {
  roomId: string;
  peerId: string;
  peerPublicKey: string;
  initiate: boolean;
  rtcConfig?: RTCConfiguration;
}

export interface SetPeerDescriptionArgs {
  peerId: string;
  peerPublicKey: string;
  roomId: string;
  description: RTCSessionDescription;
  rtcConfig?: RTCConfiguration;
}

export interface SetIceCandidateArgs {
  peerId: string;
  roomId: string;
  candidate: RTCIceCandidate;
}

export interface SetPeerChannelArgs {
  label: string;
  roomId: string;
  withPeerId: string;
}

export interface DeletePeerArgs {
  peerId: string;
}

export interface Peer {
  connectionIndex: number;
  id: string;
  publicKey: string;
}

const initialState: Peer[] = [];

const peersSlice = createSlice({
  name: "peers",
  initialState,
  reducers: {
    setPeer: (state, action: PayloadAction<SetPeerArgs>) => {
      const { peerId, peerPublicKey } = action.payload;

      // if (epc.withPeerId === peerId) return state;
      const peerIndex = state.findIndex((peer) => {
        peer.id === peerId;
      });

      if (peerIndex === -1) {
        const lastPeerIndex = state.length;
        state.push({
          connectionIndex: lastPeerIndex,
          id: peerId,
          publicKey: peerPublicKey,
        });
      } else {
        state[peerIndex] = {
          ...state[peerIndex],
          publicKey: peerPublicKey,
        };
      }

      return state;
    },

    setDescription: (state, _action: PayloadAction<SetPeerDescriptionArgs>) => {
      return state;
    },

    setCandidate: (state, _action: PayloadAction<SetIceCandidateArgs>) => {
      return state;
    },

    setPeerChannel: (state, _action: PayloadAction<SetPeerChannelArgs>) => {
      return state;
    },

    deletePeer: (state, action: PayloadAction<DeletePeerArgs>) => {
      const { peerId } = action.payload;

      const peerIndex = state.findIndex((peer) => peer.id === peerId);
      if (peerIndex > -1) {
        state.splice(peerIndex, 1);
      }

      return state;
    },

    deleteAllPeers: (_state) => {
      return [];
    },
  },
});

export const {
  setPeer,
  setDescription,
  setCandidate,
  setPeerChannel,
  deletePeer,
  deleteAllPeers,
} = peersSlice.actions;
export const peersSelector = (state: RootState) => state.peers;
export default peersSlice.reducer;
