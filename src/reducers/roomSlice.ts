import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";

export interface Channel {
  label: string;
  peerId: string;
}

export interface Peer {
  peerId: string;
  peerPublicKey: string;
}

export interface Message {
  id: string;
  message: string;
  fromPeerId: string;
  toPeerId: string;
  channelLabel: string;
  timestamp: number;
}

export interface SetRoomArgs {
  url: string;
  id: string;
  rtcConfig?: RTCConfiguration;
}

export interface Room extends SetRoomArgs {
  connectingToPeers: boolean;
  connectedToPeers: boolean;
  rtcConfig: RTCConfiguration;
  peers: Peer[];
  channels: Channel[];
  messages: Message[];
}

const initialState: Room = {
  url: "",
  id: "",
  connectingToPeers: false,
  connectedToPeers: false,
  rtcConfig: {
    iceServers: [
      {
        urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
      },
    ],
  },
  peers: [],
  channels: [],
  messages: [],
};

const roomSlice = createSlice({
  name: "room",
  initialState,
  reducers: {
    setRoom: (state, action: PayloadAction<SetRoomArgs>) => {
      const { url, id, rtcConfig } = action.payload;

      if (url.length > 0) state.url = url;
      if (isUUID(id)) state.id = id;
      if (rtcConfig) state.rtcConfig = rtcConfig;
    },

    setConnectingToPeers: (state, action: PayloadAction<boolean>) => {
      state.connectingToPeers = action.payload;
    },

    setConnectedToPeers: (state, action: PayloadAction<boolean>) => {
      state.connectingToPeers = false;
      state.connectedToPeers = action.payload;
    },

    setPeer: (state, action: PayloadAction<Peer>) => {
      const peerIndex = state.peers.findIndex(
        (p) => p.peerId === action.payload.peerId,
      );

      if (peerIndex === -1) state.peers.push(action.payload);
    },

    deletePeer: (state, action: PayloadAction<{ peerId: string }>) => {
      const peerIndex = state.peers.findIndex(
        (p) => p.peerId === action.payload.peerId,
      );

      if (peerIndex > -1) state.peers.splice(peerIndex, 1);
    },

    setChannel: (state, action: PayloadAction<Channel>) => {
      const channelIndex = state.channels.findIndex(
        (c) =>
          c.peerId === action.payload.peerId &&
          c.label === action.payload.label,
      );

      if (channelIndex === -1) state.channels.push(action.payload);
    },

    deleteChannel: (
      state,
      action: PayloadAction<{ peerId: string; label: string }>,
    ) => {
      const channelIndex = state.channels.findIndex(
        (c) =>
          c.peerId === action.payload.peerId &&
          c.label === action.payload.label,
      );

      if (channelIndex > -1) state.channels.splice(channelIndex, 1);
    },

    setMessage: (state, action: PayloadAction<Message>) => {
      const messageIndex = state.messages.findIndex(
        (m) =>
          m.fromPeerId === action.payload.fromPeerId &&
          m.toPeerId === action.payload.toPeerId &&
          m.message === action.payload.message &&
          m.channelLabel === action.payload.channelLabel &&
          m.timestamp === action.payload.timestamp,
      );

      if (messageIndex === -1) state.messages.push(action.payload);
    },

    deleteMessage: (
      state,
      action: PayloadAction<{ peerId: string; label: string }>,
    ) => {
      const messageIndex = state.messages.findIndex(
        (m) =>
          (m.channelLabel === action.payload.label &&
            m.fromPeerId === action.payload.peerId) ||
          m.toPeerId === action.payload.peerId,
      );

      if (messageIndex > -1) state.messages.splice(messageIndex, 1);
    },
  },
});

export const {
  setRoom,
  setConnectingToPeers,
  setConnectedToPeers,
  setPeer,
  setChannel,
  setMessage,
  deletePeer,
  deleteChannel,
  deleteMessage,
} = roomSlice.actions;
export const roomSelector = (state: State) => state.room;
export default roomSlice.reducer;
