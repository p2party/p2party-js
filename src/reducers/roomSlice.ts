import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RootState } from "../store";

export interface SetRoomArgs {
  url: string;
  id: string;
  rtcConfig?: RTCConfiguration;
}

export interface Room extends SetRoomArgs {
  connectingToPeers: boolean;
  connectedToPeers: boolean;
  rtcConfig: RTCConfiguration;
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
      const connectingToPeers = action.payload;

      state.connectingToPeers = connectingToPeers;
    },

    setConnectedToPeers: (state, action: PayloadAction<boolean>) => {
      const connectedToPeers = action.payload;

      state.connectingToPeers = false;
      state.connectedToPeers = connectedToPeers;
    },
  },
});

export const { setRoom, setConnectingToPeers, setConnectedToPeers } =
  roomSlice.actions;
export const roomSelector = (state: RootState) => state.room;
export default roomSlice.reducer;
