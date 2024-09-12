import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";

export interface SignalingState {
  isEstablishingConnection: boolean;
  isConnected: boolean;
  serverUrl: string;
}

const initialState: SignalingState = {
  isEstablishingConnection: false,
  isConnected: false,
  serverUrl: "ws://localhost:3001/ws",
};

const signalingServerSlice = createSlice({
  name: "signalingServer",
  initialState,
  reducers: {
    startConnecting: (state, action: PayloadAction<string | undefined>) => {
      state.isEstablishingConnection = true;
      state.serverUrl = action.payload ?? "ws://localhost:3001/ws";
    },

    connectionEstablished: (state) => {
      state.isConnected = true;
      state.isEstablishingConnection = true;
    },

    disconnect: (state) => {
      state.isConnected = false;
      state.isEstablishingConnection = false;
    },

    sendMessage: (
      state,
      _action: PayloadAction<{
        content: unknown;
      }>,
    ) => {
      return state;
    },

    // receiveMessage: (
    //   state,
    //   action: PayloadAction<{
    //     message: PeerId | Description | Candidate;
    //   }>,
    // ) => {
    //   state.messages.push(action.payload.message);
    // },
  },
});

export const signalingServerActions = signalingServerSlice.actions;
export const signalingServerSelector = (state: RoomState) =>
  state.signalingServer;
export default signalingServerSlice.reducer;
