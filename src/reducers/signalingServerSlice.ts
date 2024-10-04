import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";

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
      state.isEstablishingConnection = false;
    },

    disconnect: (state) => {
      state.isConnected = false;
      state.isEstablishingConnection = false;
    },
  },
});

export const signalingServerActions = signalingServerSlice.actions;
export const signalingServerSelector = (state: State) => state.signalingServer;
export default signalingServerSlice.reducer;
