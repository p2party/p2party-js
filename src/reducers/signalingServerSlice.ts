import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";

export interface SignalingState {
  isEstablishingConnection: boolean;
  isConnected: boolean;
  isVerified: boolean;
  serverUrl: string;
}

const defaultServerUrl = "wss://signaling.p2party.com/ws";

const initialState: SignalingState = {
  isEstablishingConnection: false,
  isConnected: false,
  isVerified: false,
  serverUrl: defaultServerUrl,
};

const signalingServerSlice = createSlice({
  name: "signalingServer",
  initialState,
  reducers: {
    startConnecting: (state, action: PayloadAction<string | undefined>) => {
      state.isEstablishingConnection = true;
      state.serverUrl = action.payload ?? defaultServerUrl;
    },

    connectionEstablished: (state) => {
      state.isConnected = true;
      state.isEstablishingConnection = false;
      state.isVerified = false;
    },

    connectionVerified: (state) => {
      state.isConnected = true;
      state.isEstablishingConnection = false;
      state.isVerified = true;
    },

    disconnect: (state) => {
      state.isConnected = false;
      state.isEstablishingConnection = false;
      state.isVerified = false;
    },
  },
});

export const signalingServerActions = signalingServerSlice.actions;
export const signalingServerSelector = (state: State) => state.signalingServer;
export default signalingServerSlice.reducer;
