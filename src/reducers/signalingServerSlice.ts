import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";

export interface SignalingState {
  isEstablishingConnection: boolean;
  isConnected: boolean;
  isVerified: boolean;
  serverUrl: string;
  refusal?: "version-mismatch";
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
      delete state.refusal;
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

    disconnect: (
      state,
      action: PayloadAction<"version-mismatch" | undefined>,
    ) => {
      if (action.payload) state.refusal = action.payload;
      else delete state.refusal;
      state.isConnected = false;
      state.isEstablishingConnection = false;
      state.isVerified = false;
    },
  },
});

export const signalingServerActions = signalingServerSlice.actions;
export const signalingServerSelector = (state: {
  readonly signalingServer: SignalingState;
}): SignalingState => state.signalingServer;
export default signalingServerSlice.reducer;
