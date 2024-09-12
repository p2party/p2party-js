import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";

export interface KeyPair {
  peerId: string;
  publicKey: string;
  secretKey: string;
}

export interface SetKeyPair {
  publicKey: string;
  secretKey: string;
}

export interface SetPeerId {
  peerId: string;
}

const initialState: KeyPair = {
  peerId: "",
  publicKey: "",
  secretKey: "",
};

const keyPairSlice = createSlice({
  name: "keyPair",
  initialState,
  reducers: {
    setKeyPair: (state, action: PayloadAction<SetKeyPair>) => {
      return {
        ...state,
        publicKey: action.payload.publicKey,
        secretKey: action.payload.secretKey,
      };
    },
    setPeerId: (state, action: PayloadAction<SetPeerId>) => {
      if (!isUUID(action.payload.peerId, 4)) return state;

      return {
        ...state,
        peerId: action.payload.peerId,
      };
    },
  },
});

export const { setKeyPair, setPeerId } = keyPairSlice.actions;
export const keyPairSelector = (state: RoomState) => state.keyPair;
export default keyPairSlice.reducer;
