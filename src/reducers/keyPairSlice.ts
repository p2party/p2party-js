import { createSlice } from "@reduxjs/toolkit";
import { isHexadecimal, isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";

export interface KeyPair {
  peerId: string;
  publicKey: string;
  secretKey: string;
  challenge: string;
  signature: string;
}

export interface SetKeyPair {
  publicKey: string;
  secretKey: string;
}

export interface SetPeerData {
  peerId: string;
  challenge: string;
  signature: string;
}

const initialState: KeyPair = {
  peerId: localStorage.getItem("peerId") ?? "",
  publicKey: localStorage.getItem("publicKey") ?? "",
  secretKey: localStorage.getItem("secretKey") ?? "",
  challenge: localStorage.getItem("challenge") ?? "",
  signature: localStorage.getItem("signature") ?? "",
};

const keyPairSlice = createSlice({
  name: "keyPair",
  initialState,
  reducers: {
    setKeyPair: (state, action: PayloadAction<SetKeyPair>) => {
      localStorage.setItem("secretKey", action.payload.secretKey);
      localStorage.setItem("publicKey", action.payload.publicKey);

      return {
        ...state,
        publicKey: action.payload.publicKey,
        secretKey: action.payload.secretKey,
      };
    },

    setPeerData: (state, action: PayloadAction<SetPeerData>) => {
      const { peerId, challenge, signature } = action.payload;

      if (
        !isUUID(peerId, 4) ||
        !isHexadecimal(challenge) ||
        !isHexadecimal(signature) ||
        challenge.length !== 64 ||
        signature.length !== 1024
      ) {
        return state;
      }

      localStorage.setItem("peerId", peerId);
      localStorage.setItem("challenge", challenge);
      localStorage.setItem("signature", signature);

      return {
        ...state,
        peerId,
        challenge,
        signature,
      };
    },
  },
});

export const { setKeyPair, setPeerData } = keyPairSlice.actions;
export const keyPairSelector = (state: RoomState) => state.keyPair;
export default keyPairSlice.reducer;
