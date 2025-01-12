import { createSlice } from "@reduxjs/toolkit";
import { isHexadecimal, isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";

export interface KeyPair {
  peerId: string;
  challengeId: string;
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

export interface SetChallengeId {
  challengeId: string;
  username?: string;
  credential?: string;
}

export interface SetReconnectData extends SetPeerData {
  challengeId: string;
  username?: string;
  credential?: string;
}

const initialState: KeyPair = {
  peerId: localStorage.getItem("peerId") ?? "",
  challengeId: localStorage.getItem("challengeId") ?? "",
  publicKey: localStorage.getItem("publicKey") ?? "",
  secretKey: localStorage.getItem("secretKey") ?? "",
  challenge: localStorage.getItem("challenge") ?? "",
  signature: localStorage.getItem("signature") ?? "",
};

// export const setKeyPair = createAsyncThunk(
//   "keyPair/setKeyPair",
//   async (_: void, thunkApi) => {
//     try {
//       const publicKey = localStorage.getItem("publicKey") ?? "";
//       const secretKey = localStorage.getItem("secretKey") ?? "";
//
//       if (publicKey.length === 0 || secretKey.length === 0) {
//         const newKeyPair = await crypto.subtle.generateKey(
//           {
//             name: "RSA-PSS",
//             hash: "SHA-256",
//             modulusLength: 4096,
//             publicExponent: new Uint8Array([1, 0, 1]),
//           },
//           true,
//           ["sign", "verify"],
//         );
//
//         const pair = await exportPemKeys(newKeyPair);
//
//         localStorage.setItem("secretKey", pair.secretKey);
//         localStorage.setItem("publicKey", pair.publicKey);
//
//         return pair as SetKeyPair;
//       } else {
//         return { publicKey, secretKey } as SetKeyPair;
//       }
//     } catch (error) {
//       return thunkApi.rejectWithValue(error);
//     }
//   },
//   {
//     condition: (_: void, { getState }) => {
//       const { keyPair } = getState() as RoomState;
//       if (keyPair.secretKey.length > 0 && keyPair.publicKey.length > 0) {
//         return false;
//       } else {
//         return true;
//       }
//     },
//   },
// );

const keyPairSlice = createSlice({
  name: "keyPair",
  initialState,
  reducers: {
    setKeyPair: (state, action: PayloadAction<SetKeyPair>) => {
      const { publicKey, secretKey } = action.payload;

      if (publicKey.length === 64 && secretKey.length === 128) {
        state.publicKey = action.payload.publicKey;
        state.secretKey = action.payload.secretKey;
      }
    },

    setReconnectData: (state, action: PayloadAction<SetReconnectData>) => {
      const { peerId, challenge, signature, challengeId } = action.payload;

      if (
        isUUID(peerId, 4) &&
        isUUID(challengeId) &&
        isHexadecimal(challenge) &&
        isHexadecimal(signature) &&
        challenge.length === 64 &&
        // signature.length === 1024
        signature.length === 128
      ) {
        state.peerId = peerId;
        state.challenge = challenge;
        state.signature = signature;
        state.challengeId = challengeId;
      }
    },

    setPeerData: (state, action: PayloadAction<SetPeerData>) => {
      const { peerId, challenge, signature } = action.payload;

      if (
        isUUID(peerId, 4) &&
        isHexadecimal(challenge) &&
        isHexadecimal(signature) &&
        challenge.length === 64 &&
        // signature.length === 1024
        signature.length === 128
      ) {
        state.peerId = peerId;
        state.challenge = challenge;
        state.signature = signature;
      }
    },

    setChallengeId: (state, action: PayloadAction<SetChallengeId>) => {
      const { challengeId } = action.payload;

      if (isUUID(challengeId)) state.challengeId = challengeId;
    },

    resetIdentity: (_state, _action: PayloadAction<void>) => {
      return {
        peerId: "",
        challengeId: "",
        publicKey: "",
        secretKey: "",
        challenge: "",
        signature: "",
      };
    },
  },
});

export const {
  setKeyPair,
  setReconnectData,
  setPeerData,
  setChallengeId,
  resetIdentity,
} = keyPairSlice.actions;
export const keyPairSelector = (state: State) => state.keyPair;
export default keyPairSlice.reducer;
