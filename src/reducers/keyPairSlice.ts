import {
  createSlice,
  // createAsyncThunk
} from "@reduxjs/toolkit";
import { isHexadecimal, isUUID } from "class-validator";

// import { exportPemKeys } from "../utils/exportPEMKeys";

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
  peerId: "",
  publicKey: "",
  secretKey: "",
  challenge: "",
  signature: "",
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
      state.publicKey = action.payload.publicKey;
      state.secretKey = action.payload.secretKey;
    },

    setPeerData: (state, action: PayloadAction<SetPeerData>) => {
      const { peerId, challenge, signature } = action.payload;

      if (
        isUUID(peerId, 4) &&
        isHexadecimal(challenge) &&
        isHexadecimal(signature) &&
        challenge.length === 64 &&
        signature.length === 1024
      ) {
        state.peerId = peerId;
        state.challenge = challenge;
        state.signature = signature;
      }
    },
  },
  // extraReducers: (builder) => {
  //   builder.addCase(
  //     setKeyPair.fulfilled,
  //     (state, action: PayloadAction<SetKeyPair>) => {
  //       state.publicKey = action.payload.publicKey;
  //       state.secretKey = action.payload.secretKey;
  //     },
  //   );
  //
  //   builder.addCase(setKeyPair.rejected, (state, _action) => {
  //     state.publicKey = "";
  //     state.secretKey = "";
  //   });
  // },
});

export const { setKeyPair, setPeerData } = keyPairSlice.actions;
export const keyPairSelector = (state: RoomState) => state.keyPair;
export default keyPairSlice.reducer;
