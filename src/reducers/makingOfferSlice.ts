import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";

export interface MakingOffer {
  withPeerId: string;
  makingOffer: boolean;
}

const initialState: MakingOffer[] = [];

const makingOfferSlice = createSlice({
  name: "makingOffer",
  initialState,
  reducers: {
    setMakingOffer: (state, action: PayloadAction<MakingOffer>) => {
      const offerIndex = state.findIndex((o) => {
        o.withPeerId === action.payload.withPeerId;
      });

      if (offerIndex === -1) {
        state.push(action.payload);
      } else if (state[offerIndex].makingOffer !== action.payload.makingOffer) {
        state[offerIndex].makingOffer = action.payload.makingOffer;
      }
    },
  },
});

export const { setMakingOffer } = makingOfferSlice.actions;
export const makingOfferSelector = (state: State) => state.makingOffer;
export default makingOfferSlice.reducer;
