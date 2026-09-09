import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";

export interface CommonState {
  currentRoomUrl: string;
}

const initialState: CommonState = {
  currentRoomUrl: "",
};

const commonSlice = createSlice({
  name: "commonState",
  initialState,
  reducers: {
    setCurrentRoomUrl: (state, action: PayloadAction<string>) => {
      state.currentRoomUrl = action.payload;
    },
  },
});

export const { setCurrentRoomUrl } = commonSlice.actions;
export const commonStateSelector = (state: {
  readonly commonState: CommonState;
}): CommonState => state.commonState;
export default commonSlice.reducer;
