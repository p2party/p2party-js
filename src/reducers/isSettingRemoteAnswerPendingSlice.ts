import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RootState } from "../store";

const initialState = false;

const isSettingRemoteAnswerPendingSlice = createSlice({
  name: "isSettingRemoteAnswerPending",
  initialState,
  reducers: {
    setIsSettingRemoteAnswerPending: (
      _state,
      action: PayloadAction<boolean>,
    ) => {
      return action.payload;
    },
  },
});

export const { setIsSettingRemoteAnswerPending } =
  isSettingRemoteAnswerPendingSlice.actions;
export const isSettingRemoteAnswerPendingSelector = (state: RootState) =>
  state.isSettingRemoteAnswerPending;
export default isSettingRemoteAnswerPendingSlice.reducer;
