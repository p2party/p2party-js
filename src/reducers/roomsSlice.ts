import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";

export interface Room {
  url: string;
  id: string;
}

const initialState: Room[] = [];

const roomsSlice = createSlice({
  name: "rooms",
  initialState,
  reducers: {
    setRoom: (state, action: PayloadAction<Room>) => {
      const { url, id } = action.payload;
      if (!isUUID(id)) return state;

      const roomIndex = state.findIndex((r) => r.url === url);

      if (roomIndex > -1) {
        if (state[roomIndex].id !== id) {
          const data = state[roomIndex];
          state.splice(
            roomIndex,
            1,
            Object.assign(data, {
              id,
            }),
          );
        } else {
          return state;
        }
      } else {
        state.push(action.payload);
      }

      return state;
    },
  },
});

export const { setRoom } = roomsSlice.actions;
export const roomsSelector = (state: RoomState) => state.rooms;
export default roomsSlice.reducer;
