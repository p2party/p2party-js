import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";

export interface Room {
  url: string;
  id?: string;
}

const initialState: Room[] = [];

const roomsSlice = createSlice({
  name: "rooms",
  initialState,
  reducers: {
    setRoomUrl: (state, action: PayloadAction<string>) => {
      const url = action.payload;

      const roomIndex = state.findIndex((r) => r.url === url);

      if (roomIndex > -1) return state;

      state.push({ url });

      return state;
    },

    setRoom: (state, action: PayloadAction<Room>) => {
      const { url, id } = action.payload;
      if (!isUUID(id)) return state;

      const roomIndex = state.findIndex((r) => r.url === url);

      if (roomIndex !== -1) {
        if (state[roomIndex].id !== id) {
          state.splice(
            roomIndex,
            1,
            Object.assign(state[roomIndex], {
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

export const { setRoom, setRoomUrl } = roomsSlice.actions;
export const roomsSelector = (state: RoomState) => state.rooms;
export default roomsSlice.reducer;
