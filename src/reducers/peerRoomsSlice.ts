import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";

export interface SetPeerRoomArgs {
  withPeerId: string;
  roomId: string;
}

export interface PeerRooms {
  withPeerId: string;
  roomIds: string[];
}

const initialState: PeerRooms[] = [];

const peerRoomsSlice = createSlice({
  name: "peerRooms",
  initialState,
  reducers: {
    setPeerRoom: (state, action: PayloadAction<SetPeerRoomArgs>) => {
      const { withPeerId, roomId } = action.payload;

      if (isUUID(withPeerId) && isUUID(roomId)) {
        const peerRoomsIndex = state.findIndex((p) => {
          p.withPeerId === withPeerId;
        });

        if (peerRoomsIndex > -1) {
          const roomIndex = state[peerRoomsIndex].roomIds.findIndex((r) => {
            r === roomId;
          });

          if (roomIndex === -1) {
            state[peerRoomsIndex].roomIds.push(roomId);
          }
        } else {
          state.push({ withPeerId, roomIds: [roomId] });
        }
      }
    },
  },
});

export const { setPeerRoom } = peerRoomsSlice.actions;
export const peerRoomsSelector = (state: State) => state.room;
export default peerRoomsSlice.reducer;
