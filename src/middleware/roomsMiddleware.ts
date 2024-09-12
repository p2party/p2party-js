import { setRoomUrl } from "../reducers/roomsSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import type { Middleware } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";

const roomsMiddleware: Middleware = (store) => {
  return (next) => async (action) => {
    if (setRoomUrl.match(action)) {
      const { keyPair, rooms } = store.getState() as RoomState;
      const url = action.payload;
      const roomIndex = rooms.findIndex((r) => r.url === url);

      if (roomIndex > -1) return next(action);

      store.dispatch(
        signalingServerActions.sendMessage({
          content: {
            type: "room",
            fromPeerId: keyPair.peerId,
            roomUrl: url,
          },
        }),
      );
    }

    return next(action);
  };
};

export default roomsMiddleware;
