import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import { setConnectingToPeers, setRoom } from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";

import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  matcher: isAnyOf(setConnectingToPeers, setRoom),
  // actionCreator: setConnectingToPeers,
  effect: async (action, listenerApi) => {
    if (setConnectingToPeers.match(action)) {
      const connectingToPeers = action.payload;
      if (connectingToPeers) {
        const { signalingServer, keyPair, room } =
          listenerApi.getState() as State;

        if (
          signalingServer.isConnected &&
          isUUID(keyPair.peerId) &&
          isUUID(room.id)
        ) {
          listenerApi.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "peers",
                fromPeerId: keyPair.peerId,
                roomId: room.id,
              } as WebSocketMessagePeersRequest,
            }),
          );
        }
      }
    } else if (setRoom.match(action)) {
      const { signalingServer, keyPair, room } =
        listenerApi.getState() as State;

      if (
        signalingServer.isConnected &&
        isUUID(keyPair.peerId) &&
        isUUID(room.id)
      ) {
        listenerApi.dispatch(setConnectingToPeers(true));
      }
    }
  },
});

export default roomListenerMiddleware;
