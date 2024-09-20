import { createListenerMiddleware } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import { setConnectingToPeers } from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";

import type { RootState } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  actionCreator: setConnectingToPeers,
  effect: async (action, listenerApi) => {
    const connectingToPeers = action.payload;
    if (connectingToPeers) {
      const { signalingServer, keyPair, room } =
        listenerApi.getState() as RootState;

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
  },
});

export default roomListenerMiddleware;
