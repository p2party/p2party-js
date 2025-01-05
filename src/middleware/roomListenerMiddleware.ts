import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import {
  setConnectingToPeers,
  setRoom,
  setMessage,
  deleteMessage,
  deleteAll,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { deleteDBChunk } from "../db/api";

import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";
import { compileChannelMessageLabel } from "../utils/channelLabel";

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  matcher: isAnyOf(
    setConnectingToPeers,
    setRoom,
    setMessage,
    deleteMessage,
    deleteAll,
  ),
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
    } else if (setMessage.match(action)) {
      const { room } = listenerApi.getState() as State;
      const messageIndex = room.messages.findIndex(
        (m) => m.merkleRootHex === action.payload.merkleRootHex,
      );

      if (
        messageIndex > -1 &&
        room.messages[messageIndex].savedSize ===
          room.messages[messageIndex].totalSize
      ) {
        const label = await compileChannelMessageLabel(
          room.messages[messageIndex].channelLabel,
          room.messages[messageIndex].merkleRootHex,
          room.messages[messageIndex].sha512Hex,
        );

        listenerApi.dispatch(
          webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
            label,
            alsoDeleteData: false,
          }),
        );
      }
    } else if (deleteMessage.match(action)) {
      const { merkleRootHex } = action.payload;

      await deleteDBChunk(merkleRootHex);
    } else if (deleteAll.match(action)) {
      listenerApi.dispatch(
        webrtcApi.endpoints.disconnect.initiate({ alsoDeleteDB: true }),
      );
    }
  },
});

export default roomListenerMiddleware;
