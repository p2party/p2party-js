import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import {
  setConnectingToPeers,
  // setOnlyConnectWithKnownPeers,
  setRoom,
  setMessage,
  deleteMessage,
  deleteRoom,
  setMessageAllChunks,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { compileChannelMessageLabel } from "../utils/channelLabel";

import {
  deleteDBChunk,
  deleteDBMessageData,
  getDBRoomMessageData,
  setDBUniqueRoom,
} from "../db/api";

import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  matcher: isAnyOf(
    setConnectingToPeers,
    // setOnlyConnectWithKnownPeers,
    setRoom,
    setMessage,
    deleteMessage,
    deleteRoom,
  ),
  // actionCreator: setConnectingToPeers,
  effect: async (action, listenerApi) => {
    if (setConnectingToPeers.match(action)) {
      const { roomId, connectingToPeers } = action.payload;
      if (connectingToPeers) {
        const { signalingServer, keyPair, rooms } =
          listenerApi.getState() as State;

        const roomIndex = rooms.findIndex((r) => r.id === roomId);

        if (
          signalingServer.isConnected &&
          isUUID(keyPair.peerId) &&
          roomIndex > -1 &&
          isUUID(rooms[roomIndex].id)
        ) {
          listenerApi.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "peers",
                fromPeerId: keyPair.peerId,
                roomId,
              } as WebSocketMessagePeersRequest,
            }),
          );
        }

        listenerApi.dispatch(
          setConnectingToPeers({ roomId, connectingToPeers: false }),
        );
      }
    } else if (setRoom.match(action)) {
      await setDBUniqueRoom(action.payload.url, action.payload.id);

      const oldMessages = await getDBRoomMessageData(action.payload.id);
      const oldMessagesLen = oldMessages.length;
      for (let i = 0; i < oldMessagesLen; i++) {
        listenerApi.dispatch(setMessageAllChunks(oldMessages[i]));
      }

      if (action.payload.onlyConnectWithKnownPeers != undefined) {
        localStorage.setItem(
          action.payload.url + "-onlyConnectWithKnownPeers",
          String(action.payload.onlyConnectWithKnownPeers),
        );
      }

      const { signalingServer, keyPair, rooms } =
        listenerApi.getState() as State;

      const roomIndex = rooms.findIndex((r) => r.id === action.payload.id);

      if (
        signalingServer.isConnected &&
        isUUID(keyPair.peerId) &&
        roomIndex > -1 &&
        isUUID(rooms[roomIndex].id)
      ) {
        listenerApi.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "peers",
              fromPeerId: keyPair.peerId,
              roomId: rooms[roomIndex].id,
            } as WebSocketMessagePeersRequest,
          }),
        );
      }
    } else if (setMessage.match(action)) {
      const { roomId } = action.payload;
      const { keyPair, rooms } = listenerApi.getState() as State;
      const roomIndex = rooms.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const messageIndex = rooms[roomIndex].messages.findIndex(
          (m) => m.merkleRootHex === action.payload.merkleRootHex,
        );

        if (
          messageIndex > -1 &&
          rooms[roomIndex].messages[messageIndex].fromPeerId !==
            keyPair.peerId &&
          rooms[roomIndex].messages[messageIndex].savedSize ===
            rooms[roomIndex].messages[messageIndex].totalSize
        ) {
          const label = await compileChannelMessageLabel(
            rooms[roomIndex].messages[messageIndex].channelLabel,
            rooms[roomIndex].messages[messageIndex].merkleRootHex,
            rooms[roomIndex].messages[messageIndex].sha512Hex,
          );

          listenerApi.dispatch(
            webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
              label,
              alsoDeleteData: false,
            }),
          );
        }
      }
    } else if (deleteMessage.match(action)) {
      const { merkleRootHex } = action.payload;

      await deleteDBChunk(merkleRootHex);
      await deleteDBMessageData(merkleRootHex);
    } else if (deleteRoom.match(action)) {
      listenerApi.dispatch(
        webrtcApi.endpoints.disconnect.initiate({ alsoDeleteDB: true }),
      );
    }
  },
});

export default roomListenerMiddleware;
