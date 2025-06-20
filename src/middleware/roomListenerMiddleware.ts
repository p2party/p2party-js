import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import {
  setConnectingToPeers,
  setRoom,
  setMessage,
  deleteMessage,
  deleteRoom,
  setMessageAllChunks,
  setChannel,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { compileChannelMessageLabel } from "../utils/channelLabel";

import {
  deleteDBChunk,
  deleteDBMessageData,
  deleteDBNewChunk,
  // getDBMessageData,
  getDBRoomMessageData,
  // setDBRoomMessageData,
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
    setChannel,
    // setMessage,
    setMessageAllChunks,
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
    } else if (setChannel.match(action)) {
      // const { roomId, peerId } = action.payload;
      //
      // const pastMessages = await getDBRoomMessageData(roomId);
      // const len = pastMessages.length;
      // for (let i = 0; i < len; i++) {
      //   if (pastMessages[i]. pastMessages[i].savedSize < pastMessages[i].totalSize) {
      //
      //   }
      // }
    } else if (setRoom.match(action)) {
      const { signalingServer, keyPair, rooms } =
        listenerApi.getState() as State;

      const { url, id, onlyConnectWithKnownPeers } = action.payload;

      if (url.length === 64 && onlyConnectWithKnownPeers != undefined) {
        localStorage.setItem(
          url + "-onlyConnectWithKnownPeers",
          String(onlyConnectWithKnownPeers),
        );
      }

      if (url.length === 64 && isUUID(id)) {
        await setDBUniqueRoom(url, id);

        const oldMessages = await getDBRoomMessageData(id);
        const oldMessagesLen = oldMessages.length;
        for (let i = 0; i < oldMessagesLen; i++) {
          listenerApi.dispatch(
            setMessage({
              roomId: oldMessages[i].roomId,
              merkleRootHex: oldMessages[i].merkleRoot,
              sha512Hex: oldMessages[i].hash,
              fromPeerId: oldMessages[i].fromPeerId,
              filename: oldMessages[i].filename,
              messageType: oldMessages[i].messageType,
              chunkSize: oldMessages[i].savedSize,
              totalSize: oldMessages[i].totalSize,
              channelLabel: oldMessages[i].channelLabel,
              timestamp: oldMessages[i].timestamp,
            }),
          );
        }

        const roomIndex = rooms.findIndex((r) => r.id === id);

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
      }
      // } else if (setMessage.match(action)) {
    } else if (setMessageAllChunks.match(action)) {
      const { roomId, merkleRootHex, sha512Hex, alsoSendFinishedMessage } =
        action.payload;
      const { rooms, keyPair } = listenerApi.getState() as State;
      const roomIndex = rooms.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const messageIndex = rooms[roomIndex].messages.findLastIndex(
          (m) => m.merkleRootHex === merkleRootHex || m.sha512Hex === sha512Hex,
        );

        // const msg = await getDBMessageData(merkleRootHex);
        // if (
        //   messageIndex > -1 &&
        //   (rooms[roomIndex].messages[messageIndex].savedSize ===
        //     rooms[roomIndex].messages[messageIndex].totalSize ||
        //     rooms[roomIndex].messages[messageIndex].savedSize + chunkSize ===
        //       rooms[roomIndex].messages[messageIndex].totalSize) &&
        //   msg &&
        //   rooms[roomIndex].messages[messageIndex].totalSize === msg.totalSize &&
        //   msg.savedSize < msg.totalSize
        // ) {
        //   await setDBRoomMessageData(
        //     roomId,
        //     merkleRootHex,
        //     msg.hash,
        //     msg.fromPeerId,
        //     msg.totalSize - msg.savedSize,
        //     msg.totalSize,
        //     msg.messageType,
        //     msg.filename,
        //     msg.channelLabel,
        //     msg.timestamp,
        //   );
        // }

        if (
          messageIndex > -1 &&
          // If message receiver
          rooms[roomIndex].messages[messageIndex].fromPeerId !== keyPair.peerId
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
              alsoSendFinishedMessage,
            }),
          );
        }
      }
    } else if (deleteMessage.match(action)) {
      const { merkleRootHex } = action.payload;

      await deleteDBChunk(merkleRootHex);
      await deleteDBNewChunk(merkleRootHex);
      await deleteDBMessageData(merkleRootHex);
    } else if (deleteRoom.match(action)) {
      const roomId = action.payload;

      listenerApi.dispatch(
        webrtcApi.endpoints.disconnectFromRoom.initiate({
          roomId,
          deleteMessages: true,
        }),
      );
    }
  },
});

export default roomListenerMiddleware;
