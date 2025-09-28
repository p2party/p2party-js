import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import {
  setConnectingToPeers,
  setRoom,
  setMessage,
  deleteMessage,
  deleteRoom,
  setMessageAllChunks,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import { compileChannelMessageLabel } from "../utils/channelLabel";
import { hexToUint8Array } from "../utils/uint8array";

import {
  deleteDBChunk,
  deleteDBMessageData,
  deleteDBNewChunk,
  getDBRoomMessageData,
  setDBUniqueRoom,
} from "../db/api";

import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  matcher: isAnyOf(
    setConnectingToPeers,
    setRoom,
    setMessage,
    setMessageAllChunks,
    deleteMessage,
    deleteRoom,
  ),
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
          await listenerApi.dispatch(
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
          await listenerApi.dispatch(
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
    } else if (setMessageAllChunks.match(action)) {
      const { roomId, merkleRootHex, sha512Hex, alsoSendFinishedMessage } =
        action.payload;
      const { rooms, keyPair } = listenerApi.getState() as State;

      const roomIndex = rooms.findIndex((r) => r.id === roomId);
      if (roomIndex > -1) {
        // If message receiver set this
        const messageIndex = rooms[roomIndex].messages.findLastIndex(
          (m) =>
            m.merkleRootHex === merkleRootHex &&
            m.fromPeerId !== keyPair.peerId,
        );

        if (messageIndex > -1) {
          const label = await compileChannelMessageLabel(
            rooms[roomIndex].messages[messageIndex].channelLabel,
            rooms[roomIndex].messages[messageIndex].merkleRootHex,
          );

          const messageHash = hexToUint8Array(sha512Hex);

          // await listenerApi.dispatch(
          //   webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
          //     label,
          //     messageHash,
          //     alsoDeleteData: false,
          //     alsoSendFinishedMessage,
          //   }),
          // );
          await listenerApi.dispatch(
            webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
              label,
              peerId: rooms[roomIndex].messages[messageIndex].fromPeerId,
              messageHash,
              alsoDeleteData: false,
              alsoSendFinishedMessage,
            }),
          );
        }
      }
    } else if (deleteMessage.match(action)) {
      const { merkleRootHex, hashHex } = action.payload;

      if (!merkleRootHex && !hashHex) return;
      if (
        merkleRootHex &&
        merkleRootHex.length !== crypto_hash_sha512_BYTES * 2
      )
        return;

      if (hashHex && hashHex.length !== crypto_hash_sha512_BYTES * 2) return;

      if (merkleRootHex) {
        await deleteDBChunk(merkleRootHex);
        await deleteDBNewChunk(merkleRootHex);
        await deleteDBMessageData(merkleRootHex);
      } else if (hashHex) {
        // await deleteDBChunk(hashHex);
        await deleteDBNewChunk(undefined, undefined, hashHex);
      }
    } else if (deleteRoom.match(action)) {
      const roomId = action.payload;

      await listenerApi.dispatch(
        webrtcApi.endpoints.disconnectFromRoom.initiate({
          roomId,
          deleteMessages: true,
        }),
      );
    }
  },
});

export default roomListenerMiddleware;
