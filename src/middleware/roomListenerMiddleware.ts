import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import {
  setConnectingToPeers,
  setRoom,
  setMessage,
  deleteMessage,
  deleteRoom,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";

import { hexToUint8Array } from "../utils/uint8array";
import { compileChannelMessageLabel } from "../utils/channelLabel";
import { encodeRoomPolicyV1 } from "../roomPolicy";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { PROTOCOL_VERSION } from "../utils/constants";

import {
  deleteReceiveTransfer,
  deleteDBNewChunk,
  getDBRoomMessageData,
  setDBUniqueRoom,
} from "../db/api";

import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";

// Debounce peers requests per room to prevent rapid re-requests
const lastPeersRequest = new Map<string, number>();
const PEERS_REQUEST_DEBOUNCE_MS = 2000;

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  matcher: isAnyOf(
    setConnectingToPeers,
    setRoom,
    setMessage,
    deleteMessage,
    deleteRoom,
  ),
  effect: async (action, listenerApi) => {
    if (setConnectingToPeers.match(action)) {
      const { roomId, connectingToPeers } = action.payload;
      console.log("[roomListenerMiddleware] setConnectingToPeers:", {
        roomId,
        connectingToPeers,
      });
      if (connectingToPeers) {
        const { signalingServer, keyPair, rooms } =
          listenerApi.getState() as State;

        const roomIndex = rooms.findIndex((r) => r.id === roomId);
        console.log("[roomListenerMiddleware] setConnectingToPeers check:", {
          isConnected: signalingServer.isConnected,
          peerId: keyPair.peerId,
          isPeerIdUUID: isUUID(keyPair.peerId),
          roomIndex,
          roomId: roomIndex > -1 ? rooms[roomIndex].id : "N/A",
        });

        if (
          signalingServer.isConnected &&
          signalingServer.isVerified &&
          isUUID(keyPair.peerId) &&
          roomIndex > -1 &&
          isUUID(rooms[roomIndex].id)
        ) {
          // Debounce peers requests to prevent rapid re-requests
          const now = Date.now();
          const lastRequest = lastPeersRequest.get(roomId) ?? 0;
          if (now - lastRequest < PEERS_REQUEST_DEBOUNCE_MS) {
            console.log(
              "[roomListenerMiddleware] Skipping peers request - debounced",
            );
          } else {
            lastPeersRequest.set(roomId, now);
            console.log(
              "[roomListenerMiddleware] Sending peers request from setConnectingToPeers",
            );
            await listenerApi.dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                    type: "peers",
                    fromPeerId: keyPair.peerId,
                    roomId,
                    protocolVersion: PROTOCOL_VERSION,
                } as WebSocketMessagePeersRequest,
              }),
            );
          }
        }

        listenerApi.dispatch(
          setConnectingToPeers({ roomId, connectingToPeers: false }),
        );
      }
    } else if (setRoom.match(action)) {
      const { signalingServer, keyPair, rooms } =
        listenerApi.getState() as State;

      const { url, id, onlyConnectWithKnownPeers } = action.payload;
      console.log("[roomListenerMiddleware] setRoom:", {
        url,
        id,
        onlyConnectWithKnownPeers,
      });

      if (url.length === 64 && onlyConnectWithKnownPeers != undefined) {
        localStorage.setItem(
          url + "-onlyConnectWithKnownPeers",
          String(onlyConnectWithKnownPeers),
        );
      }

      if (url.length === 64 && isUUID(id)) {
        console.log("[roomListenerMiddleware] setRoom processed:", {
          url,
          id,
          isConnected: signalingServer.isConnected,
          peerId: keyPair.peerId,
          roomsLen: rooms.length,
        });

        const roomIndex = rooms.findIndex((r) => r.id === id);
        if (roomIndex === -1) return;
        const encodedPolicy = encodeRoomPolicyV1(rooms[roomIndex].policy);
        const persistedPolicy = encodedPolicy.slice().buffer as ArrayBuffer;
        await setDBUniqueRoom(url, id, persistedPolicy);

        const oldMessages = await getDBRoomMessageData(id);
        const oldMessagesLen = oldMessages.length;
        for (let i = 0; i < oldMessagesLen; i++) {
          listenerApi.dispatch(
            setMessage({
              roomId: oldMessages[i].roomId,
              transferId: oldMessages[i].transferId,
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

        console.log(
          "[roomListenerMiddleware] Checking peers request conditions:",
          {
            isConnected: signalingServer.isConnected,
            isPeerIdUUID: isUUID(keyPair.peerId),
            peerId: keyPair.peerId,
            roomIndex,
            roomId: roomIndex > -1 ? rooms[roomIndex].id : "N/A",
          },
        );

        if (
          signalingServer.isConnected &&
          signalingServer.isVerified &&
          isUUID(keyPair.peerId) &&
          roomIndex > -1 &&
          isUUID(rooms[roomIndex].id)
        ) {
          console.log(
            "[roomListenerMiddleware] Sending peers request for room:",
            rooms[roomIndex].id,
          );
          await listenerApi.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "peers",
                fromPeerId: keyPair.peerId,
                roomId: rooms[roomIndex].id,
                protocolVersion: PROTOCOL_VERSION,
              } as WebSocketMessagePeersRequest,
            }),
          );
        }
      }
    } else if (setMessage.match(action)) {
      const { roomId, merkleRootHex, sha512Hex, chunkSize, totalSize } =
        action.payload;
      const { rooms, keyPair } = listenerApi.getOriginalState() as State;

      const roomIndex = rooms.findIndex((r) => r.id === roomId);
      if (roomIndex > -1) {
        const messageIndex = rooms[roomIndex].messages.findLastIndex(
          (m) =>
            m.merkleRootHex === merkleRootHex &&
            // We are the message receiver
            m.fromPeerId !== keyPair.peerId &&
            // // This piece will finish the puzzle
            m.savedSize + chunkSize === totalSize,
        );

        if (messageIndex > -1) {
          const label = await compileChannelMessageLabel(
            rooms[roomIndex].messages[messageIndex].channelLabel,
            rooms[roomIndex].messages[messageIndex].merkleRootHex,
          );

          const messageHash = hexToUint8Array(sha512Hex);

          await listenerApi.dispatch(
            webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
              roomId,
              label,
              messageHash,
              alsoDeleteData: false,
              alsoSendFinishedMessage: true,
            }),
          );
        }
      }
      // } else if (setMessageAllChunks.match(action)) {
      //   const { roomId, merkleRootHex, sha512Hex, alsoSendFinishedMessage } =
      //     action.payload;
      //   const { rooms, keyPair } = listenerApi.getState() as State;
      //
      //   const roomIndex = rooms.findIndex((r) => r.id === roomId);
      //   if (roomIndex > -1) {
      //     // If message receiver set this
      //     const messageIndex = rooms[roomIndex].messages.findLastIndex(
      //       (m) =>
      //         m.merkleRootHex === merkleRootHex &&
      //         m.fromPeerId !== keyPair.peerId,
      //     );
      //
      //     if (messageIndex > -1) {
      //       const label = await compileChannelMessageLabel(
      //         rooms[roomIndex].messages[messageIndex].channelLabel,
      //         rooms[roomIndex].messages[messageIndex].merkleRootHex,
      //       );
      //
      //       const messageHash = hexToUint8Array(sha512Hex);
      //
      //       await listenerApi.dispatch(
      //         webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
      //           label,
      //           peerId: rooms[roomIndex].messages[messageIndex].fromPeerId,
      //           messageHash,
      //           alsoDeleteData: false,
      //           alsoSendFinishedMessage,
      //         }),
      //       );
      //     }
      //   }
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
        await deleteReceiveTransfer(merkleRootHex);
        await deleteDBNewChunk({ merkleRootHex });
      } else if (hashHex) {
        // await deleteDBChunk(hashHex);
        await deleteDBNewChunk({ hashHex });
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
