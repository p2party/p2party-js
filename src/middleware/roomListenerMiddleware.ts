import { debugLog } from "../utils/debug";
import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import {
  setConnectingToPeers,
  setRoom,
  applyRoomResponse,
  setMessage,
  deleteMessage,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";
import { signalingServerActions } from "../reducers/signalingServerSlice";
import { hexToUint8Array } from "../utils/uint8array";
import { compileChannelMessageLabel } from "../utils/channelLabel";
import { encodeRoomPolicyV1 } from "../roomPolicy";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { PROTOCOL_VERSION } from "../utils/constants";
import { signalingPeerRequestDebouncer } from "../utils/signalingPeerRequestDebouncer";

import {
  deleteReceiveTransfer,
  deleteDBNewChunk,
  getDBRoomMessageData,
  setDBUniqueRoom,
} from "../db/api";

import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";

const PEERS_REQUEST_DEBOUNCE_MS = 2000;

const roomListenerMiddleware = createListenerMiddleware();
roomListenerMiddleware.startListening({
  matcher: isAnyOf(
    setConnectingToPeers,
    setRoom,
    applyRoomResponse,
    setMessage,
    deleteMessage,
    signalingServerActions.startConnecting,
    signalingServerActions.disconnect,
  ),
  effect: async (action, listenerApi) => {
    // Guarded as a whole. This effect awaits IndexedDB through the worker, and
    // a storage failure there would otherwise surface as an unhandled promise
    // rejection in the host application — a library has no business taking a
    // page down because it could not cache a room.
    try {
      if (
        signalingServerActions.startConnecting.match(action) ||
        signalingServerActions.disconnect.match(action)
      ) {
        signalingPeerRequestDebouncer.resetSocketLifecycle();
      } else if (setConnectingToPeers.match(action)) {
        const { roomId, connectingToPeers, reason } = action.payload;
        debugLog("[roomListenerMiddleware] setConnectingToPeers:", {
          roomId,
          connectingToPeers,
          reason,
        });
        if (connectingToPeers) {
          const { signalingServer, keyPair, rooms } =
            listenerApi.getState() as State;

          const roomIndex = rooms.findIndex((r) => r.id === roomId);
          debugLog("[roomListenerMiddleware] setConnectingToPeers check:", {
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
            // Debounce peers requests to prevent rapid re-requests. A re-dial
            // after an edge teardown gets its own budget: it may land inside
            // the join window of a fresh room join, and the edge it needs to
            // rebuild was torn down after that join's peers request went out.
            const now = Date.now();
            if (
              !signalingPeerRequestDebouncer.shouldSend(
                reason === "redial" ? "redial" : "join",
                roomId,
                PEERS_REQUEST_DEBOUNCE_MS,
                now,
              )
            ) {
              debugLog(
                "[roomListenerMiddleware] Skipping peers request - debounced",
              );
            } else {
              debugLog(
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
        debugLog("[roomListenerMiddleware] setRoom:", {
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
          debugLog("[roomListenerMiddleware] setRoom processed:", {
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

          debugLog(
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
            debugLog(
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
      } else if (applyRoomResponse.match(action)) {
        const { roomUrl, roomId } = action.payload;
        const originalRooms = (listenerApi.getOriginalState() as State).rooms;
        const original = originalRooms.find((room) => room.url === roomUrl);
        // A credential refresh keeps the same room identity and must not reload
        // the room's complete message history on every rotation.
        if (!original || original.id === roomId) return;

        const current = (listenerApi.getState() as State).rooms.find(
          (room) => room.url === roomUrl && room.id === roomId,
        );
        if (!current) return;
        const encodedPolicy = encodeRoomPolicyV1(current.policy);
        await setDBUniqueRoom(
          roomUrl,
          roomId,
          encodedPolicy.slice().buffer as ArrayBuffer,
        );

        const oldMessages = await getDBRoomMessageData(roomId);
        for (const message of oldMessages) {
          listenerApi.dispatch(
            setMessage({
              roomId: message.roomId,
              transferId: message.transferId,
              merkleRootHex: message.merkleRoot,
              sha512Hex: message.hash,
              fromPeerId: message.fromPeerId,
              filename: message.filename,
              messageType: message.messageType,
              chunkSize: message.savedSize,
              totalSize: message.totalSize,
              channelLabel: message.channelLabel,
              timestamp: message.timestamp,
            }),
          );
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
      }
    } catch (error) {
      console.error("p2party: room listener effect failed", error);
    }
  },
});

export default roomListenerMiddleware;
