import { debugLog } from "../utils/debug";
import {
  hasTerminalPeerHandshakeFailure,
  isTerminalHandshakeStatus,
} from "../handlers/handshakeFailure";
import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID } from "../utils/formatValidation";

import {
  setConnectingToPeers,
  setRoom,
  applyRoomResponse,
  setMessage,
  deleteMessage,
  setPeer,
  setKnownRoomPeers,
  deletePeer,
  setPeerHandshakeStatus,
  deleteRoom,
  purgeAllRooms,
  notePeerPresence,
  peerDeparted,
} from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";
import webrtcApi from "../api/webrtc";
import { signalingServerActions } from "../reducers/signalingServerSlice";
import { hexToUint8Array } from "../utils/uint8array";
import { compileChannelMessageLabel } from "../utils/channelLabel";
import { encodeRoomPolicyV1 } from "../roomPolicy";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import {
  PROTOCOL_VERSION,
  ROOM_ROSTER_RECONCILE_DEBOUNCE_MS,
  ROOM_ROSTER_RECONCILE_DELAYS_MS,
  ROOM_ROSTER_RECONCILE_MAX_ATTEMPTS,
} from "../utils/constants";
import { signalingPeerRequestDebouncer } from "../utils/signalingPeerRequestDebouncer";
import { MAX_SIGNALING_ROOM_PEERS } from "../utils/signalingBounds";
import { stopOutboxOwners } from "../handlers/outbox";
import { reportReceiveStorageError } from "../handlers/handleReceiveMessage";
import {
  StorageFailedError,
  rebuildError,
  serializeError,
} from "../db/dbErrors";
import {
  discardRoomOutbox,
  resumeRoomOutbox,
} from "../handlers/outboxCoordinator";
import {
  createRoomRosterReconciler,
  hasReportedDeparture,
  isRoomRosterStranded,
  hasOnlyTerminalPeerHandshakeFailures,
} from "../utils/roomRosterReconciler";

import {
  announceFileNotRemoved,
  deleteReceiveTransfer,
  deleteDBNewChunk,
  getDBRoomMessageData,
  onFileNotRemoved,
  setDBUniqueRoom,
} from "../db/api";

import type {
  Dispatch,
  ListenerEffectAPI,
  UnknownAction,
} from "@reduxjs/toolkit";
import type { State } from "../store";
import type { WebSocketMessagePeersRequest } from "../utils/interfaces";
import type { RoomRosterReconciler } from "../utils/roomRosterReconciler";
import type { SignalingPeerRequestKind } from "../utils/signalingPeerRequestDebouncer";

const PEERS_REQUEST_DEBOUNCE_MS = 2000;

const browserTimeoutReconciler = (): RoomRosterReconciler =>
  createRoomRosterReconciler({
    schedule: {
      setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
      clearTimeout: (handle) => {
        clearTimeout(handle);
      },
    },
    delaysMs: ROOM_ROSTER_RECONCILE_DELAYS_MS,
    maxAttempts: ROOM_ROSTER_RECONCILE_MAX_ATTEMPTS,
  });

/**
 * Reconcile discovery or each missing member independently after room changes.
 * A recovered/removed member, socket loss or room leave cancels the relevant
 * key. An unchanged offline member retains its exhausted budget.
 */
const reconcileRoomRosters = (
  reconciler: RoomRosterReconciler,
  listenerApi: ListenerEffectAPI<unknown, Dispatch<UnknownAction>>,
): void => {
  const { rooms, signalingServer, keyPair } = listenerApi.getState() as State;
  const stranded = new Set<string>();
  if (isUUID(keyPair.peerId))
    for (const room of rooms) {
      if (!isRoomRosterStranded(room, signalingServer)) continue;
      const members =
        room.knownPeers === undefined
          ? [undefined]
          : room.knownPeers
              .filter(
                (peer) =>
                  room.handshakeStatusByPeer?.[peer.peerId]?.status !==
                    "authenticated" &&
                  !hasReportedDeparture(room, peer.peerId) &&
                  !hasTerminalPeerHandshakeFailure(
                    room.handshakeStatusByPeer,
                    peer.peerId,
                    peer.peerPublicKey,
                  ),
              )
              .map((peer) => peer.peerId);
      for (const peerId of members) {
        const key = peerId ? `${room.id}/${peerId}` : room.id;
        stranded.add(key);
        reconciler.arm(key, () => {
          const state = listenerApi.getState() as State;
          const target = state.rooms.find(
            (candidate) => candidate.id === room.id,
          );
          if (
            !target ||
            !isUUID(state.keyPair.peerId) ||
            !isRoomRosterStranded(target, state.signalingServer)
          )
            return false;
          if (
            peerId &&
            (!target.knownPeers?.some(
              (peer) =>
                peer.peerId === peerId &&
                !hasReportedDeparture(target, peer.peerId) &&
                !hasTerminalPeerHandshakeFailure(
                  target.handshakeStatusByPeer,
                  peer.peerId,
                  peer.peerPublicKey,
                ),
            ) ||
              target.handshakeStatusByPeer?.[peerId]?.status ===
                "authenticated")
          )
            return false;
          listenerApi.dispatch(
            setConnectingToPeers({
              roomId: room.id,
              connectingToPeers: true,
              reason: "reconcile",
              peerId,
            }),
          );
          return true;
        });
      }
    }
  for (const roomId of reconciler.armedRooms())
    if (!stranded.has(roomId)) reconciler.cancel(roomId);
};

// A removal the SDK started itself left a received file on disk: the
// application hears it through onReceiveStorageError as "not-removed", with
// the browser's own error as `cause`. Announcements come from the database
// worker (a peer's cancel, the stale-receive sweep, the drop after a failed
// verification, the retry at its start) and from the delete effect below.
// Subscribed once for the module, however many middlewares are created.
onFileNotRemoved((notice) => {
  reportReceiveStorageError(
    {
      roomId: notice.roomId,
      fromPeerId: notice.fromPeerId,
      merkleRoot: notice.merkleRoot,
      filename: notice.filename,
      totalSize: notice.totalSize,
      chunkIndex: -1,
    },
    { failure: "not-removed" },
    rebuildError(notice.error),
  );
});

export const createRoomListenerMiddleware = (
  reconciler: RoomRosterReconciler = browserTimeoutReconciler(),
) => {
  // null means a full discovery; sets coalesce simultaneous member retries.
  const pendingTargets = new Map<string, Set<string> | null>();
  const roomListenerMiddleware = createListenerMiddleware();
  roomListenerMiddleware.startListening({
    matcher: isAnyOf(
      setConnectingToPeers,
      setRoom,
      applyRoomResponse,
      setMessage,
      deleteMessage,
      setPeer,
      setKnownRoomPeers,
      deletePeer,
      setPeerHandshakeStatus,
      deleteRoom,
      purgeAllRooms,
      notePeerPresence,
      peerDeparted,
      signalingServerActions.startConnecting,
      signalingServerActions.connectionEstablished,
      signalingServerActions.connectionVerified,
      signalingServerActions.disconnect,
    ),
    effect: async (action, listenerApi) => {
      // What a deleted message was, read now: the original state is only
      // readable before the effect's first await.
      const deletedMessage = deleteMessage.match(action)
        ? (listenerApi.getOriginalState() as State).rooms
            .find((room) => room.id === action.payload.roomId)
            ?.messages.findLast(
              (message) =>
                message.merkleRootHex === action.payload.merkleRootHex,
            )
        : undefined;
      // Guarded as a whole. This effect awaits IndexedDB through the worker, and
      // a storage failure there would otherwise surface as an unhandled promise
      // rejection in the host application — a library has no business taking a
      // page down because it could not cache a room.
      try {
        if (deleteRoom.match(action)) {
          const original = (listenerApi.getOriginalState() as State).rooms.find(
            (r) => r.id === action.payload || r.url === action.payload,
          );
          if (original) {
            signalingPeerRequestDebouncer.cancelRoom(original.id);
            for (const kind of ["join", "empty-roster", "redial", "reconcile"])
              pendingTargets.delete(`${kind}:${original.id}`);
            if (isUUID(original.id)) {
              stopOutboxOwners("room left", original.id);
              await discardRoomOutbox(original.id);
            }
          }
        } else if (purgeAllRooms.match(action)) {
          stopOutboxOwners("rooms purged");
          pendingTargets.clear();
          signalingPeerRequestDebouncer.resetSocketLifecycle();
        }
        if (
          setPeerHandshakeStatus.match(action) &&
          action.payload.status === "authenticated"
        ) {
          const { roomId, peerId, peerPublicKey } = action.payload;
          // Let the handshake finish installing its cover/PQ owners before a
          // retained message asks those owners to resume.
          void Promise.resolve()
            .then(async () => {
              const room = (listenerApi.getState() as State).rooms.find(
                (r) => r.id === roomId,
              );
              const status = room?.handshakeStatusByPeer?.[peerId];
              if (
                room?.signalingActive !== false &&
                status?.status === "authenticated" &&
                status.peerPublicKey === peerPublicKey
              )
                await resumeRoomOutbox(roomId);
            })
            .catch((error: unknown) => debugLog("Outbox resume failed", error));
        }
        if (
          signalingServerActions.startConnecting.match(action) ||
          signalingServerActions.disconnect.match(action)
        ) {
          pendingTargets.clear();
          signalingPeerRequestDebouncer.resetSocketLifecycle();
        } else if (setConnectingToPeers.match(action)) {
          const { roomId, connectingToPeers, reason, peerId } = action.payload;
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
              isUUID(rooms[roomIndex].id) &&
              !hasOnlyTerminalPeerHandshakeFailures(rooms[roomIndex])
            ) {
              // Debounce peers requests to prevent rapid re-requests. A re-dial
              // after an edge teardown gets its own budget: it may land inside
              // the join window of a fresh room join, and the edge it needs to
              // rebuild was torn down after that join's peers request went out.
              // An empty-room reconcile gets a third, for the same reason in the
              // other direction: its whole point is to fire when nothing else is.
              const kind: SignalingPeerRequestKind =
                reason === "redial"
                  ? "redial"
                  : reason === "reconcile"
                    ? "reconcile"
                    : "join";
              const targetKey = `${kind}:${roomId}`;
              if (peerId && isUUID(peerId)) {
                const pending = pendingTargets.get(targetKey);
                if (pending !== null) {
                  const targets = pending ?? new Set<string>();
                  targets.add(peerId);
                  pendingTargets.set(targetKey, targets);
                }
              } else pendingTargets.set(targetKey, null);
              signalingPeerRequestDebouncer.request(
                kind,
                roomId,
                reason === "reconcile"
                  ? ROOM_ROSTER_RECONCILE_DEBOUNCE_MS
                  : PEERS_REQUEST_DEBOUNCE_MS,
                () => {
                  // A trailing request runs after the listener effect ended:
                  // read current state and never rejoin a left or failed room.
                  const pending = pendingTargets.get(targetKey);
                  pendingTargets.delete(targetKey);
                  const state = listenerApi.getState() as State;
                  const room = state.rooms.find((r) => r.id === roomId);
                  if (
                    !room ||
                    room.signalingActive === false ||
                    !state.signalingServer.isConnected ||
                    !state.signalingServer.isVerified ||
                    !isUUID(state.keyPair.peerId) ||
                    hasOnlyTerminalPeerHandshakeFailures(room)
                  )
                    return;
                  const excludedPeerIds = [
                    ...new Set([
                      ...(room.knownPeers ?? room.peers)
                        .filter((peer) =>
                          hasTerminalPeerHandshakeFailure(
                            room.handshakeStatusByPeer,
                            peer.peerId,
                            peer.peerPublicKey,
                          ),
                        )
                        .map((peer) => peer.peerId),
                      ...Object.entries(room.handshakeStatusByPeer ?? {})
                        .filter(([, status]) =>
                          isTerminalHandshakeStatus(status),
                        )
                        .map(([peerId]) => peerId),
                    ]),
                  ].filter((peerId) => isUUID(peerId));
                  // Legacy servers ignore exclusions. Never trigger a failed
                  // peer's fresh-connection retry via an unrelated repair.
                  if (
                    excludedPeerIds.length > MAX_SIGNALING_ROOM_PEERS ||
                    (Object.values(room.handshakeStatusByPeer ?? {}).some(
                      isTerminalHandshakeStatus,
                    ) &&
                      !signalingPeerRequestDebouncer.supportsRosterSnapshots)
                  )
                    return;
                  const targetPeerIds = pending
                    ? [...pending].filter((id) =>
                        room.knownPeers?.some(
                          (peer) =>
                            peer.peerId === id &&
                            !excludedPeerIds.includes(id) &&
                            !hasReportedDeparture(room, id) &&
                            room.handshakeStatusByPeer?.[id]?.status !==
                              "authenticated",
                        ),
                      )
                    : undefined;
                  if (targetPeerIds?.length === 0) return;
                  listenerApi.dispatch(
                    signalingServerApi.endpoints.sendMessage.initiate({
                      content: {
                        type: "peers",
                        fromPeerId: state.keyPair.peerId,
                        roomId,
                        rosterRequestId:
                          signalingPeerRequestDebouncer.beginRosterRequest(
                            roomId,
                          ),
                        excludedPeerIds,
                        ...(targetPeerIds ? { targetPeerIds } : {}),
                        protocolVersion: PROTOCOL_VERSION,
                      } satisfies WebSocketMessagePeersRequest,
                    }),
                  );
                },
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

            // Loading the room to show it: its held files are verified.
            const oldMessages = await getDBRoomMessageData(id, {
              verifyHeld: true,
            });
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

            listenerApi.dispatch(
              setConnectingToPeers({ roomId: id, connectingToPeers: true }),
            );
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

          // Loading the room to show it: its held files are verified.
          const oldMessages = await getDBRoomMessageData(roomId, {
            verifyHeld: true,
          });
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

          if (hashHex && hashHex.length !== crypto_hash_sha512_BYTES * 2)
            return;

          if (merkleRootHex) {
            try {
              // Called before this effect's first await. When the action was
              // dispatched inside a call of the application that answers for
              // this file (p2party.deleteMessage, p2party.cancelMessage),
              // that call takes a refusal and this resolves.
              await deleteReceiveTransfer(merkleRootHex);
            } catch (error) {
              if (!(error instanceof StorageFailedError)) throw error;
              // A dispatched delete returns nothing to its caller: the
              // message has left the list and its records are gone, but its
              // file is still on disk. The application hears that through
              // onReceiveStorageError ("not-removed"), once per file.
              announceFileNotRemoved({
                merkleRoot: merkleRootHex,
                roomId: action.payload.roomId,
                fromPeerId: deletedMessage?.fromPeerId ?? "",
                filename: deletedMessage?.filename ?? "",
                totalSize: deletedMessage?.totalSize ?? 0,
                error: serializeError(error.cause ?? error),
              });
            }
            await deleteDBNewChunk({ merkleRootHex });
          } else if (hashHex) {
            // await deleteDBChunk(hashHex);
            await deleteDBNewChunk({ hashHex });
          }
        }
      } catch (error) {
        console.error("p2party: room listener effect failed", error);
      } finally {
        // In `finally` so the sweep also runs for the branches above that return
        // early, and for the actions this effect matches only in order to see
        // them (a peer arriving, a room being left, the socket changing state).
        try {
          reconcileRoomRosters(reconciler, listenerApi);
        } catch (error) {
          console.error("p2party: room roster reconciliation failed", error);
        }
      }
    },
  });

  return roomListenerMiddleware;
};

const roomListenerMiddleware = createRoomListenerMiddleware();

export default roomListenerMiddleware;
