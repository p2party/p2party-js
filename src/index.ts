import { deriveRoomLocator } from "./utils/roomLocator";
import { outboxRequest } from "./db/api";
import { pendingMessageView, discardPendingSelection } from "./handlers/outbox";
import { createExpiredReceiveMaintenance } from "./handlers/expiredReceiveProjection";
import type { PendingMessage } from "./handlers/outbox";
import { registerOutboxResume } from "./handlers/outboxCoordinator";
export type { PendingMessage } from "./handlers/outbox";
import { isUUID } from "./utils/formatValidation";
import pkg from "../package.json";

import { store, dispatch } from "./store";

import { SignalingVersionMismatchError } from "./utils/protocolVersion";
import { newKeyPair, sign, verify } from "./cryptography/ed25519";
import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  SessionReplayError,
} from "./session";
import {
  generateMnemonic,
  keyPairFromMnemonic,
  validateMnemonic,
  validateMnemonicWords,
} from "./cryptography/mnemonic";
import { crypto_hash_sha512_BYTES } from "./cryptography/interfaces";
import { setWasmSourceUrl } from "./cryptography/wasmLoader";
import { setDebugLogging } from "./utils/debug";
import { getCoverTimerSource as readCoverTimerSource } from "./handlers/coverTimerWorker";

import {
  deleteDB,
  deleteDBAddressBookEntry,
  deleteDBNewChunk,
  deleteDBPeerFromBlacklist,
  deleteReceiveTransfer,
  answeringForRemoval,
  retryFileRemovals,
  getAllDBAddressBookEntries,
  assembleToOPFS,
  getReceiveFile,
  getAllDBBlacklisted,
  getAllDBUniqueRooms,
  getDBRoomStats,
  deleteIdentityDerivation,
  deleteIdentityEd25519,
  deleteIdentityX25519,
  getDBAddressBookEntry,
  getDBAllChunks,
  getDBAllNewChunksCount,
  getDBPeerIsBlacklisted,
  getIdentityDerivation,
  getIdentityEd25519,
  setDBAddressBookEntry,
  setDBPeerInBlacklist,
  setIdentityDerivation,
  setIdentityEd25519,
} from "./db/api";
import {
  getFileExtension,
  getMessageCategory,
  getMimeType,
  MessageCategory,
  MessageType,
} from "./utils/messageTypes";
import {
  CHUNK_LEN,
  CHUNK_SIZE_FLOOR,
  WIRE_CHUNK_FRAME_LEN,
} from "./utils/constants";
import {
  abortAllTransfers,
  abortRoomTransfers,
  abortTransfer,
  beginTransfer,
  createTransferId,
} from "./handlers/transferAbort";
import {
  DEFAULT_ROOM_POLICY_V1,
  MIN_COVER_CADENCE_MS,
  MAX_COVER_CADENCE_MS,
  MAX_COVER_LANES,
  MAX_COVER_FRAMES_PER_CELL,
  MIN_COVER_SLOT_MS,
  canonicalizeRoomPolicyV1,
  decodeRoomPolicyV1,
  encodeRoomPolicyV1,
  hashRoomPolicyV1,
  roomPoliciesEqualV1,
  validateRoomPolicyV1,
} from "./roomPolicy";
import {
  clearRoomPins,
  deleteRoomPin,
  getRoomPin,
  hasRoomPin,
  putRoomPin,
} from "./roomPinVault";
import { clearPinAttemptLimits, clearPinAttempts } from "./roomPinAttempts";
import {
  decodeRoomCapability,
  decodeRoomCapabilityBase64Url,
  decodeRoomCapabilityWords,
  decodeRoomInviteFragment,
  encodeRoomCapabilityBase64Url,
  encodeRoomCapabilityWords,
  encodeRoomInviteFragment,
  generateRoomCapability,
  normalizeRoomCapability,
  ROOM_INVITE_WORDLIST_ID,
} from "./roomInvite";

import signalingServerApi, {
  requestCurrentSocketRoomLeave,
  sendRoomRequestMessage,
} from "./api/signalingServerApi";
import webrtcApi, { snapshotPeerConnections } from "./api/webrtc";
import {
  getRoomIceConfigurationMutex,
  releaseRoomIceConfigurationMutex,
} from "./api/webrtc/negotiationLock";
import {
  canonicalSignalingServerUrl,
  selectSignalingServerUrl,
} from "./utils/signalingServerBoundary";

import { commonStateSelector } from "./reducers/commonSlice";
import {
  roomSelector,
  deriveEffectiveRTCConfig,
  rtcConfigurationsEqual,
  setConnectionRelay,
  setRoom,
  clearPeerHandshakeFailures,
  setOnlyConnectWithKnownPeers,
  deleteMessage as deleteMessageAction,
  deleteMessageStateOnly,
  deleteRoom,
  purgeAllRooms,
} from "./reducers/roomSlice";
import {
  keyPairSelector,
  resetIdentity,
  setKeyPair,
} from "./reducers/keyPairSlice";
import {
  signalingServerActions,
  signalingServerSelector,
} from "./reducers/signalingServerSlice";
import { setCurrentRoomUrl } from "./reducers/commonSlice";

import { compileChannelMessageLabel } from "./utils/channelLabel";
import { uint8ArrayToHex } from "./utils/uint8array";
import { isCanonicalEd25519Identity } from "./utils/identityRole";
import { signalingAttemptLifecycle } from "./utils/signalingAttemptLifecycle";
import { signalingRoomOperationLifecycle } from "./utils/signalingRoomOperationLifecycle";
import {
  runIdentityPurgeSettlement,
  runRoomPurgeSettlement,
  runTerminalSettlement,
} from "./utils/terminalSettlement";
import {
  createRecoverableIdentityWith,
  InvalidRecoveryPhraseError,
  restoreIdentityFromMnemonicWith,
} from "./utils/identityRestore";
import { resolveRoomConnectAdmission } from "./utils/roomConnectAdmission";
import { RemoteRoomRevocationUnconfirmedError } from "./utils/roomLeaveCoordinator";

import type { State as InternalState } from "./store";
import type {
  Room,
  Peer,
  PeerSignalingPresence,
  Channel,
  Message,
  SetRoomArgs,
} from "./reducers/roomSlice";
import type { SignalingState } from "./reducers/signalingServerSlice";
import type { MimeType, FileExtension } from "./utils/messageTypes";
import type {
  WebSocketMessageRoomIdRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageChallengeRequest,
  WebSocketMessageChallengeResponse,
  WebSocketMessageDescriptionSend,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateSend,
  WebSocketMessageCandidateReceive,
  WebSocketMessageLeaveRoomRequest,
  WebSocketMessageRoomLeftResponse,
  WebSocketMessageError,
} from "./utils/interfaces";
import type { RoomData } from "./api/webrtc/interfaces";
import type {
  BlacklistedPeer,
  FileRemovalRetryScope,
  IdentityDerivation,
  UsernamedPeer,
  UniqueRoom,
  RoomStats,
} from "./db/types";
import type { FileRemovalFailure } from "./db/dbErrors";
import type {
  CreatedRecoverableIdentity,
  CreateRecoverableIdentityOptions,
  IdentityRestoreEffects,
  RestoredIdentity,
} from "./utils/identityRestore";
import type { KeyPair } from "./reducers/keyPairSlice";
import type { RoomPolicyV1 } from "./roomPolicy";
import type { SendMessageResult } from "./handlers/handleSendMessage";
import { getTransferAcks } from "./handlers/reconcile";
// Exported so consumers can narrow the rejection of `MessageTransferHandle.done`
// and read its per-peer outcomes, rather than matching on an error message.
import { MessageDeliveryError } from "./handlers/handleSendMessage";
import { requestRoomFromSignalingWithRetry } from "./handlers/requestRoom";
import {
  assertReceivedFileIntact,
  onReceiveStorageError,
  ReceiveIntegrityError,
} from "./handlers/handleReceiveMessage";
import {
  asStorageFailure,
  DatabaseUnavailableError,
  DatabaseUpgradeBlockedError,
  DatabaseWorkerError,
  filesNotRemoved,
  InvalidMessageHashError,
  InvalidTransferIdError,
  MissingMessageIdentifierError,
  StorageFailedError,
} from "./db/dbErrors";
import { deleteRoomDataTerminal } from "./api/webrtc/deleteRoomData";
import type { ReceiveStorageError } from "./handlers/handleReceiveMessage";
import {
  cancelRoomRequestLifecycle,
  MAX_ACTIVE_SIGNALING_ROOMS,
} from "./utils/roomRequestCoordinator";

/** Public projection; reducer state keeps its additional fields normalized. */
type State = Omit<InternalState, "rooms"> & { rooms: Room[] };

// const originalClose = RTCDataChannel.prototype.close;
// RTCDataChannel.prototype.close = function () {
//   console.trace("RTCDataChannel closed from:");
//   originalClose.apply(this);
// };

export interface ConnectRoomOptions {
  /**
   * Canonical public room policy. Omit on reconnect to preserve the room's
   * existing policy; a new room defaults to hybrid-PQ, no-PIN, immediate
   * delivery over the currently shipped signaling path.
   */
  policy?: RoomPolicyV1;
  /**
   * Required exactly when `policy.authMode` is `pin`. Copied into an in-memory
   * vault keyed by the local room URL; never enters Redux, storage, or logs.
   */
  pin?: Uint8Array;
}

type ActivateSignalingRoomArgs = Omit<SetRoomArgs, "url" | "id">;

const assertCompatibleSignalingServer = (
  requestedServerUrl: string,
): string => {
  const { rooms, signalingServer } = store.getState();
  const hasActiveRooms = rooms.some((room) => room.signalingActive !== false);
  return selectSignalingServerUrl({
    requestedServerUrl,
    currentServerUrl: signalingServer.serverUrl,
    hasActiveRooms,
    isConnected: signalingServer.isConnected,
    isEstablishingConnection: signalingServer.isEstablishingConnection,
  });
};

/** One admission/reactivation path for every public signaling entry point. */
const activateSignalingRoom = async (
  roomUrl: string,
  args: ActivateSignalingRoomArgs = {},
): Promise<void> => {
  await getRoomIceConfigurationMutex(roomUrl).runExclusive(async () => {
    const rooms = store.getState().rooms;
    const existing = rooms.find((room) => room.url === roomUrl);
    const transitionsToActive = !existing || existing.signalingActive === false;
    if (
      transitionsToActive &&
      rooms.filter((room) => room.signalingActive !== false).length >=
        MAX_ACTIVE_SIGNALING_ROOMS
    )
      throw new Error(
        `Cannot activate more than ${String(MAX_ACTIVE_SIGNALING_ROOMS)} rooms`,
      );

    const callerConfigChanged =
      existing !== undefined &&
      args.rtcConfig !== undefined &&
      !rtcConfigurationsEqual(existing.callerRtcConfig, args.rtcConfig);
    const previousRtcConfig = existing?.rtcConfig;
    const nextRtcConfig =
      callerConfigChanged && existing && args.rtcConfig
        ? deriveEffectiveRTCConfig(
            args.rtcConfig,
            existing.signalingTurnCredentials,
          )
        : undefined;
    const appliedLiveConfiguration =
      callerConfigChanged &&
      existing !== undefined &&
      isUUID(existing.id, 4) &&
      nextRtcConfig !== undefined;

    if (appliedLiveConfiguration)
      await dispatch(
        webrtcApi.endpoints.applyRoomConfiguration.initiate({
          roomId: existing.id,
          rtcConfig: nextRtcConfig,
          restartIce: true,
          failurePolicy: "rollback",
        }),
      ).unwrap();

    try {
      dispatch(
        setRoom({
          ...args,
          url: roomUrl,
          id: existing?.id ?? "",
        }),
      );
      if (callerConfigChanged && args.rtcConfig) {
        const published = store
          .getState()
          .rooms.find((room) => room.url === roomUrl);
        if (
          !published ||
          !rtcConfigurationsEqual(published.callerRtcConfig, args.rtcConfig) ||
          (nextRtcConfig !== undefined &&
            !rtcConfigurationsEqual(published.rtcConfig, nextRtcConfig))
        )
          throw new Error("Caller RTC configuration publication was rejected");
      }
    } catch (error) {
      if (appliedLiveConfiguration && existing && previousRtcConfig)
        await dispatch(
          webrtcApi.endpoints.applyRoomConfiguration.initiate({
            roomId: existing.id,
            rtcConfig: previousRtcConfig,
            restartIce: true,
            failurePolicy: "close",
          }),
        ).unwrap();
      throw error;
    }
  });
};

const startSignalingConnectionInBackground = (
  signalingServerUrl: string,
): void => {
  // Reserve the one global signaling-server choice synchronously. RTK starts
  // the async base query after dispatch, so without this state transition a
  // second room join could select another server in the same turn.
  dispatch(signalingServerActions.startConnecting(signalingServerUrl));
  void dispatch(
    signalingServerApi.endpoints.connectWebSocket.initiate(signalingServerUrl),
  )
    .unwrap()
    .catch((error: unknown) => {
      const current = store.getState().signalingServer;
      if (
        current.isEstablishingConnection &&
        canonicalSignalingServerUrl(current.serverUrl) === signalingServerUrl
      )
        dispatch(signalingServerActions.disconnect());
      console.warn(
        "p2party: signaling connection attempt failed",
        error instanceof Error ? error.message : String(error),
      );
    });
};

/**
 * One exact-server decision after room activation.
 *
 * Re-reading the store here matters: connect() may await IndexedDB/PIN work
 * while a socket finishes proof. The fresh-proof sweep can precede activation,
 * so the newly active room must issue its own correlated request.
 */
const joinRoomThroughSignaling = (
  roomUrl: string,
  normalizedRequestedUrl: string,
): void => {
  const { keyPair, signalingServer } = store.getState();
  if (
    signalingServer.refusal &&
    signalingServer.serverUrl === normalizedRequestedUrl
  )
    throw new SignalingVersionMismatchError();
  const socketActive =
    signalingServer.isConnected || signalingServer.isEstablishingConnection;

  if (
    signalingServer.isConnected &&
    signalingServer.isVerified &&
    isUUID(keyPair.peerId, 4)
  ) {
    void requestRoomFromSignalingWithRetry(store, roomUrl, (request) =>
      sendRoomRequestMessage(store, request),
    ).catch((error: unknown) => {
      console.warn(
        "p2party: background room join failed",
        error instanceof Error ? error.message : String(error),
      );
    });
    return;
  }

  if (!socketActive)
    startSignalingConnectionInBackground(normalizedRequestedUrl);
};

const completeSignalingRoomJoin = (
  roomUrl: string,
  normalizedRequestedUrl: string,
): void => {
  if (store.getState().commonState.currentRoomUrl !== roomUrl)
    dispatch(setCurrentRoomUrl(roomUrl));
  joinRoomThroughSignaling(roomUrl, normalizedRequestedUrl);
};

const connect = async (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
  rtcConfig?: RTCConfiguration,
  options: ConnectRoomOptions = {},
) => {
  roomUrl = normalizeRoomCapability(roomUrl);
  if (options === null || typeof options !== "object" || Array.isArray(options))
    throw new Error("Invalid room connection options");

  await signalingRoomOperationLifecycle.runJoin(async () => {
    const { rooms, signalingServer } = store.getState();
    if (
      signalingServer.refusal &&
      signalingServer.serverUrl ===
        canonicalSignalingServerUrl(signalingServerUrl)
    )
      throw new SignalingVersionMismatchError();
    const roomIndex = rooms.findIndex((room) => room.url === roomUrl);
    let persistedPolicy: RoomPolicyV1 | undefined;
    if (roomIndex === -1) {
      const persistedRooms = await getAllDBUniqueRooms();
      const persisted = persistedRooms.find((room) => room.roomUrl === roomUrl);
      if (persisted?.roomPolicy) {
        persistedPolicy = decodeRoomPolicyV1(
          new Uint8Array(persisted.roomPolicy),
        );
      }
    }
    const policy = resolveRoomConnectAdmission({
      existingPolicy: roomIndex > -1 ? rooms[roomIndex].policy : undefined,
      persistedPolicy,
      requestedPolicy: options.policy,
      providedPin: options.pin,
      hasTransientPin: hasRoomPin(roomUrl),
    });

    const normalizedRequestedUrl =
      assertCompatibleSignalingServer(signalingServerUrl);
    if (policy.authMode === "pin" && options.pin !== undefined) {
      const existingRoomId =
        store.getState().rooms.find((room) => room.url === roomUrl)?.id ?? "";
      // A deliberate PIN re-entry resets the throttles but keeps the record
      // of peers that already authenticated here: they stay exempt from the
      // room window. Purge (below) removes that record too.
      if (existingRoomId)
        await clearPinAttemptLimits(deriveRoomLocator(roomUrl));
    }

    await activateSignalingRoom(roomUrl, {
      rtcConfig,
      policy,
    });

    const previousPin = getRoomPin(roomUrl);
    let pinChanged = false;
    try {
      if (policy.authMode === "pin" && options.pin !== undefined) {
        putRoomPin(roomUrl, options.pin);
        pinChanged = true;
      } else if (policy.authMode === "nopin") {
        // A deliberate switch back to no-PIN must not leave the old secret
        // alive after the room has been activated successfully.
        deleteRoomPin(roomUrl);
        pinChanged = true;
      }
      // connect() is the application's deliberate retry boundary. Automatic
      // socket/roster recovery never calls it, so a terminal PIN/policy failure
      // stays stopped until the caller accepts this room's settings again.
      dispatch(clearPeerHandshakeFailures(roomUrl));
      completeSignalingRoomJoin(roomUrl, normalizedRequestedUrl);
    } catch (error) {
      if (pinChanged) {
        if (previousPin) putRoomPin(roomUrl, previousPin);
        else deleteRoomPin(roomUrl);
      }
      throw error;
    } finally {
      previousPin?.fill(0);
    }
  });
};

export interface WaitForRoomOptions {
  /** Reject if the signaling service has not assigned an id in this long. */
  timeoutMs?: number;
  /** Cancel the wait, e.g. because the user navigated away. */
  signal?: AbortSignal;
}

const DEFAULT_ROOM_TIMEOUT_MS = 30_000;

/**
 * Resolve once the signaling service has assigned this room its id.
 *
 * `connect()` returns as soon as the join has been *started*; the id arrives
 * later, on a `roomId` frame. Without this, every caller has to hand-roll the
 * same store subscription — a mutable `unsubscribe` binding, an `inspect()`
 * that must also be called once synchronously in case the room is already
 * there, and no timeout — which is a lot of ceremony to learn one string.
 *
 * Resolves immediately when the room is already known.
 */
const waitForRoom = async (
  roomUrl: string,
  options: WaitForRoomOptions = {},
): Promise<Room> => {
  const normalized = normalizeRoomCapability(roomUrl);
  const { timeoutMs = DEFAULT_ROOM_TIMEOUT_MS, signal } = options;

  const current = (): Room | undefined => {
    const candidate = roomSelector(store.getState()).find(
      (item) => item.url === normalized,
    );
    return candidate?.id ? candidate : undefined;
  };

  if (store.getState().signalingServer.refusal)
    throw new SignalingVersionMismatchError();
  const alreadyJoined = current();
  if (alreadyJoined) return alreadyJoined;
  if (signal?.aborted)
    throw new Error("Waiting for the room was aborted before it started");

  return await new Promise<Room>((resolve, reject) => {
    // Every exit path runs this exactly once, so a resolved wait cannot leave a
    // store subscription or a timer behind.
    let settled = false;
    let unsubscribe = () => {};
    const timer = setTimeout(() => {
      finish(() => {
        reject(
          new Error(
            `The signaling service did not assign a room id within ${String(timeoutMs)}ms. ` +
              "The socket may be connected but not yet verified, or the room may be unreachable.",
          ),
        );
      });
    }, timeoutMs);

    const onAbort = () => {
      finish(() => {
        reject(new Error("Waiting for the room was aborted"));
      });
    };

    function finish(settle: () => void): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      unsubscribe();
      settle();
    }

    const inspect = () => {
      if (store.getState().signalingServer.refusal) {
        finish(() => reject(new SignalingVersionMismatchError()));
        return;
      }
      const room = current();
      if (room)
        finish(() => {
          resolve(room);
        });
    };

    signal?.addEventListener("abort", onAbort, { once: true });
    unsubscribe = store.subscribe(inspect);
    // The room can already have arrived between the check above and the
    // subscription being installed.
    inspect();
  });
};

/**
 * Join a room and resolve once it has an id, in one call.
 *
 * This is `connect()` followed by `waitForRoom()`, which is what essentially
 * every browser caller wants:
 *
 * ```ts
 * const invite = p2party.generateRoomInvite();
 * const room = await p2party.joinRoom(invite);
 * console.log("joined", room.id);
 * ```
 */
const joinRoom = async (
  roomUrl: string,
  signalingServerUrl?: string,
  rtcConfig?: RTCConfiguration,
  options: ConnectRoomOptions & WaitForRoomOptions = {},
): Promise<Room> => {
  const { timeoutMs, signal, ...connectOptions } = options;
  await connect(roomUrl, signalingServerUrl, rtcConfig, connectOptions);
  return await waitForRoom(roomUrl, { timeoutMs, signal });
};

export interface WaitForPeersOptions extends WaitForRoomOptions {
  /** Resolve once this many peers have completed the handshake. Default 1. */
  count?: number;
}

/**
 * Resolve once `count` peers in the room have finished authenticating.
 *
 * A room having an id says nothing about whether anyone can receive a message:
 * `sendMessage` to a room with no authenticated peer rejects. Callers were
 * writing their own store subscription and peer-count poll to bridge that gap.
 */
const waitForPeers = async (
  roomId: string,
  options: WaitForPeersOptions = {},
): Promise<Peer[]> => {
  const { count = 1, timeoutMs = DEFAULT_ROOM_TIMEOUT_MS, signal } = options;

  const ready = (): Peer[] | undefined => {
    const room = roomSelector(store.getState()).find(
      (candidate) => candidate.id === roomId,
    );
    if (!room) return undefined;
    // A peer with a recorded handshake status counts only when authenticated;
    // rooms that predate the status map fall back to presence.
    const statuses = room.handshakeStatusByPeer;
    const authenticated = statuses
      ? room.peers.filter(
          (peer) => statuses[peer.peerId]?.status === "authenticated",
        )
      : room.peers;
    return authenticated.length >= count ? authenticated : undefined;
  };

  const already = ready();
  if (already) return already;
  if (signal?.aborted)
    throw new Error("Waiting for peers was aborted before it started");

  return await new Promise<Peer[]>((resolve, reject) => {
    let settled = false;
    let unsubscribe = () => {};
    const timer = setTimeout(() => {
      finish(() => {
        reject(
          new Error(
            `Only ${String(ready()?.length ?? 0)} of ${String(count)} peer(s) authenticated within ${String(timeoutMs)}ms`,
          ),
        );
      });
    }, timeoutMs);
    const onAbort = () => {
      finish(() => {
        reject(new Error("Waiting for peers was aborted"));
      });
    };
    function finish(settle: () => void): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      unsubscribe();
      settle();
    }
    const inspect = () => {
      const peers = ready();
      if (peers)
        finish(() => {
          resolve(peers);
        });
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    unsubscribe = store.subscribe(inspect);
    inspect();
  });
};

export interface InboundMessage {
  readonly roomId: string;
  readonly fromPeerId: string;
  readonly merkleRootHex: string;
  readonly filename: string;
  readonly size: number;
  /** Text for a text message; a Blob for a completed file. */
  readonly message: string | Blob;
}

/**
 * Call `handler` once for each message that finishes arriving in a room.
 *
 * Without this, every application reimplements the same loop: subscribe to the
 * store, diff the room's `messages` array against what it saw last time, skip
 * anything still in flight, and call `readMessage` to decode. Returns an
 * unsubscribe function.
 *
 * Handler errors are caught and logged rather than allowed to escape into the
 * store's notify loop, where they would break unrelated subscribers.
 */
const onMessage = (
  roomId: string,
  handler: (message: InboundMessage) => void,
): (() => void) => {
  const delivered = new Set<string>();

  const inspect = () => {
    const room = roomSelector(store.getState()).find(
      (candidate) => candidate.id === roomId,
    );
    if (!room) return;

    for (const message of room.messages) {
      const key = message.merkleRootHex;
      if (!key || delivered.has(key)) continue;
      // Only once every byte has landed; a partial read would hand the caller
      // a truncated file and no way to tell.
      if (!(message.totalSize > 0 && message.savedSize >= message.totalSize))
        continue;
      delivered.add(key);

      void readMessage(key, message.sha512Hex)
        .then((opened) => {
          try {
            handler({
              roomId,
              fromPeerId: message.fromPeerId,
              merkleRootHex: key,
              filename: opened.filename,
              size: opened.size,
              message: opened.message,
            });
          } catch (error) {
            console.error("p2party: onMessage handler threw", error);
          }
        })
        .catch((error: unknown) => {
          delivered.delete(key);
          console.error("p2party: could not read message", key, error);
        });
    }
  };

  const unsubscribe = store.subscribe(inspect);
  inspect();
  return unsubscribe;
};

const connectToSignalingServer = async (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
) => {
  await connect(roomUrl, signalingServerUrl);
};

const disconnectFromSignalingServer = async () => {
  await signalingRoomOperationLifecycle.runGlobalTerminal(async () => {
    await dispatch(
      signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
    ).unwrap();
  });
};

const disconnectFromPeer = async (peerId: string) => {
  await dispatch(webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }));
};

// Remove everything stored for a room's messages. First the files an earlier
// delete of this room's messages left on disk are tried again (their messages
// are no longer listed, so nothing else would reach them), then every stored
// message is removed. Each file is tried once; whatever failed is thrown
// after everything was tried.
//
// The earlier leftovers are found by the room's id while it has one. A room
// that was removed before has none (its entry is a placeholder with an empty
// id, or is gone), and its leftovers are found by a digest of its URL, which
// purgeRoom passes. A caller that has tried the leftovers itself (leaving
// all rooms does, once for all of them) passes `retryLeftovers` false.
const deleteStoredRoomData = async (
  roomId: string,
  roomUrl?: string,
  retryLeftovers = true,
): Promise<void> => {
  const failures: unknown[] = [];
  const left = !retryLeftovers
    ? undefined
    : roomId !== ""
      ? { roomId, ...(roomUrl === undefined ? {} : { roomUrl }) }
      : roomUrl === undefined
        ? undefined
        : { roomUrl };
  if (left)
    try {
      await retryFileRemovals(left);
    } catch (error) {
      failures.push(error);
    }
  try {
    await deleteRoomDataTerminal(roomId, (merkleRootHex) => {
      dispatch(deleteMessageStateOnly({ roomId, merkleRootHex }));
    });
  } catch (error) {
    failures.push(error);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(
      failures,
      "Room data deletion did not fully settle",
    );
};

// With `deleteMessages`, every stored message of the room is removed after
// the room's connections close. A received file the browser refuses to remove
// makes this reject with one StorageFailedError (`failures`: each file and
// the browser's error for it) once every other message was tried. The
// messages are unlisted and their records gone either way; calling this
// again tries the files that were left.
const disconnectFromRoom = async (roomId: string, deleteMessages = false) => {
  await dispatch(
    webrtcApi.endpoints.disconnectFromRoom.initiate({
      roomId,
      deleteMessages: false,
    }),
  );
  if (!deleteMessages) return;
  try {
    await deleteStoredRoomData(roomId);
  } catch (error) {
    throw asStorageFailure(
      error,
      "p2party: leaving the room left received files on disk",
    );
  }
};

// With `deleteMessages`, every stored message of every room left is removed
// after the connections close. A received file the browser refuses to remove
// makes this reject with one StorageFailedError (`failures`: each file and
// the browser's error for it) once every other room and message was tried.
// Calling it again tries the files that were left, also those of rooms this
// page no longer lists (after a reload it lists none until they are joined
// again): every file a deleted message left, the excepted rooms' aside.
const disconnectFromAllRooms = async (
  deleteMessages = false,
  exceptionRoomIds: string[] = [],
) => {
  await dispatch(
    webrtcApi.endpoints.disconnectFromAllRooms.initiate({
      deleteMessages: false,
      exceptionRoomIds,
    }),
  );
  if (!deleteMessages) return;
  const exceptions = new Set(exceptionRoomIds);
  const failures: unknown[] = [];
  try {
    await retryFileRemovals({ exceptRoomIds: exceptionRoomIds });
  } catch (error) {
    failures.push(error);
  }
  for (const room of store.getState().rooms) {
    if (exceptions.has(room.id)) continue;
    try {
      // The files earlier deletes left were tried above, once.
      await deleteStoredRoomData(room.id, undefined, false);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0)
    throw asStorageFailure(
      new AggregateError(
        failures,
        "All-room data deletion did not fully settle",
      ),
      "p2party: leaving the rooms left received files on disk",
    );
};

const allowConnectionRelay = (roomId: string, allowed = true) => {
  const { rooms } = store.getState();
  const roomIndex = rooms.findIndex((r) => r.id === roomId);
  if (roomIndex > -1) {
    dispatch(
      setConnectionRelay({
        roomId: rooms[roomIndex].id,
        canBeConnectionRelay: allowed,
      }),
    );
  }
};

const onlyAllowConnectionsFromAddressBook = async (
  roomUrl: string,
  onlyAllow: boolean,
) => {
  let canonicalRoomUrl: string;
  try {
    canonicalRoomUrl = normalizeRoomCapability(roomUrl);
  } catch {
    return;
  }
  roomUrl = canonicalRoomUrl;
  const { rooms } = store.getState();
  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex === -1 || rooms[roomIndex].signalingActive === false) return;

  if (
    roomIndex > -1 &&
    !rooms[roomIndex].onlyConnectWithKnownAddresses &&
    onlyAllow &&
    rooms[roomIndex].peers.length > 0
  ) {
    const peersLen = rooms[roomIndex].peers.length;
    for (let i = 0; i < peersLen; i++) {
      const address = await getDBAddressBookEntry(
        rooms[roomIndex].peers[i].peerPublicKey,
      );

      if (!address) {
        await dispatch(
          webrtcApi.endpoints.disconnectFromPeer.initiate({
            peerId: rooms[roomIndex].peers[i].peerId,
            roomId: rooms[roomIndex].id,
            alsoDeleteData: false,
          }),
        );
      }
    }
  }

  dispatch(
    setOnlyConnectWithKnownPeers({
      roomId: rooms[roomIndex].id,
      roomUrl,
      onlyConnectWithKnownPeers: onlyAllow,
    }),
  );
};

// A remembered routing ID can now belong to a different key. Only disconnect
// current room edges that name the key the user actually edited.
const disconnectIdentity = async (
  peerPublicKey: string,
  alsoDeleteData: boolean,
) => {
  for (const connection of snapshotPeerConnections()) {
    if (connection.withPeerPublicKey !== peerPublicKey) continue;
    await dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({
        roomId: connection.roomId,
        peerId: connection.withPeerId,
        expectedPeerPublicKey: peerPublicKey,
        alsoDeleteData: false,
      }),
    );
  }
  if (alsoDeleteData) {
    for (const room of store.getState().rooms)
      for (const message of room.messages)
        if (message.fromPeerPublicKey === peerPublicKey)
          dispatch(
            deleteMessageAction({
              roomId: room.id,
              merkleRootHex: message.merkleRootHex,
            }),
          );
  }
};

const deletePeerFromAddressBook = async (peerPublicKey: string) => {
  await deleteDBAddressBookEntry(peerPublicKey);
  await disconnectIdentity(peerPublicKey, false);
};

const blacklistPeer = async (peerId: string, peerPublicKey: string) => {
  await setDBPeerInBlacklist(peerId, peerPublicKey);
  await disconnectIdentity(peerPublicKey, true);
};

// const openChannel = async (
//   roomId: string,
//   label: string,
//   withPeers?: { peerId: string; peerPublicKey: string }[],
// ) => {
//   await dispatch(
//     webrtcApi.endpoints.openChannel.initiate({
//       roomId,
//       channel: label,
//       withPeers,
//     }),
//   );
// };

/**
 * If no toChannel then broadcast the message everywhere to everyone.
 * If toChannel then broadcast to all peers with that channel.
 */
export interface MessageTransferHandle {
  readonly transferId: string;
  /**
   * Settles only after every started peer send/reconciliation and cleanup
   * finishes, preserving the ordered per-peer delivery outcomes.
   *
   * This promise REJECTS when no peer took delivery — for example every edge
   * failed, or the transfer was cancelled. The rejection is a
   * {@link MessageDeliveryError}, whose `result.outcomes` carries the same
   * per-peer detail a resolved value would have, and whose `errors` holds the
   * underlying per-peer failures. Always attach a catch:
   *
   * ```ts
   * const handle = p2party.sendMessage(data, "chat", roomId);
   * try {
   *   const result = await handle.done;
   * } catch (error) {
   *   if (error instanceof p2party.MessageDeliveryError)
   *     console.table(error.result.outcomes);
   * }
   * ```
   */
  readonly done: Promise<SendMessageResult | undefined>;
  /**
   * Cancels exactly this logical send, even before hashing/WASM setup
   * finishes. Like `cancelMessage`, it rejects with StorageFailedError when
   * the browser refuses to remove a file kept for the message (the copy
   * assembled when the sent file was read back); the send is cancelled all
   * the same, and calling it again tries the file again.
   */
  cancel(): Promise<void>;
}

const sendMessage = (
  data: string | File,
  toChannel: string,
  roomId: string,
  percentageFilledChunk = 0.9,
  minChunks = 3,
  chunkSize = CHUNK_LEN,
  metadataSchemaVersion = 1,
  transferId = createTransferId(),
): MessageTransferHandle => {
  if (!/^[0-9a-f]{64}$/.test(transferId))
    throw new Error("Invalid transfer ID");
  const transfer = beginTransfer(roomId, transferId);
  const request = dispatch(
    webrtcApi.endpoints.sendMessage.initiate({
      transferId,
      data,
      label: toChannel,
      roomId,
      minChunks,
      chunkSize,
      percentageFilledChunk,
      metadataSchemaVersion,
    }),
  );
  const done = request.unwrap().finally(() => transfer.finish());

  return {
    transferId,
    done,
    cancel: () =>
      cancelMessage(roomId, toChannel, undefined, undefined, transferId),
  };
};

const maintainExpiredReceives = createExpiredReceiveMaintenance({
  getRooms: () => store.getState().rooms,
  getPeers: snapshotPeerConnections,
  dropMessage: (roomId, merkleRootHex) => {
    dispatch(deleteMessageStateOnly({ roomId, merkleRootHex }));
  },
});

/** Metadata only; the durable outbox never exposes or stores a PIN or ratchet key. */
const listPendingMessages = async (
  roomId?: string,
): Promise<PendingMessage[]> => {
  await maintainExpiredReceives();
  const { keyPair } = store.getState();
  const result = await outboxRequest({
    kind: "list",
    senderPublicKey: keyPair.publicKey,
    roomId,
  });
  return (result.manifests ?? []).map(pendingMessageView);
};

const resumeAttempts = new Map<string, Promise<SendMessageResult[]>>();
/** Retry retained bytes on matching authenticated edges; never connects or supplies credentials. */
const resumePendingMessages = (
  roomId: string,
): Promise<SendMessageResult[]> => {
  const active = resumeAttempts.get(roomId);
  if (active) return active;
  const run = async (): Promise<SendMessageResult[]> => {
    if (!store.getState().signalingServer.isVerified) return [];
    const pending = await listPendingMessages(roomId);
    const results: SendMessageResult[] = [];
    const failures: unknown[] = [];
    for (const message of pending) {
      const currentState = store.getState();
      const room = currentState.rooms.find((r) => r.id === roomId);
      if (
        !currentState.signalingServer.isVerified ||
        !room ||
        room.signalingActive === false
      )
        break;
      if (!message.retryable || message.retryAfter > Date.now()) continue;
      const hasRecipient = Object.values(room.handshakeStatusByPeer ?? {}).some(
        (status) =>
          status.status === "authenticated" &&
          message.remainingRecipients.some(
            (peer) => peer.publicKey === status.peerPublicKey,
          ),
      );
      if (!hasRecipient) continue;
      try {
        const result = await dispatch(
          webrtcApi.endpoints.sendMessage.initiate({
            transferId: message.transferId,
            roomId,
            label: message.channelLabel,
          }),
        ).unwrap();
        if (result) results.push(result);
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        "Some pending messages remain undelivered",
      );
    return results;
  };
  const work = run().finally(() => {
    resumeAttempts.delete(roomId);
  });
  resumeAttempts.set(roomId, work);
  return work;
};

/**
 * Cancel a pending outbound message by its transfer ID. It goes through
 * `cancelMessage`, and like it rejects with StorageFailedError when the
 * browser refuses to remove a file kept for the message.
 */
const cancelPendingMessage = async (
  roomId: string,
  transferId: string,
): Promise<void> => {
  const row = (await listPendingMessages(roomId)).find(
    (message) => message.transferId === transferId,
  );
  await cancelMessage(
    roomId,
    row?.channelLabel ?? "main",
    undefined,
    undefined,
    transferId,
  );
};

const leaseRetryTimers = new Map<string, ReturnType<typeof setTimeout>>();
registerOutboxResume(async (roomId) => {
  await resumePendingMessages(roomId);
  // A reload may authenticate before the previous tab's lease expires. One
  // delayed claim follows this authentication event; failure never rearms it.
  if (leaseRetryTimers.has(roomId)) return;
  const pending = await listPendingMessages(roomId);
  const deadlines = pending
    .filter((message) => message.retryable && message.retryAfter > Date.now())
    .map((message) => message.retryAfter);
  if (!deadlines.length) return;
  const timer = setTimeout(
    () => {
      leaseRetryTimers.delete(roomId);
      void resumePendingMessages(roomId).catch((error) => console.error(error));
    },
    Math.min(31_000, Math.max(0, Math.min(...deadlines) - Date.now()) + 100),
  );
  leaseRetryTimers.set(roomId, timer);
});

const readMessage = async (
  merkleRootHex: string,
  hashHex?: string,
  // When false, a COMPLETED file is NOT materialized (no OPFS reassembly / Blob):
  // the result carries metadata only (message: ""). Use this to render list
  // previews and file bubbles cheaply, and materialize (default) only when the
  // user actually opens / downloads / saves the file. Text is always returned.
  materialize = true,
): Promise<{
  message: string | Blob;
  percentage: number;
  size: number;
  filename: string;
  mimeType: MimeType;
  extension: FileExtension;
  category: string;
  // Telemetry (percentage stays over the REAL message): frames seen incl.
  // decoys, real chunks, and sender retransmit rounds.
  chunksReceivedTotal?: number;
  chunksReceivedReal?: number;
  retransmits?: number;
}> => {
  if (!merkleRootHex && !hashHex)
    return {
      message: "No message",
      percentage: 0,
      size: 0,
      filename: "",
      mimeType: "text/plain",
      extension: "txt",
      category: MessageCategory.Text,
    };

  try {
    const { keyPair, rooms } = store.getState();
    const roomsLen = rooms.length;
    let roomIndex = -1;
    let messageIndex = -1;
    for (let i = 0; i < roomsLen; i++) {
      messageIndex = rooms[i].messages.findLastIndex(
        (m) =>
          m.merkleRootHex === merkleRootHex ||
          (keyPair.peerId === m.fromPeerId &&
            m.sha512Hex === hashHex &&
            m.merkleRootHex === ""),
      );
      if (messageIndex > -1) {
        roomIndex = i;
        break;
      }
    }

    if (roomIndex === -1 || messageIndex === -1)
      return {
        message: "No message",
        percentage: 0,
        size: 0,
        filename: "",
        mimeType: "text/plain",
        extension: "",
        category: MessageCategory.Text,
      };

    const messageType = rooms[roomIndex].messages[messageIndex].messageType;
    const mimeType = getMimeType(messageType);
    const extension = getFileExtension(messageType);
    const category = getMessageCategory(messageType);
    const percentage =
      rooms[roomIndex].messages[messageIndex].fromPeerId === keyPair.peerId
        ? 100
        : Math.floor(
            (rooms[roomIndex].messages[messageIndex].savedSize /
              rooms[roomIndex].messages[messageIndex].totalSize) *
              100,
          );

    // Telemetry over the padded transfer — percentage above stays real-only.
    const telemetry = {
      chunksReceivedTotal:
        rooms[roomIndex].messages[messageIndex].chunksReceivedTotal ?? 0,
      chunksReceivedReal:
        rooms[roomIndex].messages[messageIndex].chunksReceivedReal ?? 0,
      retransmits: rooms[roomIndex].messages[messageIndex].retransmits ?? 0,
    };

    // A received file that failed whole-file verification has no readable
    // bytes; say so instead of handing back a partial Blob. A completed file
    // was verified when it completed and is not re-hashed here.
    if (
      messageType !== MessageType.Text &&
      materialize &&
      percentage < 100 &&
      rooms[roomIndex].messages[messageIndex].fromPeerId !== keyPair.peerId
    )
      await assertReceivedFileIntact(
        rooms[roomIndex].messages[messageIndex].merkleRootHex,
      );

    // Metadata-only read: skip the (potentially huge) file materialization for a
    // completed file when the caller only needs name/size/category (list
    // previews, file bubbles). Avoids reassembling the whole file on the render
    // path — materialize it only on open/download/save.
    if (messageType !== MessageType.Text && !materialize)
      return {
        message: "",
        percentage,
        size: rooms[roomIndex].messages[messageIndex].totalSize,
        filename: rooms[roomIndex].messages[messageIndex].filename,
        mimeType,
        extension,
        category,
        ...telemetry,
      };

    // A completed FILE is served from a disk-backed OPFS file — the whole file
    // is never held in RAM (arbitrary-size support). A RECEIVED file already
    // lives in OPFS (chunks were written there at their offsets as they
    // arrived), so getReceiveFile just opens it. A SENT copy's bytes are in the
    // IndexedDB chunks store, so it is streamed to OPFS by assembleToOPFS. Text
    // and in-progress reads use the in-memory path below; if OPFS is unavailable
    // either call returns null and we fall through to the in-memory Blob too.
    if (messageType !== MessageType.Text && percentage === 100) {
      const filename = rooms[roomIndex].messages[messageIndex].filename;
      const isSent =
        rooms[roomIndex].messages[messageIndex].fromPeerId === keyPair.peerId;
      const opfsFile = isSent
        ? await assembleToOPFS(
            rooms[roomIndex].messages[messageIndex].merkleRootHex,
            rooms[roomIndex].messages[messageIndex].totalSize,
            filename,
            mimeType,
          )
        : await getReceiveFile(
            rooms[roomIndex].messages[messageIndex].merkleRootHex,
            rooms[roomIndex].messages[messageIndex].totalSize,
            filename,
            mimeType,
          );
      if (opfsFile) {
        return {
          message: opfsFile,
          percentage,
          size: rooms[roomIndex].messages[messageIndex].totalSize,
          filename,
          mimeType,
          extension,
          category,
          ...telemetry,
        };
      }
    }

    const chunks =
      percentage === 100
        ? await getDBAllChunks(
            rooms[roomIndex].messages[messageIndex].merkleRootHex,
            rooms[roomIndex].messages[messageIndex].sha512Hex,
          )
        : [];

    // Only records that still carry bytes belong in the in-memory Blob. This
    // fallback runs for text, in-progress reads, and completed files where OPFS
    // was unavailable/old-format (all such records have `data`); a received file
    // whose bytes are in OPFS never reaches here (getReceiveFile returned it).
    const dataChunks = chunks
      .map((c) => c.data)
      .filter((d): d is ArrayBuffer => d != null);

    try {
      const data = new Blob(dataChunks, {
        type: mimeType,
      });

      if (messageType === MessageType.Text) {
        return {
          message:
            dataChunks.length > 0
              ? await data.text()
              : rooms[roomIndex].messages[messageIndex].fromPeerId ===
                  keyPair.peerId
                ? "Outgoing message..."
                : "Incoming message...",
          percentage,
          size: rooms[roomIndex].messages[messageIndex].totalSize,
          filename: "",
          mimeType,
          extension,
          category,
          ...telemetry,
        };
      } else {
        // Guard: with receive-time OPFS writes, a received file's bytes live in
        // OPFS and its IndexedDB records are bytesless. This in-memory Blob
        // fallback is only complete when the bytes ARE in IndexedDB (OPFS
        // unavailable / sender copy / old rows). If we reach here for a completed
        // file yet the assembled Blob is short (getReceiveFile failed
        // exceptionally), never hand back a silently truncated file.
        if (
          percentage === 100 &&
          data.size !== rooms[roomIndex].messages[messageIndex].totalSize
        )
          return {
            message: "Irretrievable message",
            percentage: 0,
            size: rooms[roomIndex].messages[messageIndex].totalSize,
            filename: rooms[roomIndex].messages[messageIndex].filename,
            mimeType,
            extension,
            category,
          };

        return {
          message: data,
          percentage,
          size: rooms[roomIndex].messages[messageIndex].totalSize,
          filename: rooms[roomIndex].messages[messageIndex].filename,
          mimeType,
          extension,
          category,
          ...telemetry,
        };
      }
    } catch {
      return {
        message: "Invalid message",
        percentage: 0,
        size: rooms[roomIndex].messages[messageIndex].totalSize,
        filename: rooms[roomIndex].messages[messageIndex].filename,
        mimeType,
        extension,
        category,
      };
    }
  } catch (error) {
    if (error instanceof ReceiveIntegrityError) throw error;
    console.error(error);

    return {
      message: "Irretrievable message",
      percentage: 0,
      size: 0,
      filename: "",
      mimeType: "text/plain",
      extension: "",
      category: MessageCategory.Text,
    };
  }
};

// A Merkle root or whole-file hash as the application gives it: the 128
// lower-case hexadecimal characters the SDK reports it as, or the 64 bytes
// those encode. Any other form names nothing the SDK holds, so it is refused
// here with a typed error instead of being looked up.
const MESSAGE_HASH_HEX = new RegExp(
  `^[0-9a-f]{${String(crypto_hash_sha512_BYTES * 2)}}$`,
);
const messageHashHex = (
  value: string | Uint8Array | undefined,
  argument: "merkleRoot" | "hash",
): string => {
  if (value === undefined) return "";
  if (typeof value !== "string") {
    if (value.length !== crypto_hash_sha512_BYTES)
      throw new InvalidMessageHashError(argument);
    return uint8ArrayToHex(value);
  }
  if (!MESSAGE_HASH_HEX.test(value))
    throw new InvalidMessageHashError(argument);
  return value;
};

// A delete or cancel of a message this page does not list. That is also how
// a message looks whose delete or cancel was refused its file earlier, in
// this session or before a reload: its records are gone and its file may
// still be on disk. The removal is tried again, under every name the call
// gave (a file found under two of them is listed once). Only what this
// room's deleted messages left is touched (a file some record still owns, or
// that another room's records name, is left alone). A file that is still
// refused rejects the call with StorageFailedError, as the first call did,
// after every name was tried.
const retryUnlistedRemoval = async (
  roomId: string,
  names: { merkleRootHex: string; hashHex: string; transferId?: string },
): Promise<void> => {
  const scopes: FileRemovalRetryScope[] = [];
  if (names.transferId) scopes.push({ roomId, transferId: names.transferId });
  if (names.merkleRootHex)
    scopes.push({ roomId, merkleRootHex: names.merkleRootHex });
  if (names.hashHex) scopes.push({ roomId, hash: names.hashHex });
  const left = new Map<string, FileRemovalFailure>();
  for (const scope of scopes)
    try {
      await retryFileRemovals(scope);
    } catch (error) {
      if (!(error instanceof StorageFailedError) || error.failures.length === 0)
        throw error;
      for (const failure of error.failures)
        left.set(failure.merkleRootHex, failure);
    }
  if (left.size > 0) throw filesNotRemoved([...left.values()]);
};

/**
 * Cancel a message that is being sent or received, and remove everything
 * stored for it. `merkleRoot` and `hash` are the 128 lower-case hexadecimal
 * characters the SDK reports, or the 64 bytes those encode
 * (InvalidMessageHashError otherwise).
 *
 * Rejects with StorageFailedError when the browser refuses to remove the
 * message's file; the message is cancelled and unlisted all the same.
 * Calling again with the same arguments tries the file again, and rejects
 * while it is still on disk.
 */
const cancelMessage = async (
  roomId: string,
  channelLabel: string,
  merkleRoot?: string | Uint8Array,
  hash?: string | Uint8Array,
  transferId?: string,
) => {
  if (
    transferId === undefined &&
    merkleRoot === undefined &&
    hash === undefined
  )
    throw new MissingMessageIdentifierError();
  if (transferId !== undefined && !/^[0-9a-f]{64}$/.test(transferId))
    throw new InvalidTransferIdError();
  const merkleRootHex = messageHashHex(merkleRoot, "merkleRoot");
  const hashHex = messageHashHex(hash, "hash");

  await discardPendingSelection(
    {
      roomId,
      senderPublicKey: store.getState().keyPair.publicKey,
      transferId,
      merkleRootHex: merkleRootHex || undefined,
      hashHex: hashHex || undefined,
    },
    () => {
      abortTransfer(roomId, {
        transferId,
        merkleRootHex: merkleRootHex || undefined,
        hashHex: hashHex || undefined,
      });
    },
  );

  const { rooms } = store.getState();
  const roomIndex = rooms.findIndex((room) => room.id === roomId);
  const messageIndex =
    roomIndex > -1
      ? transferId
        ? rooms[roomIndex].messages.findIndex(
            (message) => message.transferId === transferId,
          )
        : merkleRoot
          ? rooms[roomIndex].messages.findIndex(
              (message) => message.merkleRootHex === merkleRootHex,
            )
          : rooms[roomIndex].messages.findIndex(
              (message) => message.sha512Hex === hashHex,
            )
      : -1;

  if (
    roomIndex > -1 &&
    messageIndex > -1 &&
    rooms[roomIndex].messages[messageIndex].merkleRootHex.length ===
      crypto_hash_sha512_BYTES * 2
  ) {
    const label = await compileChannelMessageLabel(
      channelLabel,
      rooms[roomIndex].messages[messageIndex].merkleRootHex,
      // rooms[roomIndex].messages[messageIndex].sha512Hex,
    );

    await removeStoredMessage(
      rooms[roomIndex].id,
      label,
      rooms[roomIndex].messages[messageIndex].merkleRootHex,
    );
  } else if (messageIndex === -1)
    await retryUnlistedRemoval(roomId, { merkleRootHex, hashHex, transferId });
};

// Close a listed message's channel and remove everything stored for it, for
// a call the application made to delete it (deleteMessage, cancelMessage).
//
// The call answers for the message's file: while it runs, the channel's own
// cancel and the delete the channel query dispatches are part of it and
// report nothing themselves. If the browser refuses to remove the file, the
// call rejects with one StorageFailedError (`cause`: the browser's error)
// after everything else was done. The message's records are gone by then, so
// it leaves the list either way; the file is tried again when the SDK next
// starts and when deleteMessage is called again with its Merkle root.
const removeStoredMessage = async (
  roomId: string,
  label: string,
  merkleRootHex: string,
): Promise<void> => {
  try {
    await answeringForRemoval(merkleRootHex, async () => {
      await store.dispatch(
        webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
          roomId,
          label,
          alsoDeleteData: true,
        }),
      );
      await deleteReceiveTransfer(merkleRootHex);
      await deleteDBNewChunk({ merkleRootHex });
    });
  } catch (error) {
    if (error instanceof StorageFailedError)
      store.dispatch(deleteMessageStateOnly({ roomId, merkleRootHex }));
    throw error;
  }
  store.dispatch(deleteMessageStateOnly({ roomId, merkleRootHex }));
};

/**
 * Delete a message of a room and everything stored for it. `merkleRoot` and
 * `hash` are the 128 lower-case hexadecimal characters the SDK reports, or
 * the 64 bytes those encode (InvalidMessageHashError otherwise).
 *
 * Rejects with StorageFailedError when the browser refuses to remove the
 * message's file; its records are deleted and it is unlisted all the same.
 * Calling again with the same arguments tries the file again, and rejects
 * while it is still on disk.
 *
 * Only a message this page lists is deleted. For any other name the call
 * tries again the file an earlier delete of this room's messages left, if
 * there is one, and otherwise resolves without changing anything: a file a
 * record still owns, or that another room's records name, is never touched.
 */
const deleteMsg = async (
  roomId: string,
  merkleRoot?: string | Uint8Array,
  hash?: string | Uint8Array,
) => {
  if (!merkleRoot && !hash)
    throw new Error("Need to provide either merkle root or hash");
  const merkleRootHex = messageHashHex(merkleRoot, "merkleRoot");
  const hashHex = messageHashHex(hash, "hash");

  await discardPendingSelection(
    {
      roomId,
      senderPublicKey: store.getState().keyPair.publicKey,
      merkleRootHex: merkleRootHex || undefined,
      hashHex: hashHex || undefined,
    },
    () => {
      abortTransfer(roomId, {
        merkleRootHex: merkleRootHex || undefined,
        hashHex: hashHex || undefined,
      });
    },
  );

  const { rooms } = store.getState();
  const roomIndex = rooms.findIndex((room) => room.id === roomId);
  const messageIndex =
    roomIndex > -1
      ? merkleRoot
        ? rooms[roomIndex].messages.findIndex(
            (message) => message.merkleRootHex === merkleRootHex,
          )
        : hash
          ? rooms[roomIndex].messages.findIndex(
              (message) => message.sha512Hex === hashHex,
            )
          : -1
      : -1;

  if (
    roomIndex > -1 &&
    messageIndex > -1 &&
    rooms[roomIndex].messages[messageIndex].merkleRootHex.length ===
      crypto_hash_sha512_BYTES * 2
  ) {
    const label = await compileChannelMessageLabel(
      rooms[roomIndex].messages[messageIndex].channelLabel,
      rooms[roomIndex].messages[messageIndex].merkleRootHex,
      // rooms[roomIndex].messages[messageIndex].sha512Hex,
    );

    await removeStoredMessage(
      rooms[roomIndex].id,
      label,
      rooms[roomIndex].messages[messageIndex].merkleRootHex,
    );
  } else if (messageIndex === -1)
    await retryUnlistedRemoval(roomId, { merkleRootHex, hashHex });
};

/**
 * Stop signaling, drain any cancelled identity bootstrap, then delete both
 * identity roles under that same exclusive boundary. This is the one purge
 * path so a late IndexedDB write cannot resurrect either identity.
 */
const stopSignalingAndDeleteIdentity = async (
  finishWhilePurged: () => Promise<void> = async () => undefined,
): Promise<void> => {
  const releaseIdentityBootstrap =
    await signalingAttemptLifecycle.cancelAndAcquireBootstrap();
  try {
    await runIdentityPurgeSettlement({
      disconnectSignaling: async () => {
        await dispatch(
          signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
        ).unwrap();
      },
      clearRoomPins: () => clearRoomPins(),
      resetIdentity: () => {
        dispatch(resetIdentity());
      },
      // Authenticated transports become terminal before either IndexedDB
      // identity deletion is awaited. A stalled database worker therefore
      // cannot leave traffic live under already-reset identity state.
      teardownRooms: finishWhilePurged,
      // D2=B: clear the wrapped X25519 identity and its Ed25519 cross-signature
      // before deleting the Ed25519 identity it authenticates.
      deleteIdentityX25519: () => deleteIdentityX25519(),
      deleteIdentityEd25519: () => deleteIdentityEd25519(),
      // Non-secret, but it describes the key just deleted: a surviving
      // "mnemonic" flag would tell the next, randomly generated identity that
      // it can be exported as a recovery phrase.
      deleteIdentityDerivation: () => deleteIdentityDerivation(),
    });
  } finally {
    // No await between the final cancellation/state reset and releasing the
    // purge lease: every attempt invoked during deletion remains rejected.
    signalingAttemptLifecycle.cancelActive();
    dispatch(signalingServerActions.disconnect());
    releaseIdentityBootstrap();
  }
};

/**
 * Bring every room's WebRTC transport to a terminal state without touching the
 * durable data behind it. Both identity-wide operations need exactly this: the
 * edges authenticated by the outgoing identity have to be closed, whether that
 * identity is being deleted or replaced.
 */
const disconnectEveryRoomTransport = async (message: string): Promise<void> => {
  const { rooms } = store.getState();
  await runTerminalSettlement(
    message,
    rooms.map(
      (room) => async () =>
        await dispatch(
          webrtcApi.endpoints.disconnectFromRoom.initiate({
            roomId: room.id,
          }),
        ).unwrap(),
    ),
  );
};

const purgeIdentity = async () => {
  await signalingRoomOperationLifecycle.runGlobalTerminal(async () => {
    abortAllTransfers();
    await stopSignalingAndDeleteIdentity(
      async () =>
        await disconnectEveryRoomTransport(
          "One or more WebRTC rooms could not be disconnected during identity purge",
        ),
    );
  });
};

const toIdentityBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);

  return buffer;
};

/**
 * The real seams behind an identity restore. The ordering contract that uses
 * them lives in `utils/identityRestore`, where it can be asserted without a
 * socket, a WebRTC stack or IndexedDB.
 */
const identityRestoreEffects: IdentityRestoreEffects = {
  deriveIdentity: async (mnemonic, password) =>
    await keyPairFromMnemonic(mnemonic, password),

  // The same exclusive boundary a purge takes: no connection attempt, room
  // operation or identity bootstrap can interleave with the swap, and any
  // in-flight attempt is cancelled before it can write the outgoing identity
  // back to storage.
  runExclusive: async (operation) =>
    await signalingRoomOperationLifecycle.runGlobalTerminal(async () => {
      abortAllTransfers();
      const releaseIdentityBootstrap =
        await signalingAttemptLifecycle.cancelAndAcquireBootstrap();
      try {
        return await operation();
      } finally {
        // No await between the final cancellation and releasing the lease, so
        // every attempt begun during the swap stays rejected.
        signalingAttemptLifecycle.cancelActive();
        dispatch(signalingServerActions.disconnect());
        releaseIdentityBootstrap();
      }
    }),

  disconnectSignaling: async () => {
    await dispatch(
      signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
    ).unwrap();
  },

  // Rooms, messages, the address book and the room PIN vault are all kept, so
  // the caller can reconnect to the same rooms under the restored identity.
  teardownRooms: async () =>
    await disconnectEveryRoomTransport(
      "One or more WebRTC rooms could not be disconnected during identity restore",
    ),

  deleteIdentityX25519: () => deleteIdentityX25519(),

  writeIdentityEd25519: async ({ publicKey, secretKey }) => {
    // The write boundary copies before it transfers, so this copy of the
    // account secret is ours to wipe rather than something the worker takes.
    const secret = toIdentityBuffer(secretKey);
    try {
      await setIdentityEd25519({ pub: toIdentityBuffer(publicKey), secret });
    } finally {
      if (secret.byteLength > 0) new Uint8Array(secret).fill(0);
    }
  },

  recordDerivation: async () => {
    await setIdentityDerivation("mnemonic");
  },

  resetIdentityState: () => {
    dispatch(resetIdentity());
  },

  adoptIdentity: (publicKey, secretKey) => {
    dispatch(setKeyPair({ publicKey, secretKey }));
  },
};

/**
 * Adopt the identity a recovery phrase encodes, in place of the current one.
 *
 * An invalid phrase rejects with `InvalidRecoveryPhraseError` before anything
 * is disconnected, so a typo costs nothing. Only a phrase that derives a key
 * opens the exclusive boundary: signaling is disconnected, every room's WebRTC
 * transport is brought to a terminal state, the cross-signed X25519 identity is
 * deleted (the next connection regenerates and re-signs it), the Ed25519 key is
 * persisted, and the identity is adopted in memory last.
 *
 * Rooms, messages, the address book and cached room PINs are all kept. Peers
 * see a new identity key for this device, exactly as they would after a purge,
 * so the address book will report an identity change.
 *
 * Signaling is left disconnected: call `connect(roomUrl)` afterwards to come
 * back online under the restored identity.
 *
 * @param mnemonic - The recovery phrase, in any transcription
 * @param password - The passphrase the identity was created with, if any
 * @returns The restored Ed25519 public key, hex-encoded
 */
const restoreIdentityFromMnemonic = async (
  mnemonic: string,
  password?: string,
): Promise<RestoredIdentity> =>
  await restoreIdentityFromMnemonicWith(
    identityRestoreEffects,
    mnemonic,
    password,
  );

/**
 * Replace the current identity with a freshly generated, recoverable one and
 * return the phrase that restores it.
 *
 * The phrase is shown once and stored nowhere: it is the only backup, and a
 * caller that drops it before the user has written it down has lost it. A
 * `password` is folded into the derivation and is equally unrecoverable — the
 * phrase alone will not restore the identity without it.
 *
 * As with `restoreIdentityFromMnemonic`, signaling is left disconnected; call
 * `connect(roomUrl)` afterwards.
 *
 * @param options - Entropy bits (128 gives 12 words, 256 gives 24) and an
 *   optional passphrase
 * @returns The recovery phrase and the Ed25519 public key it now derives
 */
const createRecoverableIdentity = async (
  options?: CreateRecoverableIdentityOptions,
): Promise<CreatedRecoverableIdentity> =>
  await createRecoverableIdentityWith(identityRestoreEffects, options);

/** What the current account key is, and whether a phrase can reproduce it. */
export interface IdentityBackupStatus {
  publicKey: string;
  derivation: IdentityDerivation | null;
}

/**
 * Whether the identity in use can be backed up at all.
 *
 * `derivation` is "mnemonic" only for an identity that was created from a
 * recovery phrase; a "random" one cannot be exported, and the only way to get a
 * recoverable identity is `createRecoverableIdentity`, which replaces it. It is
 * null when no identity is stored yet, and also when the stored flag no longer
 * describes the stored key — an unreadable provenance hint must never be
 * reported as "this can be backed up".
 *
 * @returns The current Ed25519 public key (empty when there is none) and how it
 *   came into being
 */
const getIdentityBackupStatus = async (): Promise<IdentityBackupStatus> => {
  let publicKey = keyPairSelector(store.getState()).publicKey;
  // Before the first connection Redux holds no identity, but one may already
  // be stored: reading the status must not depend on having connected.
  if (!isCanonicalEd25519Identity(publicKey)) {
    const stored = await getIdentityEd25519();
    publicKey = stored ? uint8ArrayToHex(new Uint8Array(stored.pub)) : "";
    // The read boundary hands back the account secret; nothing here wants it.
    if (stored) new Uint8Array(stored.secret).fill(0);
  }

  return { publicKey, derivation: await getIdentityDerivation() };
};

/**
 * Forget one room locally and request authoritative server unlinking.
 *
 * An offline or non-acknowledging server causes a
 * RemoteRoomRevocationUnconfirmedError only after local state, WebRTC
 * transports, and durable data have reached their terminal boundary. The
 * shared signaling socket and every other room remain untouched.
 */
// Every step runs even when an earlier one fails. A received file of the room
// that the browser refuses to remove makes this reject with one
// StorageFailedError (`cause`: what the purge's steps threw; `failures`: each
// file and the browser's error for it) after everything else was done.
const purgeRoom = async (roomUrl: string): Promise<void> => {
  roomUrl = normalizeRoomCapability(roomUrl);
  try {
    await purgeRoomSettled(roomUrl);
  } catch (error) {
    throw asStorageFailure(
      error,
      "p2party: purging the room left received files on disk",
    );
  }
};

const purgeRoomSettled = async (roomUrl: string): Promise<void> => {
  await signalingRoomOperationLifecycle.runRoomTerminal(roomUrl, async () => {
    const { rooms } = store.getState();
    const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
    // An unknown capability has no local or server-side membership to remove.
    // In particular it must not tear down the socket shared by other rooms.
    // It may name a room that was removed before, some of whose files the
    // browser refused to remove then. Those removals are tried again (the
    // files are found by a digest of this URL), and one that is refused again
    // rejects this call as it did the first. (Until the page is reloaded a
    // removed room is still listed, as a placeholder without an id; that
    // case goes through deleteStoredRoomData below, which does the same.)
    if (roomIndex === -1) {
      await retryFileRemovals({ roomUrl });
      return;
    }

    const removedRoom = rooms[roomIndex];
    deleteRoomPin(roomUrl);
    abortRoomTransfers(removedRoom.id);
    cancelRoomRequestLifecycle(roomUrl, "room was purged");
    // URL is the unique local room identity even while multiple pending rooms
    // all have id=""; deleting by id could cancel the wrong room.
    dispatch(deleteRoom(roomUrl));

    const needsRemoteRevocation = removedRoom.signalingActive !== false;
    await runRoomPurgeSettlement({
      closeLocalTransport: async () => {
        try {
          await getRoomIceConfigurationMutex(roomUrl).runExclusive(async () => {
            await dispatch(
              webrtcApi.endpoints.disconnectFromRoom.initiate({
                roomId: removedRoom.id,
              }),
            ).unwrap();
          });
        } finally {
          releaseRoomIceConfigurationMutex(roomUrl);
        }
      },
      startRemoteRevocation: async () => {
        if (!needsRemoteRevocation) return;
        await requestCurrentSocketRoomLeave(store, roomUrl);
      },
      // Awaited here, not inside the disconnect query, so a typed storage
      // failure reaches this call; closeLocalTransport already disconnected.
      deleteLocalData: () => deleteStoredRoomData(removedRoom.id, roomUrl),
      clearPinAttempts: async () => {
        await clearPinAttempts(deriveRoomLocator(roomUrl));
      },
    });
  });
};

// Every step runs even when an earlier one fails. A received file the wipe
// could not remove makes this reject with one StorageFailedError (`cause`:
// what the purge's steps threw; `failures`: each file and the browser's error
// for it) after everything else was done. The database is deleted either way,
// so such a file has no record left; the SDK removes it when it next starts,
// and calling purge again tries it at once.
const purge = async () => {
  try {
    await signalingRoomOperationLifecycle.runGlobalTerminal(async () => {
      abortAllTransfers();
      await stopSignalingAndDeleteIdentity(async () => {
        await runTerminalSettlement(
          "Full purge did not fully settle local data",
          [
            async () => {
              await dispatch(
                webrtcApi.endpoints.disconnect.initiate({
                  alsoDeleteDB: false,
                }),
              ).unwrap();
            },
            // Awaited here, not inside the disconnect query, so its typed
            // error reaches this call.
            () => deleteDB(),
            () => {
              dispatch(purgeAllRooms());
              dispatch(setCurrentRoomUrl(""));
            },
          ],
        );
      });
    });
  } catch (error) {
    throw asStorageFailure(
      error,
      "p2party: the purge left received files on disk",
    );
  }
};

const newRoomUrl = async () => {
  return encodeRoomCapabilityBase64Url(generateRoomCapability());
};

const newRoomInvite = () => encodeRoomInviteFragment(generateRoomCapability());

/**
 * Read-only diagnostic: what drives this page's scheduled-cover wake-ups now,
 * "worker" (its shared timer worker), "page" (page timers: no worker can run
 * here, or a lost one is being replaced) or "none" (no scheduled-cover edge is
 * open). On page timers a hidden page's cover cycles can degrade.
 */
const getCoverTimerSource = (): "worker" | "page" | "none" =>
  readCoverTimerSource();

export const p2party = {
  store,
  commonStateSelector,
  signalingServerSelector,
  roomSelector,
  keyPairSelector,
  connect,
  connectToSignalingServer,
  disconnectFromSignalingServer,
  disconnectFromRoom,
  disconnectFromAllRooms,
  disconnectFromPeer,
  allowConnectionRelay,
  onlyAllowConnectionsFromAddressBook,
  addPeerToAddressBook: setDBAddressBookEntry,
  getPeerAddressBookEntry: getDBAddressBookEntry,
  getAllPeersInAddressBook: getAllDBAddressBookEntries,
  getAllPeersInBlacklist: getAllDBBlacklisted,
  deletePeerFromAddressBook,
  blacklistPeer,
  getPeerIsBlacklisted: getDBPeerIsBlacklisted,
  removePeerFromBlacklist: deleteDBPeerFromBlacklist,
  getAllExistingRooms: getAllDBUniqueRooms,
  getRoomStats: getDBRoomStats,
  // openChannel,
  sendMessage,
  listPendingMessages,
  resumePendingMessages,
  cancelPendingMessage,
  readMessage,
  // Typed report of a received chunk this device could not store, or a
  // received file whose bytes failed whole-file verification.
  onReceiveStorageError,
  // Live outbound progress for one logical send: per peer, how many chunks
  // that peer has receipted so far. Pair it with the message row's totalChunks
  // for a percentage. Empty once the transfer is cleaned up.
  getTransferAcks,
  // Read-only diagnostic: how many outbound chunks are held for one random
  // transfer ID. 0 after completion/abandonment. Content hashes are deliberately
  // not accepted because identical concurrent sends are independent.
  getSendChunksCount: getDBAllNewChunksCount,
  cancelMessage,
  createTransferId,
  deleteMessage: deleteMsg,
  purgeIdentity,
  purgeRoom,
  purge,
  generateRandomRoomUrl: newRoomUrl,
  generateRoomInvite: newRoomInvite,
  generateRoomCapability,
  encodeRoomCapabilityBase64Url,
  decodeRoomCapabilityBase64Url,
  decodeRoomCapability,
  normalizeRoomCapability,
  encodeRoomInviteFragment,
  decodeRoomInviteFragment,
  encodeRoomCapabilityWords,
  decodeRoomCapabilityWords,
  ROOM_INVITE_WORDLIST_ID,
  sign,
  verify,
  createSession,
  restoreSession,
  generateSessionIdentity,
  SessionReplayError,
  setWasmSourceUrl,
  DEFAULT_ROOM_POLICY_V1,
  encodeRoomPolicyV1,
  decodeRoomPolicyV1,
  hashRoomPolicyV1,
  roomPoliciesEqualV1,
  // Industry-standard name (cf. WebCrypto `generateKey`, libsodium
  // `crypto_sign_keypair`) + consistent with `generateMnemonic` below.
  generateKeyPair: newKeyPair,
  // Deprecated alias of `generateKeyPair`, kept for back-compat.
  newKeyPair,
  generateMnemonic,
  keyPairFromMnemonic,
  validateMnemonic,
  validateMnemonicWords,
  // Identity backup: only an identity created from a phrase can be restored
  // from one, so `getIdentityBackupStatus` says whether the current one can,
  // and `createRecoverableIdentity` is how a random one is replaced by one
  // that can. Both leave signaling disconnected; reconnect with `connect`.
  createRecoverableIdentity,
  restoreIdentityFromMnemonic,
  getIdentityBackupStatus,
  InvalidRecoveryPhraseError,
  MIN_CHUNKS: 1,
  MIN_CHUNK_SIZE: CHUNK_SIZE_FLOOR + 1,
  MAX_CHUNK_SIZE: CHUNK_LEN,
  WIRE_CHUNK_FRAME_LEN,
  MIN_COVER_CADENCE_MS,
  MAX_COVER_CADENCE_MS,
  MAX_COVER_LANES,
  MAX_COVER_FRAMES_PER_CELL,
  MIN_COVER_SLOT_MS,
  validateRoomPolicyV1,
  MessageDeliveryError,
  SignalingVersionMismatchError,
  RemoteRoomRevocationUnconfirmedError,
  // The typed errors of storage, as the guide names them (`p2party.X`), so
  // that `error instanceof p2party.StorageFailedError` works with the default
  // import as it does with the named one.
  StorageFailedError,
  InvalidMessageHashError,
  InvalidTransferIdError,
  MissingMessageIdentifierError,
  ReceiveIntegrityError,
  DatabaseUnavailableError,
  DatabaseUpgradeBlockedError,
  DatabaseWorkerError,
  joinRoom,
  waitForRoom,
  waitForPeers,
  onMessage,
  setDebugLogging,
  getCoverTimerSource,
  MIN_PERCENTAGE_FILLED_CHUNK: 0.1,
  // 100%-full cells make identical content roots deterministic. Keep at least
  // 1% RNG padding as the fresh wire/storage transfer namespace; this is not a
  // room cover-cadence setting.
  MAX_PERCENTAGE_FILLED_CHUNK: 0.99,
  ROOM_URL_LENGTH: 64,
  MessageType,
  MessageCategory,
  VERSION: pkg.version,
};

if (typeof window !== "undefined") {
  window.p2party = p2party;
}

declare global {
  interface Window {
    p2party: typeof p2party;
  }
}

// export { MessageType, MessageCategory };

export type {
  State,
  Room,
  Peer,
  PeerSignalingPresence,
  Channel,
  Message,
  RoomData,
  MimeType,
  FileExtension,
  UsernamedPeer,
  BlacklistedPeer,
  UniqueRoom,
  RoomStats,
  SignalingState,
  KeyPair,
  RoomPolicyV1,
  IdentityDerivation,
  WebSocketMessageRoomIdRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageChallengeRequest,
  WebSocketMessageChallengeResponse,
  WebSocketMessageDescriptionSend,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateSend,
  WebSocketMessageCandidateReceive,
  WebSocketMessageLeaveRoomRequest,
  WebSocketMessageRoomLeftResponse,
  WebSocketMessageError,
  ReceiveStorageError,
};

export {
  createSession,
  restoreSession,
  generateSessionIdentity,
  SessionReplayError,
  setWasmSourceUrl,
  MessageDeliveryError,
  SignalingVersionMismatchError,
  RemoteRoomRevocationUnconfirmedError,
  createRecoverableIdentity,
  restoreIdentityFromMnemonic,
  getIdentityBackupStatus,
  validateMnemonic,
  validateMnemonicWords,
  InvalidRecoveryPhraseError,
  joinRoom,
  waitForRoom,
  waitForPeers,
  onMessage,
  onReceiveStorageError,
  ReceiveIntegrityError,
  DatabaseUnavailableError,
  DatabaseUpgradeBlockedError,
  DatabaseWorkerError,
  InvalidMessageHashError,
  InvalidTransferIdError,
  MissingMessageIdentifierError,
  StorageFailedError,
  setDebugLogging,
  getCoverTimerSource,
};

export {
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
  decodeRoomPolicyV1,
  encodeRoomPolicyV1,
  hashRoomPolicyV1,
  roomPoliciesEqualV1,
};

// The bounds a scheduled cover schedule must satisfy, and the exact wire size
// of one cell. Consumers building a policy UI need these to validate before
// they construct a policy; re-declaring them downstream drifts silently.
export {
  MIN_COVER_CADENCE_MS,
  MAX_COVER_CADENCE_MS,
  MAX_COVER_LANES,
  MAX_COVER_FRAMES_PER_CELL,
  MIN_COVER_SLOT_MS,
  validateRoomPolicyV1,
  WIRE_CHUNK_FRAME_LEN,
};

export type { TransferAck } from "./handlers/reconcile";
// One entry of `StorageFailedError.failures`: a file and the browser's error.
export type { FileRemovalFailure } from "./db/dbErrors";

// The identity-backup surface: what a phrase produces, what it costs to make
// one, and the shape `validateMnemonicWords` reports a bad phrase in.
export type { MnemonicValidation } from "./cryptography/mnemonic";
export type {
  CreatedRecoverableIdentity,
  CreateRecoverableIdentityOptions,
  RestoredIdentity,
} from "./utils/identityRestore";

export type {
  RoomAuthMode,
  RoomCoverMode,
  RoomPqMode,
  RoomRendezvousMode,
} from "./roomPolicy";

export type {
  CreateSessionOptions,
  EncryptedSessionMessage,
  GenerateSessionIdentityOptions,
  GeneratedSessionIdentity,
  HandshakeTransport,
  LocalSessionIdentity,
  P2PartySession,
  SessionChannelBinding,
  SessionCryptoOptions,
} from "./session";

export default p2party;
