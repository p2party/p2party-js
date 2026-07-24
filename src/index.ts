import { isUUID } from "class-validator";
import pkg from "../package.json";

import { store, dispatch } from "./store";

import { newKeyPair, sign, verify } from "./cryptography/ed25519";
import {
  createSession,
  generateSessionIdentity,
  restoreSession,
} from "./session";
import { generateMnemonic, keyPairFromMnemonic } from "./cryptography/mnemonic";
import { crypto_hash_sha512_BYTES } from "./cryptography/interfaces";

import {
  deleteDBAddressBookEntry,
  deleteDBPeerFromBlacklist,
  getAllDBAddressBookEntries,
  assembleToOPFS,
  getReceiveFile,
  getAllDBBlacklisted,
  getAllDBUniqueRooms,
  deleteIdentityEd25519,
  deleteIdentityX25519,
  getDBAddressBookEntry,
  getDBAllChunks,
  getDBAllNewChunksCount,
  getDBPeerIsBlacklisted,
  setDBAddressBookEntry,
  setDBPeerInBlacklist,
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
  PROTOCOL_VERSION,
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
  canonicalizeRoomPolicyV1,
  decodeRoomPolicyV1,
  encodeRoomPolicyV1,
  hashRoomPolicyV1,
  roomPoliciesEqualV1,
} from "./roomPolicy";
import {
  clearRoomPins,
  deleteRoomPin,
  hasRoomPin,
  putRoomPin,
} from "./roomPinVault";
import { clearPinAttempts } from "./roomPinAttempts";
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

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import { commonStateSelector } from "./reducers/commonSlice";
import {
  roomSelector,
  setConnectionRelay,
  setRoom,
  setRoomPolicy,
  deleteMessage,
  deleteRoom,
  setConnectingToPeers,
} from "./reducers/roomSlice";
import { keyPairSelector, resetIdentity } from "./reducers/keyPairSlice";
import { signalingServerSelector } from "./reducers/signalingServerSlice";
import { setCurrentRoomUrl } from "./reducers/commonSlice";

import { compileChannelMessageLabel } from "./utils/channelLabel";
import { uint8ArrayToHex } from "./utils/uint8array";

import type { State } from "./store";
import type { Room, Peer, Channel, Message } from "./reducers/roomSlice";
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
  WebSocketMessageError,
} from "./utils/interfaces";
import type { RoomData } from "./api/webrtc/interfaces";
import type { BlacklistedPeer, UsernamedPeer, UniqueRoom } from "./db/types";
import type { KeyPair } from "./reducers/keyPairSlice";
import type { RoomPolicyV1 } from "./roomPolicy";
import type { SendMessageResult } from "./handlers/handleSendMessage";

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

const connect = async (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        // Use single STUN URL - multiple STUN servers slow down ICE gathering
        urls: "stun:stun.p2party.com:3478",
      },
    ],
    iceTransportPolicy: "all",
    // Pre-allocate ICE candidates for faster connection setup
    iceCandidatePoolSize: 2,
  },
  options: ConnectRoomOptions = {},
) => {
  roomUrl = normalizeRoomCapability(roomUrl);
  if (options === null || typeof options !== "object" || Array.isArray(options))
    throw new Error("Invalid room connection options");

  const { keyPair, signalingServer, rooms, commonState } = store.getState();

  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
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
  if (
    persistedPolicy &&
    options.policy &&
    !roomPoliciesEqualV1(persistedPolicy, options.policy)
  )
    throw new Error("Persisted room policy is immutable");
  const policy = canonicalizeRoomPolicyV1(
    options.policy ??
      (roomIndex > -1
        ? rooms[roomIndex].policy
        : (persistedPolicy ?? DEFAULT_ROOM_POLICY_V1)),
  );

  // Stable descriptor codes may precede their live implementation, but the
  // public connect path must never silently claim an unwired guarantee.
  if (policy.rendezvousMode !== "legacy-signaling")
    throw new Error("Private rendezvous room connections are not wired yet");
  if (policy.coverMode !== "immediate")
    throw new Error("Scheduled-cover room connections are not wired yet");

  if (policy.authMode === "pin") {
    if (options.pin !== undefined) {
      putRoomPin(roomUrl, options.pin);
      const existingRoomId = roomIndex > -1 ? rooms[roomIndex].id : "";
      if (existingRoomId) await clearPinAttempts(existingRoomId);
    } else if (!hasRoomPin(roomUrl)) {
      throw new Error("PIN room connection requires a PIN");
    }
  } else {
    if (options.pin !== undefined)
      throw new Error("PIN must not be provided for a no-PIN room");
    // A deliberate switch back to no-PIN must not leave the old secret alive.
    deleteRoomPin(roomUrl);
  }

  if (roomIndex === -1) {
    dispatch(setRoom({ url: roomUrl, id: "", rtcConfig, policy }));
  } else {
    dispatch(setRoomPolicy({ roomContext: roomUrl, policy }));
  }

  if (commonState.currentRoomUrl !== roomUrl)
    dispatch(setCurrentRoomUrl(roomUrl));

  if (
    signalingServer.isConnected &&
    signalingServer.isVerified &&
    isUUID(keyPair.peerId)
  ) {
    if (roomIndex === -1) {
      await dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "room",
            fromPeerId: keyPair.peerId,
            roomUrl,
            protocolVersion: PROTOCOL_VERSION,
          } as WebSocketMessageRoomIdRequest,
        }),
      );
    } else {
      dispatch(
        setConnectingToPeers({
          roomId: rooms[roomIndex].id,
          connectingToPeers: true,
        }),
      );
    }
  } else {
    await dispatch(
      signalingServerApi.endpoints.connectWebSocket.initiate(
        signalingServerUrl,
      ),
    );
  }
};

const connectToSignalingServer = async (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
) => {
  roomUrl = normalizeRoomCapability(roomUrl);

  const { signalingServer, rooms, commonState } = store.getState();

  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex === -1) dispatch(setRoom({ url: roomUrl, id: "" }));

  if (commonState.currentRoomUrl !== roomUrl)
    dispatch(setCurrentRoomUrl(roomUrl));

  if (
    signalingServer.serverUrl !== signalingServerUrl ||
    (!signalingServer.isConnected && !signalingServer.isEstablishingConnection)
  ) {
    await dispatch(
      signalingServerApi.endpoints.connectWebSocket.initiate(
        signalingServerUrl,
      ),
    );
  }
};

const disconnectFromSignalingServer = async () => {
  await dispatch(
    signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
  );
};

const disconnectFromPeer = async (peerId: string) => {
  await dispatch(webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }));
};

const disconnectFromRoom = async (roomId: string, deleteMessages = false) => {
  await dispatch(
    webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId, deleteMessages }),
  );
};

const disconnectFromAllRooms = async (
  deleteMessages = false,
  exceptionRoomIds: string[] = [],
) => {
  await dispatch(
    webrtcApi.endpoints.disconnectFromAllRooms.initiate({
      deleteMessages,
      exceptionRoomIds,
    }),
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

  if (
    roomIndex > -1 &&
    !rooms[roomIndex].onlyConnectWithKnownAddresses &&
    onlyAllow &&
    rooms[roomIndex].peers.length > 0
  ) {
    const peersLen = rooms[roomIndex].peers.length;
    for (let i = 0; i < peersLen; i++) {
      const address = await getDBAddressBookEntry(
        rooms[roomIndex].peers[i].peerId,
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
    setRoom({
      url: roomIndex > -1 ? rooms[roomIndex].url : roomUrl,
      id: roomIndex > -1 ? rooms[roomIndex].id : "",
      onlyConnectWithKnownPeers: onlyAllow,
    }),
  );
};

const deletePeerFromAddressBook = async (
  username?: string,
  peerId?: string,
  peerPublicKey?: string,
) => {
  const pId = await deleteDBAddressBookEntry(username, peerId, peerPublicKey);
  if (isUUID(pId)) {
    await dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({
        peerId: pId,
        alsoDeleteData: false,
      }),
    );
  }
};

const blacklistPeer = async (peerId: string, peerPublicKey: string) => {
  await setDBPeerInBlacklist(peerId, peerPublicKey);
  await dispatch(
    webrtcApi.endpoints.disconnectFromPeer.initiate({
      peerId,
      alsoDeleteData: true,
    }),
  );
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
   * Resolves only after every started peer send/reconciliation and cleanup
   * settles, preserving the ordered per-peer delivery outcomes.
   */
  readonly done: Promise<SendMessageResult | undefined>;
  /** Cancels exactly this logical send, even before hashing/WASM setup finishes. */
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

const cancelMessage = async (
  roomId: string,
  channelLabel: string,
  merkleRoot?: string | Uint8Array,
  hash?: string | Uint8Array,
  transferId?: string,
) => {
  if (!transferId && !merkleRoot && !hash)
    throw new Error("Need to provide a transfer ID, Merkle root, or hash");
  if (transferId && !/^[0-9a-f]{64}$/.test(transferId))
    throw new Error("Invalid transfer ID");
  if (
    merkleRoot &&
    typeof merkleRoot === "string" &&
    merkleRoot.length !== crypto_hash_sha512_BYTES * 2
  )
    throw new Error("Invalid Merkle root length");
  if (
    merkleRoot &&
    typeof merkleRoot !== "string" &&
    merkleRoot.length !== crypto_hash_sha512_BYTES
  )
    throw new Error("Invalid Merkle root length");

  if (
    hash &&
    typeof hash === "string" &&
    hash.length !== crypto_hash_sha512_BYTES * 2
  )
    throw new Error("Invalid hash length");
  if (
    hash &&
    typeof hash !== "string" &&
    hash.length !== crypto_hash_sha512_BYTES
  )
    throw new Error("Invalid hash length");

  const merkleRootHex =
    merkleRoot && typeof merkleRoot === "string"
      ? merkleRoot
      : merkleRoot && typeof merkleRoot !== "string"
        ? uint8ArrayToHex(merkleRoot)
        : "";
  const hashHex =
    hash && typeof hash === "string"
      ? hash
      : hash && typeof hash !== "string"
        ? uint8ArrayToHex(hash)
        : "";

  abortTransfer(roomId, {
    transferId,
    merkleRootHex: merkleRootHex || undefined,
    hashHex: hashHex || undefined,
  });

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

    await store.dispatch(
      webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
        roomId: rooms[roomIndex].id,
        label,
        alsoDeleteData: true,
      }),
    );

    store.dispatch(
      deleteMessage({
        roomId,
        merkleRootHex: rooms[roomIndex].messages[messageIndex].merkleRootHex,
      }),
    );
  }
};

const deleteMsg = async (
  roomId: string,
  merkleRoot?: string | Uint8Array,
  hash?: string | Uint8Array,
) => {
  if (!merkleRoot && !hash)
    throw new Error("Need to provide either merkle root or hash");
  if (
    merkleRoot &&
    typeof merkleRoot === "string" &&
    merkleRoot.length !== crypto_hash_sha512_BYTES * 2
  )
    throw new Error("Invalid Merkle root length");
  if (
    merkleRoot &&
    typeof merkleRoot !== "string" &&
    merkleRoot.length !== crypto_hash_sha512_BYTES
  )
    throw new Error("Invalid Merkle root length");
  if (
    hash &&
    typeof hash === "string" &&
    hash.length !== crypto_hash_sha512_BYTES * 2
  )
    throw new Error("Invalid hash length");
  if (
    hash &&
    typeof hash !== "string" &&
    hash.length !== crypto_hash_sha512_BYTES
  )
    throw new Error("Invalid hash length");

  const merkleRootHex =
    merkleRoot && typeof merkleRoot === "string"
      ? merkleRoot
      : merkleRoot && typeof merkleRoot !== "string"
        ? uint8ArrayToHex(merkleRoot)
        : "";
  const hashHex =
    hash && typeof hash === "string"
      ? hash
      : hash && typeof hash !== "string"
        ? uint8ArrayToHex(hash)
        : "";

  abortTransfer(roomId, {
    merkleRootHex: merkleRootHex || undefined,
    hashHex: hashHex || undefined,
  });

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

    await store.dispatch(
      webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
        roomId: rooms[roomIndex].id,
        label,
        alsoDeleteData: true,
      }),
    );

    store.dispatch(
      deleteMessage({
        roomId,
        merkleRootHex: rooms[roomIndex].messages[messageIndex].merkleRootHex,
      }),
    );
  }
};

const purgeIdentity = async () => {
  abortAllTransfers();

  clearRoomPins();
  dispatch(resetIdentity());
  // D2=B: the X25519 identity lives WebCrypto-wrapped in IndexedDB, not in the
  // Redux/localStorage identity — clear it too so a rotated Ed25519 identity never
  // leaves an orphaned X25519 record + cross-sig behind.
  await deleteIdentityX25519();
  await deleteIdentityEd25519();

  const { rooms } = store.getState();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    await dispatch(
      webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId: rooms[i].id }),
    );
  }
  await dispatch(
    signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
  );
};

const purgeRoom = async (roomUrl: string) => {
  roomUrl = normalizeRoomCapability(roomUrl);
  deleteRoomPin(roomUrl);
  const { rooms } = store.getState();
  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex > -1) {
    abortRoomTransfers(rooms[roomIndex].id);
    if (rooms[roomIndex].id) await clearPinAttempts(rooms[roomIndex].id);
    dispatch(deleteRoom(rooms[roomIndex].id));
  }

  await dispatch(
    signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
  );
};

const purge = async () => {
  abortAllTransfers();

  clearRoomPins();
  dispatch(resetIdentity());
  await deleteIdentityX25519(); // D2=B: clear the wrapped X25519 identity record too
  await deleteIdentityEd25519();
  await dispatch(
    signalingServerApi.endpoints.disconnectWebSocket.initiate(undefined),
  );

  const rooms = await getAllDBUniqueRooms();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    dispatch(deleteRoom(rooms[i].roomId));
  }
};

const newRoomUrl = async () => {
  return encodeRoomCapabilityBase64Url(generateRoomCapability());
};

const newRoomInvite = () => encodeRoomInviteFragment(generateRoomCapability());

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
  // openChannel,
  sendMessage,
  readMessage,
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
  MIN_CHUNKS: 1,
  MIN_CHUNK_SIZE: CHUNK_SIZE_FLOOR + 1,
  MAX_CHUNK_SIZE: CHUNK_LEN,
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
  Channel,
  Message,
  RoomData,
  MimeType,
  FileExtension,
  UsernamedPeer,
  BlacklistedPeer,
  UniqueRoom,
  SignalingState,
  KeyPair,
  RoomPolicyV1,
  WebSocketMessageRoomIdRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageChallengeRequest,
  WebSocketMessageChallengeResponse,
  WebSocketMessageDescriptionSend,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateSend,
  WebSocketMessageCandidateReceive,
  WebSocketMessageError,
};

export { createSession, restoreSession, generateSessionIdentity };

export {
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
  decodeRoomPolicyV1,
  encodeRoomPolicyV1,
  hashRoomPolicyV1,
  roomPoliciesEqualV1,
};

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
