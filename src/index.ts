import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { generateRandomRoomUrl } from "./cryptography/utils";

import { getDBAllChunks } from "./db/api";
import {
  getFileExtension,
  getMessageCategory,
  getMimeType,
} from "./utils/messageTypes";
import { CHUNK_LEN, IMPORTANT_DATA_LEN } from "./utils/splitToChunks";

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import {
  roomSelector,
  setConnectionRelay,
  setRoom,
  deleteMessage,
  deleteRoom,
  setConnectingToPeers,
} from "./reducers/roomSlice";
import { keyPairSelector, resetIdentity } from "./reducers/keyPairSlice";
import { signalingServerSelector } from "./reducers/signalingServerSlice";

import { compileChannelMessageLabel } from "./utils/channelLabel";
import { uint8ArrayToHex } from "./utils/uint8array";
import { crypto_hash_sha512_BYTES } from "./cryptography/interfaces";

import type { State } from "./store";
import type { Room, Peer, Channel, Message } from "./reducers/roomSlice";
import {
  MessageCategory,
  MessageType,
  type MimeType,
  type FileExtension,
} from "./utils/messageTypes";
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

const connect = (
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        urls: [
          "stun:stun.p2party.com:3478",
          // "stun:stun.l.google.com:19302",
          // "stun:stun1.l.google.com:19302",
        ],
      },
    ],
    iceTransportPolicy: "all",
  },
) => {
  const { keyPair, signalingServer, room } = store.getState();

  if (room.url !== roomUrl) {
    dispatch(setRoom({ url: roomUrl, id: "", rtcConfig }));
  }

  if (signalingServer.isConnected && isUUID(keyPair.peerId)) {
    if (roomUrl !== room.url) {
      dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "room",
            fromPeerId: keyPair.peerId,
            roomUrl,
          } as WebSocketMessageRoomIdRequest,
        }),
      );
    } else {
      dispatch(setConnectingToPeers(true));
    }
  } else {
    dispatch(
      signalingServerApi.endpoints.connectWebSocket.initiate(
        signalingServerUrl,
      ),
    );
  }
};

const connectToSignalingServer = (
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
) => {
  dispatch(
    signalingServerApi.endpoints.connectWebSocket.initiate(signalingServerUrl),
  );
};

const disconnectFromSignalingServer = () => {
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const disconnectFromPeer = (peerId: string) => {
  dispatch(webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }));
};

const disconnectFromRoom = (roomId: string, _deleteMessages = false) => {
  dispatch(webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId }));
};

const allowConnectionRelay = (allowed = true) => {
  dispatch(setConnectionRelay(allowed));
};

const openChannel = async (
  label: string,
  withPeers?: { peerId: string; peerPublicKey: string }[],
) => {
  dispatch(
    webrtcApi.endpoints.openChannel.initiate({
      channel: label,
      withPeers,
    }),
  );
};

/**
 * If no toChannel then broadcast the message everywhere to everyone.
 * If toChannel then broadcast to all peers with that channel.
 */
const sendMessage = (
  data: string | File,
  toChannel: string,
  minChunks = 4,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
) => {
  // dispatch(
  //   signalingServerApi.endpoints.sendMessageToPeer.initiate({
  //     data,
  //     // fromPeerId: keyPair.peerId,
  //     toChannel,
  //   }),
  // );

  dispatch(
    webrtcApi.endpoints.sendMessage.initiate({
      data,
      label: toChannel,
      minChunks,
      chunkSize,
      percentageFilledChunk,
      metadataSchemaVersion,
    }),
  );
};

const readMessage = async (
  merkleRootHex: string,
): Promise<{
  message: string | Blob;
  percentage: number;
  size: number;
  filename: string;
  mimeType: MimeType;
  extension: FileExtension;
  category: MessageCategory;
}> => {
  try {
    const { room } = store.getState();

    const messageIndex = room.messages.findIndex(
      (m) => m.merkleRootHex === merkleRootHex,
    );
    if (messageIndex === -1) {
      return {
        message: "Unknown message",
        percentage: 0,
        size: 0,
        filename: "",
        mimeType: "text/plain",
        extension: "",
        category: MessageCategory.Text,
      };
    }

    const messageType = room.messages[messageIndex].messageType;
    const mimeType = getMimeType(messageType);
    const extension = getFileExtension(messageType);
    const category = getMessageCategory(messageType);

    const percentage = Math.floor(
      (room.messages[messageIndex].savedSize /
        room.messages[messageIndex].totalSize) *
        100,
    );

    if (percentage === 100) {
      const label = await compileChannelMessageLabel(
        room.messages[messageIndex].channelLabel,
        room.messages[messageIndex].merkleRootHex,
        room.messages[messageIndex].sha512Hex,
      );

      await store.dispatch(
        webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
          label,
          alsoDeleteData: false,
        }),
      );
    }

    const root = room.messages[messageIndex].merkleRootHex;
    const chunks =
      percentage === 100
        ? await getDBAllChunks(root)
        : [
            // {
            //   merkleRoot: merkleRootHex,
            //   chunkIndex: -1,
            //   data: new Uint8Array().buffer,
            //   mimeType,
            // },
          ];
    const dataChunks =
      chunks.length > 0
        ? chunks.sort((a, b) => a.chunkIndex - b.chunkIndex).map((c) => c.data)
        : [new Uint8Array().buffer];
    const data = new Blob(dataChunks, {
      type: mimeType,
    });

    if (messageType === MessageType.Text) {
      return {
        message: await data.text(),
        percentage,
        size: room.messages[messageIndex].totalSize,
        filename: "",
        mimeType,
        extension,
        category,
      };
    } else if (data) {
      return {
        message: data,
        percentage,
        size: room.messages[messageIndex].totalSize,
        filename: room.messages[messageIndex].filename,
        mimeType,
        extension,
        category,
      };
    } else {
      return {
        message: "Invalid message",
        percentage: 0,
        size: room.messages[messageIndex].totalSize,
        filename: room.messages[messageIndex].filename,
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
  channelLabel: string,
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

  const { room } = store.getState();

  const messageIndex = merkleRoot
    ? room.messages.findIndex((m) => m.merkleRootHex === merkleRootHex)
    : hash
      ? room.messages.findIndex((m) => m.sha512Hex === hashHex)
      : -1;

  if (messageIndex === -1) return;

  const label = await compileChannelMessageLabel(
    channelLabel,
    room.messages[messageIndex].merkleRootHex,
    room.messages[messageIndex].sha512Hex,
  );

  dispatch(
    webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
      label,
      alsoDeleteData: true,
    }),
  );
};

const deleteMsg = async (
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

  const { room } = store.getState();

  const messageIndex = merkleRoot
    ? room.messages.findIndex((m) => m.merkleRootHex === merkleRootHex)
    : hash
      ? room.messages.findIndex((m) => m.sha512Hex === hashHex)
      : -1;

  if (messageIndex === -1) return;

  const label = await compileChannelMessageLabel(
    room.messages[messageIndex].channelLabel,
    room.messages[messageIndex].merkleRootHex,
    room.messages[messageIndex].sha512Hex,
  );

  store.dispatch(
    webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
      label,
      alsoDeleteData: true,
    }),
  );

  dispatch(
    deleteMessage({ merkleRootHex: room.messages[messageIndex].merkleRootHex }),
  );
};

const purgeIdentity = () => {
  const { room } = store.getState() as State;
  dispatch(resetIdentity());
  dispatch(
    webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId: room.id }),
  );
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const purgeRoom = () => {
  dispatch(deleteRoom());
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const purge = () => {
  dispatch(deleteRoom());
  dispatch(resetIdentity());
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

export default {
  store,
  signalingServerSelector,
  roomSelector,
  keyPairSelector,
  connect,
  connectToSignalingServer,
  disconnectFromSignalingServer,
  disconnectFromRoom,
  disconnectFromPeer,
  allowConnectionRelay,
  openChannel,
  sendMessage,
  readMessage,
  cancelMessage,
  deleteMessage: deleteMsg,
  purgeIdentity,
  purgeRoom,
  purge,
  generateRandomRoomUrl,
  MIN_CHUNKS: 3,
  MIN_CHUNK_SIZE: IMPORTANT_DATA_LEN + 1,
  MAX_CHUNK_SIZE: CHUNK_LEN,
  MIN_PERCENTAGE_FILLED_CHUNK: 0.1,
  MAX_PERCENTAGE_FILLED_CHUNK: 1,
};

export { MessageType, MessageCategory };

export type {
  State,
  Room,
  Peer,
  Channel,
  Message,
  RoomData,
  MimeType,
  FileExtension,
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
