import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { generateRandomRoomUrl } from "./cryptography/utils";

import { getDBAllChunks } from "./db/api";
import {
  getFileExtension,
  getMessageCategory,
  getMimeType,
} from "./utils/messageTypes";

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import {
  roomSelector,
  setConnectingToPeers,
  setConnectionRelay,
  setRoom,
  deleteMessage,
  deleteAll,
} from "./reducers/roomSlice";
import { keyPairSelector } from "./reducers/keyPairSlice";
import { signalingServerSelector } from "./reducers/signalingServerSlice";

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
import { compileChannelMessageLabel } from "./utils/channelLabel";
import { uint8ArrayToHex } from "./utils/uint8array";
import { crypto_hash_sha512_BYTES } from "./cryptography/interfaces";

const connect = (
  roomUrl: string,
  signalingServerUrl = "ws://localhost:3001/ws",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        urls: [
          "stun:127.0.0.1:3478",
          "stun:stun.l.google.com:19302",
          "stun:stun1.l.google.com:19302",
        ],
      },
      {
        urls: ["turn:127.0.0.1:3478"],
        username: "username", // Dummy username
        credential: "password", // Dummy password
      },
    ],
    iceTransportPolicy: "all", // Use 'relay' if you want to force TURN server usage
  },
) => {
  const { keyPair, signalingServer, room } = store.getState();

  if (room.url !== roomUrl) {
    dispatch(setRoom({ url: roomUrl, id: "", rtcConfig }));
  }

  if (signalingServer.isConnected && isUUID(keyPair.peerId)) {
    const { room } = store.getState();
    if (!isUUID(room.id)) {
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
  signalingServerUrl = "ws://localhost:3001/ws",
) => {
  dispatch(
    signalingServerApi.endpoints.connectWebSocket.initiate(signalingServerUrl),
  );
};

const disconnectFromSignalingServer = () => {
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const allowConnectionRelay = (allowed = true) => {
  dispatch(setConnectionRelay(allowed));
};

const disconnectFromRoom = (roomId: string, _deleteMessages = false) => {
  dispatch(webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId }));
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
const sendMessage = (data: string | File, toChannel: string) => {
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
    }),
  );
};

const readMessage = async (
  merkleRootHex: string,
): Promise<{
  message: string | Blob;
  percentage: number;
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

    const root = room.messages[messageIndex].merkleRootHex;
    const chunks =
      percentage === 100
        ? await getDBAllChunks(root)
        : [
            {
              merkleRoot: merkleRootHex,
              chunkIndex: 0,
              data: new Blob([new Uint8Array()]),
              mimeType,
            },
          ];
    const dataChunks = chunks
      .sort((a, b) => a.chunkIndex - b.chunkIndex)
      .map((c) => c.data);
    const data = new Blob(dataChunks, {
      type: mimeType,
    });

    if (messageType === 1) {
      return {
        message: await data.text(),
        percentage,
        mimeType,
        extension,
        category,
      };
    } else if (data) {
      return {
        message: data,
        percentage,
        mimeType,
        extension,
        category,
      };
    } else {
      return {
        message: "Invalid message",
        percentage: 0,
        mimeType,
        extension: "",
        category: MessageCategory.Text,
      };
    }
  } catch (error) {
    console.error(error);

    return {
      message: "Inretrievable message",
      percentage: 0,
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

  dispatch(
    deleteMessage({ merkleRootHex: room.messages[messageIndex].merkleRootHex }),
  );
};

const purge = () => {
  dispatch(deleteAll());
};

export default {
  store,
  signalingServerSelector,
  roomSelector,
  keyPairSelector,
  connect,
  connectToSignalingServer,
  disconnectFromSignalingServer,
  allowConnectionRelay,
  disconnectFromRoom,
  openChannel,
  sendMessage,
  readMessage,
  cancelMessage,
  deleteMessage: deleteMsg,
  purge,
  generateRandomRoomUrl,
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
