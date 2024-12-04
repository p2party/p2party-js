import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { generateRandomRoomUrl } from "./cryptography/utils";

import {
  // createIDBReadableStream,
  getDBAllChunks,
} from "./utils/db";
import {
  getFileExtension,
  getMessageCategory,
  getMimeType,
} from "./utils/messageTypes";
// import { concatUint8Arrays, hexToUint8Array } from "./utils/uint8array";

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import {
  roomSelector,
  setConnectingToPeers,
  setConnectionRelay,
  setRoom,
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
import { uint8ArrayToHex } from "./utils/uint8array";

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
  hashMatches: boolean;
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
        hashMatches: false,
      };
    }

    const root = room.messages[messageIndex].merkleRootHex;
    const messageType = room.messages[messageIndex].messageType;

    const chunks = await getDBAllChunks(root);

    const dataChunks = chunks
      .sort((a, b) => a.chunkIndex - b.chunkIndex)
      .map((c) => c.data); // hexToUint8Array(c.data));

    const mimeType = getMimeType(messageType);
    const extension = getFileExtension(messageType);
    const category = getMessageCategory(messageType);

    const data = new Blob(dataChunks, {
      type: mimeType,
    });

    const dataArrayBuffer = await data.arrayBuffer();
    const hashArrayBuffer = await window.crypto.subtle.digest(
      "SHA-512",
      dataArrayBuffer,
    );
    const hash = new Uint8Array(hashArrayBuffer);
    const hashHex = uint8ArrayToHex(hash);

    const percentage = Math.floor(
      (room.messages[messageIndex].savedSize /
        room.messages[messageIndex].totalSize) *
        100,
    );

    if (messageType === 1) {
      return {
        message: await data.text(),
        percentage,
        mimeType,
        extension,
        category,
        hashMatches: room.messages[messageIndex].sha512Hex === hashHex,
      };
    } else if (data) {
      return {
        message: data,
        percentage,
        mimeType,
        extension,
        category,
        hashMatches: room.messages[messageIndex].sha512Hex === hashHex,
      };
    } else {
      return {
        message: "Invalid message",
        percentage: 0,
        mimeType,
        extension: "",
        category: MessageCategory.Text,
        hashMatches: false,
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
      hashMatches: false,
    };
  }
};

export default {
  store,
  signalingServerSelector,
  roomSelector,
  keyPairSelector,
  connect,
  connectToSignalingServer,
  // connectToRoomPeers,
  disconnectFromSignalingServer,
  allowConnectionRelay,
  disconnectFromRoom,
  openChannel,
  sendMessage,
  readMessage,
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
