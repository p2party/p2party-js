import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { generateRandomRoomUrl } from "./cryptography/utils";

import { getDBAllChunks } from "./utils/db";
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

const connect = (
  roomUrl: string,
  signalingServerUrl = "ws://localhost:3001/ws",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
      urls: ['stun:127.0.0.1:3478'],
      },
      {
        urls: ['turn:127.0.0.1:3478'],
        username: 'username',       // Dummy username
        credential: 'password' // Dummy password
      },
    ],
    // Optional: Specify ICE transport policy
    iceTransportPolicy: 'all', // Use 'relay' if you want to force TURN server usage

    // iceServers: [
      // {
      //   urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
      // },
    // ],
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
const sendMessage = (data: string | File, toChannel?: string) => {
  const { keyPair } = store.getState();

  // dispatch(
  //   signalingServerApi.endpoints.sendMessageToPeer.initiate({
  //     data,
  //     // fromPeerId: keyPair.peerId,
  //     toChannel,
  //   }),
  // );

  dispatch(
    webrtcApi.endpoints.message.initiate({
      data,
      fromPeerId: keyPair.peerId,
      label: toChannel,
    }),
  );
};

const readMessage = async (
  merkleRootHex: string,
): Promise<{
  message: string | Blob;
  percentage: number;
  category: MessageCategory;
  filename: string;
  extension: FileExtension;
  mimeType: MimeType;
}> => {
  try {
    const { room } = store.getState();

    const messageIndex = room.messages.findIndex(
      (m) => m.merkleRootHex === merkleRootHex,
    );
    if (messageIndex === -1) {
      return {
        message: "Unknown message",
        percentage: 100,
        category: MessageCategory.Text,
        filename: "txt",
        extension: "",
        mimeType: "text/plain"
      };
    }

    const root = room.messages[messageIndex].merkleRootHex;
    const messageType = room.messages[messageIndex].messageType;
    const percentage =
      Math.ceil(
        room.messages[messageIndex].savedSize /
          room.messages[messageIndex].totalSize,
      ) * 100;

    const chunks = await getDBAllChunks(root);

    const dataChunks = chunks
      .sort((a, b) => a.chunkIndex - b.chunkIndex)
      .map((c) => c.data); // hexToUint8Array(c.data));

    const filename = messageType === MessageType.Text ? "txt" : room.messages[messageIndex].filename
    const mimeType = getMimeType(messageType);
    const extension = getFileExtension(messageType);
    const category = getMessageCategory(messageType);

    const data = new Blob(dataChunks, {
      type: mimeType,
    }); // await concatUint8Arrays(dataChunks);

    if (messageType === 1) {
      return {
        message: await data.text(), // new TextDecoder().decode(data),
        percentage,
        category: MessageCategory.Text,
        filename: "txt",
        extension: "",
        mimeType,
      };
    } else if (data) {
      return { message: data, percentage, category, filename, extension, mimeType };
    } else {
      return {
        message: "Invalid message",
        percentage: 100,
        category: MessageCategory.Text,
        filename: "txt",
        extension: "",
        mimeType,
      };
    }
  } catch (error) {
    console.error(error);

    return {
      message: "Inretrievable message",
      percentage: 100,
      category: MessageCategory.Text,
      filename: "txt",
      extension: "",
      mimeType: "text/plain"
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
