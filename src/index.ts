import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { generateRandomRoomUrl } from "./cryptography/utils";

import { getDBAllChunks } from "./utils/db";
import {
  getFileExtension,
  getMessageCategory,
  getMimeType,
} from "./utils/messageTypes";
import { concatUint8Arrays, hexToUint8Array } from "./utils/uint8array";

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
      // {
      //   urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
      // },
    ],
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

const readMessage = async (merkleRootHex: string) => {
  try {
    const chunks = await getDBAllChunks(merkleRootHex);

    const data = chunks
      .sort((a, b) => a.chunkIndex - b.chunkIndex)
      .map((c) => hexToUint8Array(c.data));

    return concatUint8Arrays(data);
  } catch (error) {
    console.error(error);

    return;
  }
};

const getMessageTypeInfo = (messageType: MessageType) => {
  const extension = getFileExtension(messageType);
  const mimeType = getMimeType(messageType);
  const category = getMessageCategory(messageType);

  return {
    extension,
    mimeType,
    category,
  };
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
  getMessageTypeInfo,
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
