import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { generateRandomRoomUrl } from "./cryptography/utils";

import {
  deleteDBAddressBookEntry,
  deleteDBPeerFromBlacklist,
  getAllDBAddressBookEntries,
  getAllDBBlacklisted,
  getAllDBUniqueRooms,
  getDBAddressBookEntry,
  getDBAllChunks,
  getDBPeerIsBlacklisted,
  setDBAddressBookEntry,
  setDBPeerInBlacklist,
} from "./db/api";
import {
  getFileExtension,
  getMessageCategory,
  getMimeType,
} from "./utils/messageTypes";
import { CHUNK_LEN, IMPORTANT_DATA_LEN } from "./utils/splitToChunks";

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import { commonStateSelector } from "./reducers/commonSlice";
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
import { setCurrentRoomUrl } from "./reducers/commonSlice";

import { compileChannelMessageLabel } from "./utils/channelLabel";
import { uint8ArrayToHex } from "./utils/uint8array";
import { crypto_hash_sha512_BYTES } from "./cryptography/interfaces";

import type { State } from "./store";
import type { Room, Peer, Channel, Message } from "./reducers/roomSlice";
import type { SignalingState } from "./reducers/signalingServerSlice";
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
import type { BlacklistedPeer, UsernamedPeer, UniqueRoom } from "./db/types";

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
  if (roomUrl.length !== 64) throw new Error("Invalid room url length");

  const { keyPair, signalingServer, rooms, commonState } = store.getState();

  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex === -1) dispatch(setRoom({ url: roomUrl, id: "", rtcConfig }));

  if (commonState.currentRoomUrl !== roomUrl)
    dispatch(setCurrentRoomUrl(roomUrl));

  if (signalingServer.isConnected && isUUID(keyPair.peerId)) {
    if (roomIndex === -1) {
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
      dispatch(
        setConnectingToPeers({
          roomId: rooms[roomIndex].id,
          connectingToPeers: true,
        }),
      );
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
  roomUrl: string,
  signalingServerUrl = "wss://signaling.p2party.com/ws",
  // signalingServerUrl = "ws://localhost:3001/ws",
) => {
  if (roomUrl.length !== 64) throw new Error("Invalid room url length");

  const { signalingServer, rooms, commonState } = store.getState();

  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex === -1) dispatch(setRoom({ url: roomUrl, id: "" }));

  if (commonState.currentRoomUrl !== roomUrl)
    dispatch(setCurrentRoomUrl(roomUrl));

  if (
    signalingServer.serverUrl !== signalingServerUrl ||
    (!signalingServer.isConnected && !signalingServer.isEstablishingConnection)
  ) {
    dispatch(
      signalingServerApi.endpoints.connectWebSocket.initiate(
        signalingServerUrl,
      ),
    );
  }
};

const disconnectFromSignalingServer = () => {
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const disconnectFromPeer = (peerId: string) => {
  dispatch(webrtcApi.endpoints.disconnectFromPeer.initiate({ peerId }));
};

const disconnectFromRoom = (roomId: string, deleteMessages = false) => {
  dispatch(
    webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId, deleteMessages }),
  );
};

const disconnectFromAllRooms = (
  deleteMessages = false,
  exceptionRoomIds: string[] = [],
) => {
  dispatch(
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
  if (roomUrl.length === 64) {
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
          dispatch(
            webrtcApi.endpoints.disconnectFromPeer.initiate({
              peerId: rooms[roomIndex].peers[i].peerId,
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
  }
};

const deletePeerFromAddressBook = async (
  username?: string,
  peerId?: string,
  peerPublicKey?: string,
) => {
  const pId = await deleteDBAddressBookEntry(username, peerId, peerPublicKey);
  if (isUUID(pId)) {
    dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({
        peerId: pId,
        alsoDeleteData: false,
      }),
    );
  }
};

const blacklistPeer = async (peerId: string, peerPublicKey: string) => {
  await setDBPeerInBlacklist(peerId, peerPublicKey);
  dispatch(
    webrtcApi.endpoints.disconnectFromPeer.initiate({
      peerId,
      alsoDeleteData: true,
    }),
  );
};

const openChannel = async (
  roomId: string,
  label: string,
  withPeers?: { peerId: string; peerPublicKey: string }[],
) => {
  dispatch(
    webrtcApi.endpoints.openChannel.initiate({
      roomId,
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
  roomId: string,
  minChunks = 3,
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
      roomId,
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
    const { rooms } = store.getState();
    const roomsLen = rooms.length;
    let index = -1;
    for (let i = 0; i < roomsLen; i++) {
      const messageIndex = rooms[i].messages.findIndex(
        (m) => m.merkleRootHex === merkleRootHex,
      );
      if (messageIndex > -1) {
        index = i;
        break;
      }
    }

    if (index > -1) {
      const messageIndex = rooms[index].messages.findIndex(
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

      const messageType = rooms[index].messages[messageIndex].messageType;
      const mimeType = getMimeType(messageType);
      const extension = getFileExtension(messageType);
      const category = getMessageCategory(messageType);

      const percentage = Math.floor(
        (rooms[index].messages[messageIndex].savedSize /
          rooms[index].messages[messageIndex].totalSize) *
          100,
      );

      if (percentage === 100) {
        const label = await compileChannelMessageLabel(
          rooms[index].messages[messageIndex].channelLabel,
          rooms[index].messages[messageIndex].merkleRootHex,
          rooms[index].messages[messageIndex].sha512Hex,
        );

        await store.dispatch(
          webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
            label,
            alsoDeleteData: false,
          }),
        );
      }

      const root = rooms[index].messages[messageIndex].merkleRootHex;
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
          ? chunks
              .sort((a, b) => a.chunkIndex - b.chunkIndex)
              .map((c) => c.data)
          : [new Uint8Array().buffer];
      const data = new Blob(dataChunks, {
        type: mimeType,
      });

      if (messageType === MessageType.Text) {
        return {
          message: await data.text(),
          percentage,
          size: rooms[index].messages[messageIndex].totalSize,
          filename: "",
          mimeType,
          extension,
          category,
        };
      } else if (data) {
        return {
          message: data,
          percentage,
          size: rooms[index].messages[messageIndex].totalSize,
          filename: rooms[index].messages[messageIndex].filename,
          mimeType,
          extension,
          category,
        };
      } else {
        return {
          message: "Invalid message",
          percentage: 0,
          size: rooms[index].messages[messageIndex].totalSize,
          filename: rooms[index].messages[messageIndex].filename,
          mimeType,
          extension,
          category,
        };
      }
    } else {
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

  let roomIndex = -1;
  let messageIndex = -1;

  const { rooms } = store.getState();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    messageIndex = merkleRoot
      ? rooms[i].messages.findIndex((m) => m.merkleRootHex === merkleRootHex)
      : hash
        ? rooms[i].messages.findIndex((m) => m.sha512Hex === hashHex)
        : -1;

    if (messageIndex > -1) {
      roomIndex = i;
      break;
    }
  }

  if (roomIndex === -1 || messageIndex === -1) return;

  const label = await compileChannelMessageLabel(
    channelLabel,
    rooms[roomIndex].messages[messageIndex].merkleRootHex,
    rooms[roomIndex].messages[messageIndex].sha512Hex,
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

  let roomIndex = -1;
  let messageIndex = -1;

  const { rooms } = store.getState();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    messageIndex = merkleRoot
      ? rooms[i].messages.findIndex((m) => m.merkleRootHex === merkleRootHex)
      : hash
        ? rooms[i].messages.findIndex((m) => m.sha512Hex === hashHex)
        : -1;

    if (messageIndex > -1) {
      roomIndex = i;
      break;
    }
  }

  if (roomIndex === -1 || messageIndex === -1) return;

  const label = await compileChannelMessageLabel(
    rooms[roomIndex].messages[messageIndex].channelLabel,
    rooms[roomIndex].messages[messageIndex].merkleRootHex,
    rooms[roomIndex].messages[messageIndex].sha512Hex,
  );

  store.dispatch(
    webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
      label,
      alsoDeleteData: true,
    }),
  );

  dispatch(
    deleteMessage({
      merkleRootHex: rooms[roomIndex].messages[messageIndex].merkleRootHex,
    }),
  );
};

const purgeIdentity = () => {
  dispatch(resetIdentity());

  const { rooms } = store.getState() as State;
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    dispatch(
      webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId: rooms[i].id }),
    );
  }
  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const purgeRoom = (roomUrl: string) => {
  const { rooms } = store.getState() as State;
  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex > -1) dispatch(deleteRoom(rooms[roomIndex].id));

  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const purge = () => {
  dispatch(resetIdentity());

  const { rooms } = store.getState() as State;
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    dispatch(deleteRoom(rooms[i].id));
  }

  dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const newRoomUrl = async () => {
  const randomString = await generateRandomRoomUrl(256);
  const random = new TextEncoder().encode(randomString);
  const firstHashArray = await window.crypto.subtle.digest("SHA-512", random);
  const secondHashArray = await window.crypto.subtle.digest(
    "SHA-256",
    firstHashArray,
  );
  const hash = new Uint8Array(secondHashArray);

  return uint8ArrayToHex(hash);
};

export default {
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
  openChannel,
  sendMessage,
  readMessage,
  cancelMessage,
  deleteMessage: deleteMsg,
  purgeIdentity,
  purgeRoom,
  purge,
  generateRandomRoomUrl: newRoomUrl,
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
  UsernamedPeer,
  BlacklistedPeer,
  UniqueRoom,
  SignalingState,
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
