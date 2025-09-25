import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { newKeyPair, sign, verify } from "./cryptography/ed25519";
import {
  encryptAsymmetric,
  decryptAsymmetric,
} from "./cryptography/chacha20poly1305";
import { generateMnemonic, keyPairFromMnemonic } from "./cryptography/mnemonic";
import { generateRandomRoomUrl } from "./cryptography/utils";
import { crypto_hash_sha512_BYTES } from "./cryptography/interfaces";

import {
  deleteDBAddressBookEntry,
  deleteDBPeerFromBlacklist,
  getAllDBAddressBookEntries,
  getAllDBBlacklisted,
  getAllDBUniqueRooms,
  getDBAddressBookEntry,
  getDBAllChunks,
  getDBPeerIsBlacklisted,
  getDBMessageData,
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
import { CANCEL_SEND } from "./utils/splitToChunks";
import { CHUNK_LEN, IMPORTANT_DATA_LEN } from "./utils/constants";

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
import { hexToUint8Array, uint8ArrayToHex } from "./utils/uint8array";

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

// const originalClose = RTCDataChannel.prototype.close;
// RTCDataChannel.prototype.close = function () {
//   console.trace("RTCDataChannel closed from:");
//   originalClose.apply(this);
// };

const connect = async (
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
      await dispatch(
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
    await dispatch(
      signalingServerApi.endpoints.connectWebSocket.initiate(
        signalingServerUrl,
      ),
    );
  }
};

const disconnectFromSignalingServer = async () => {
  await dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
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
          await dispatch(
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
const sendMessage = async (
  data: string | File,
  toChannel: string,
  roomId: string,
  percentageFilledChunk = 0.9,
  minChunks = 3,
  chunkSize = CHUNK_LEN,
  metadataSchemaVersion = 1,
) => {
  // dispatch(
  //   signalingServerApi.endpoints.sendMessageToPeer.initiate({
  //     data,
  //     // fromPeerId: keyPair.peerId,
  //     toChannel,
  //   }),
  // );

  await dispatch(
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
  hashHex?: string,
): Promise<{
  message: string | Blob;
  percentage: number;
  size: number;
  filename: string;
  mimeType: MimeType;
  extension: FileExtension;
  category: string;
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

    if (roomIndex > -1 && messageIndex > -1) {
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

      if (
        percentage === 100 &&
        rooms[roomIndex].messages[messageIndex].fromPeerId !== keyPair.peerId
      ) {
        const label = await compileChannelMessageLabel(
          rooms[roomIndex].messages[messageIndex].channelLabel,
          rooms[roomIndex].messages[messageIndex].merkleRootHex,
        );

        await store.dispatch(
          webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
            label,
            messageHash: hexToUint8Array(
              rooms[roomIndex].messages[messageIndex].sha512Hex,
            ),
            alsoDeleteData: false,
            alsoSendFinishedMessage: true,
          }),
        );
      }

      const chunks =
        percentage === 100
          ? await getDBAllChunks(
              rooms[roomIndex].messages[messageIndex].merkleRootHex,
              rooms[roomIndex].messages[messageIndex].sha512Hex,
            )
          : [];

      const dataChunks = chunks.map((c) => c.data);

      try {
        const data = new Blob(dataChunks, {
          type: mimeType,
        });

        if (messageType === MessageType.Text) {
          return {
            message:
              dataChunks.length > 0 ? await data.text() : "Incoming message...",
            percentage,
            size: rooms[roomIndex].messages[messageIndex].totalSize,
            filename: "",
            mimeType,
            extension,
            category,
          };
        } else {
          return {
            message: data,
            percentage,
            size: rooms[roomIndex].messages[messageIndex].totalSize,
            filename: rooms[roomIndex].messages[messageIndex].filename,
            mimeType,
            extension,
            category,
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
    } else {
      const msg = await getDBMessageData(merkleRootHex); // , hashHex);
      if (msg) {
        const messageType = msg.messageType;
        const mimeType = getMimeType(messageType);
        const extension = getFileExtension(messageType);
        const category = getMessageCategory(messageType);
        const percentage = Math.floor((msg.savedSize / msg.totalSize) * 100);

        if (percentage === 100 && msg.fromPeerId !== keyPair.peerId) {
          const label = await compileChannelMessageLabel(
            msg.channelLabel,
            msg.merkleRoot,
          );

          await store.dispatch(
            webrtcApi.endpoints.disconnectFromChannelLabel.initiate({
              label,
              messageHash: hexToUint8Array(msg.hash),
              alsoDeleteData: false,
              alsoSendFinishedMessage: true,
            }),
          );
        }

        const chunks =
          percentage === 100 ? await getDBAllChunks(msg.merkleRoot) : [];

        const dataChunks =
          chunks.length > 0
            ? chunks
                .sort((a, b) => a.chunkIndex - b.chunkIndex)
                .map((c) => c.data)
            : [new Uint8Array().buffer];

        try {
          const data = new Blob(dataChunks, {
            type: mimeType,
          });
          if (messageType === MessageType.Text) {
            return {
              message: await data.text(),
              percentage,
              size: msg.totalSize,
              filename: "",
              mimeType,
              extension,
              category,
            };
          } else {
            return {
              message: data,
              percentage,
              size: msg.totalSize,
              filename: msg.filename,
              mimeType,
              extension,
              category,
            };
          }
        } catch {
          return {
            message: "Invalid message",
            percentage: 0,
            size: msg.totalSize,
            filename: msg.filename,
            mimeType,
            extension,
            category,
          };
        }
      } else {
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
  merkleRoot: string | Uint8Array,
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

  const evt = new CustomEvent(CANCEL_SEND);
  window.dispatchEvent(evt);

  const merkleRootHex =
    merkleRoot && typeof merkleRoot === "string"
      ? merkleRoot
      : merkleRoot && typeof merkleRoot !== "string"
        ? uint8ArrayToHex(merkleRoot)
        : "";
  // const hashHex =
  //   hash && typeof hash === "string"
  //     ? hash
  //     : hash && typeof hash !== "string"
  //       ? uint8ArrayToHex(hash)
  //       : "";

  let roomIndex = -1;
  let messageIndex = -1;

  const { rooms } = store.getState();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    messageIndex = merkleRoot
      ? rooms[i].messages.findIndex((m) => m.merkleRootHex === merkleRootHex)
      : // : hash
        //   ? rooms[i].messages.findIndex((m) => m.sha512Hex === hashHex)
        -1;

    if (messageIndex > -1) {
      roomIndex = i;
      break;
    }
  }

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
        label,
        alsoDeleteData: true,
      }),
    );

    store.dispatch(
      deleteMessage({
        merkleRootHex: rooms[roomIndex].messages[messageIndex].merkleRootHex,
      }),
    );
  }
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

  const evt = new CustomEvent(CANCEL_SEND);
  window.dispatchEvent(evt);

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
        label,
        alsoDeleteData: true,
      }),
    );

    store.dispatch(
      deleteMessage({
        merkleRootHex: rooms[roomIndex].messages[messageIndex].merkleRootHex,
      }),
    );
  }
};

const purgeIdentity = async () => {
  dispatch(resetIdentity());

  const { rooms } = store.getState();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    await dispatch(
      webrtcApi.endpoints.disconnectFromRoom.initiate({ roomId: rooms[i].id }),
    );
  }
  await dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const purgeRoom = async (roomUrl: string) => {
  const { rooms } = store.getState();
  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
  if (roomIndex > -1) dispatch(deleteRoom(rooms[roomIndex].id));

  await dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());
};

const purge = async () => {
  dispatch(resetIdentity());
  await dispatch(signalingServerApi.endpoints.disconnectWebSocket.initiate());

  const rooms = await getAllDBUniqueRooms();
  const roomsLen = rooms.length;
  for (let i = 0; i < roomsLen; i++) {
    dispatch(deleteRoom(rooms[i].roomId));
  }
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
  cancelMessage,
  deleteMessage: deleteMsg,
  purgeIdentity,
  purgeRoom,
  purge,
  generateRandomRoomUrl: newRoomUrl,
  encrypt: encryptAsymmetric,
  decrypt: decryptAsymmetric,
  sign,
  verify,
  newKeyPair,
  generateMnemonic,
  keyPairFromMnemonic,
  MIN_CHUNKS: 3,
  MIN_CHUNK_SIZE: IMPORTANT_DATA_LEN + 1,
  MAX_CHUNK_SIZE: CHUNK_LEN,
  MIN_PERCENTAGE_FILLED_CHUNK: 0.1,
  MAX_PERCENTAGE_FILLED_CHUNK: 1,
  ROOM_URL_LENGTH: 64,
  MessageType,
  MessageCategory,
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

export default p2party;
