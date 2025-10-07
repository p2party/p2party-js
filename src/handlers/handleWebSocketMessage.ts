import { isUUID, isHexadecimal } from "class-validator";

import { handleChallenge } from "./handleChallenge";
import { handleReadReceipt } from "./handleReadReceipt";

import webrtcApi from "../api/webrtc";
import signalingServerApi from "../api/signalingServerApi";

import { setRoom, setPeer, setChannel } from "../reducers/roomSlice";
import { setChallengeId, setReconnectData } from "../reducers/keyPairSlice";

import cryptoMemory from "../cryptography/memory";
import { wasmLoader } from "../cryptography/wasmLoader";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateReceive,
  WebSocketMessagePeersResponse,
  WebSocketMessageConnectionRequest,
  WebSocketMessageSuccessfulChallenge,
  WebSocketMessageError,
  WebSocketMessagePingRequest,
  WebSocketMessagePeerConnectionResponse,
  WebSocketMessageMessageSendResponse,
  WSPeerConnection,
} from "../utils/interfaces";
import { getDBAddressBookEntry, getDBPeerIsBlacklisted } from "../db/api";
import { hexToUint8Array } from "../utils/uint8array";
import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../cryptography/interfaces";
import { DECRYPTED_LEN, MESSAGE_LEN } from "../utils/constants";
import { enqueue } from "./handleMessageQueueing";
import { decompileChannelMessageLabel } from "../utils/channelLabel";

const handleWebSocketMessage = async (
  event: MessageEvent,
  ws: WebSocket,
  api: BaseQueryApi,
  peerConnections: WSPeerConnection[],
) => {
  try {
    if (event.data === "PING") {
      ws.send("PONG");

      return;
    }

    // console.log(event.data);

    const message:
      | WebSocketMessagePingRequest
      | WebSocketMessageChallengeRequest
      | WebSocketMessageRoomIdResponse
      | WebSocketMessageDescriptionReceive
      | WebSocketMessageCandidateReceive
      | WebSocketMessagePeersResponse
      | WebSocketMessageConnectionRequest
      | WebSocketMessageSuccessfulChallenge
      | WebSocketMessageError
      | WebSocketMessagePeerConnectionResponse
      | WebSocketMessageMessageSendResponse = JSON.parse(event.data);

    switch (message.type) {
      case "ping": {
        const { keyPair } = api.getState() as State;

        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "pong",
              fromPeerId: keyPair.peerId,
            },
          }),
        );

        break;
      }

      case "peerId": {
        const { keyPair } = api.getState() as State;

        const peerId = message.peerId.length > 0 ? message.peerId : "";
        const challenge = message.challenge.length > 0 ? message.challenge : "";

        const isNewPeerId =
          isUUID(peerId) &&
          isHexadecimal(challenge) &&
          challenge.length === 64 &&
          keyPair.challenge.length === 0 &&
          keyPair.signature.length === 0 &&
          !message.challengeId &&
          !message.username &&
          !message.credential;

        const isNewDbEntry =
          isUUID(peerId) &&
          isUUID(keyPair.peerId) &&
          keyPair.peerId !== peerId &&
          isHexadecimal(challenge) &&
          challenge.length === 64 &&
          !message.challengeId &&
          !message.username &&
          !message.credential;

        if (isNewPeerId || isNewDbEntry) {
          await handleChallenge(keyPair, peerId, challenge, api);
        } else {
          api.dispatch(
            setReconnectData({
              peerId,
              challenge,
              signature: message.signature ?? "",
              challengeId: message.challengeId ?? "",
              username: message.username ?? "",
              credential: message.credential ?? "",
            }),
          );
        }

        break;
      }

      case "roomId": {
        api.dispatch(
          setRoom({
            id: message.roomId,
            url: message.roomUrl,
          }),
        );

        break;
      }

      case "challenge": {
        api.dispatch(setChallengeId(message));

        break;
      }

      case "peerConnection": {
        const blacklisted = await getDBPeerIsBlacklisted(
          message.peer.id,
          message.peer.publicKey,
        );

        if (blacklisted) break;

        const { keyPair, rooms } = api.getState() as State;

        const roomIndex = rooms.findIndex((r) => r.id === message.roomId);

        if (roomIndex > -1 && rooms[roomIndex].onlyConnectWithKnownAddresses) {
          const inAddressBook = await getDBAddressBookEntry(
            message.peer.id,
            message.peer.publicKey,
          );

          if (!inAddressBook) break;
        }

        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "peerConnection",
              roomId: message.roomId,
              fromPeerId: keyPair.peerId,
              toPeerId: message.peer.id,
            },
          }),
        );

        break;
      }

      case "peers": {
        const { keyPair, rooms, commonState } = api.getState() as State;

        const roomIndex =
          commonState.currentRoomUrl.length === 64
            ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
            : -1;

        if (roomIndex > -1) {
          const len = message.peers.length;
          if (len === 0) break;

          const canOnlyConnectToKnownPeers =
            rooms[roomIndex].onlyConnectWithKnownAddresses;

          for (let i = 0; i < len; i++) {
            if (
              message.peers[i].publicKey === keyPair.publicKey ||
              message.peers[i].id === keyPair.peerId ||
              !isUUID(message.peers[i].id) ||
              message.peers[i].publicKey.length !== 64
            )
              continue;

            const blacklisted = await getDBPeerIsBlacklisted(
              message.peers[i].id,
              message.peers[i].publicKey,
            );
            if (blacklisted) continue;

            if (canOnlyConnectToKnownPeers) {
              const p = await getDBAddressBookEntry(
                message.peers[i].id,
                message.peers[i].publicKey,
              );

              if (!p) continue;
            }

            await api.dispatch(
              webrtcApi.endpoints.connectWithPeer.initiate({
                roomId: message.roomId,
                peerId: message.peers[i].id,
                peerPublicKey: message.peers[i].publicKey,
                initiator: true,
                rtcConfig: rooms[roomIndex].rtcConfig,
              }),
            );
          }
        }

        break;
      }

      case "description": {
        const blacklisted = await getDBPeerIsBlacklisted(
          message.fromPeerId,
          message.fromPeerPublicKey,
        );

        if (!blacklisted) {
          const { rooms, commonState } = api.getState() as State;

          const roomIndex =
            commonState.currentRoomUrl.length === 64
              ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
              : -1;

          if (roomIndex > -1) {
            const canOnlyConnectToKnownPeers =
              rooms[roomIndex].onlyConnectWithKnownAddresses;

            if (canOnlyConnectToKnownPeers) {
              const p = await getDBAddressBookEntry(
                message.fromPeerId,
                message.fromPeerPublicKey,
              );

              if (!p) break;
            }
          }

          await api.dispatch(
            webrtcApi.endpoints.setDescription.initiate({
              peerId: message.fromPeerId,
              peerPublicKey: message.fromPeerPublicKey,
              roomId: message.roomId,
              description: message.description,
            }),
          );
        }

        break;
      }

      case "candidate": {
        const blacklisted = await getDBPeerIsBlacklisted(message.fromPeerId);

        if (!blacklisted) {
          const { rooms, commonState } = api.getState() as State;

          const roomIndex =
            commonState.currentRoomUrl.length === 64
              ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
              : -1;

          if (roomIndex > -1) {
            const canOnlyConnectToKnownPeers =
              rooms[roomIndex].onlyConnectWithKnownAddresses;

            if (canOnlyConnectToKnownPeers) {
              const p = await getDBAddressBookEntry(message.fromPeerId);

              if (!p) break;
            }
          }

          await api.dispatch(
            webrtcApi.endpoints.setCandidate.initiate({
              peerId: message.fromPeerId,
              candidate: message.candidate,
            }),
          );
        }

        break;
      }

      case "message": {
        const { rooms } = api.getState() as State;
        const roomIndex = rooms.findIndex((r) => r.id === message.roomId);

        const data = new Uint8Array(hexToUint8Array(message.message));

        if (roomIndex > -1 && data.length === crypto_hash_sha512_BYTES) {
          try {
            await handleReadReceipt(
              data,
              message.label,
              message.fromPeerId,
              rooms[roomIndex],
              api,
              // dataChannels,
            );
          } catch (error) {
            console.error(error);
          }

          break;
        }

        if (data.length === MESSAGE_LEN) {
          const peerIndex = peerConnections.findIndex(
            (p) => p.withPeerId === message.fromPeerId,
          );

          if (peerIndex === -1) break;

          const peerRoomIndex = peerConnections[peerIndex].rooms.findLastIndex(
            (r) => r.roomId === message.roomId,
          );
          if (peerRoomIndex === -1) break;

          const { channelLabel, merkleRoot, merkleRootHex } =
            await decompileChannelMessageLabel(message.label);

          if (
            merkleRoot.length === crypto_hash_sha512_BYTES &&
            peerConnections[peerIndex].rooms[peerRoomIndex].ptr3 &&
            peerConnections[peerIndex].rooms[peerRoomIndex].merkleRootArray
          ) {
            peerConnections[peerIndex].rooms[peerRoomIndex].merkleRootArray.set(
              merkleRoot,
            );

            void enqueue(
              data,
              peerConnections[peerIndex].rooms[peerRoomIndex].queue,
              peerConnections[peerIndex].rooms[peerRoomIndex].seen,
              peerConnections[peerIndex].rooms[peerRoomIndex].draining,
              api,
              peerConnections[peerIndex].rooms[peerRoomIndex].roomId,
              message.fromPeerId,
              channelLabel,
              merkleRootHex,
              undefined,
              peerConnections[peerIndex].rooms[peerRoomIndex].decrypted,
              peerConnections[peerIndex].rooms[peerRoomIndex].messageArray,
              peerConnections[peerIndex].rooms[peerRoomIndex].merkleRootArray,
              peerConnections[peerIndex].rooms[peerRoomIndex]
                .senderPublicKeyArray,
              peerConnections[peerIndex].rooms[peerRoomIndex]
                .receiverSecretKeyArray,
              peerConnections[peerIndex].rooms[peerRoomIndex]
                .receiveMessageModule,
            );
          }

          break;
        }

        console.error(
          new Error("Wrong data length received, " + String(data.length)),
        );

        break;
      }

      case "connection": {
        const { keyPair } = api.getState() as State;
        if (
          isUUID(keyPair.peerId) &&
          isHexadecimal(keyPair.challenge) &&
          isHexadecimal(keyPair.signature) &&
          // keyPair.signature.length === 1024 &&
          keyPair.signature.length === 128 &&
          keyPair.challenge.length === 64 &&
          isUUID(message.fromPeerId) &&
          message.fromPeerPublicKey.length === 64 &&
          isUUID(message.roomId)
        ) {
          api.dispatch(
            setPeer({
              roomId: message.roomId,
              peerId: message.fromPeerId,
              peerPublicKey: message.fromPeerPublicKey,
            }),
          );

          const CHANNELS_LEN = message.labels.length;
          for (let i = 0; i < CHANNELS_LEN; i++) {
            api.dispatch(
              setChannel({
                roomId: message.roomId,
                label: message.labels[i],
                peerId: message.fromPeerId,
              }),
            );

            console.log(
              `Connected with ${keyPair.peerId} on websocket channel ${message.labels[i]}`,
            );
          }

          const peerIndex = peerConnections.findIndex(
            (p) =>
              p.withPeerId === message.fromPeerId ||
              p.withPeerPublicKey === message.fromPeerPublicKey,
          );
          if (peerIndex === -1) {
            const wasmMemory = cryptoMemory.getReceiveMessageMemory();
            const receiveMessageModule = await wasmLoader(wasmMemory);

            const ptr1 = receiveMessageModule._malloc(DECRYPTED_LEN);
            const decrypted = new Uint8Array(
              receiveMessageModule.wasmMemory.buffer,
              ptr1,
              DECRYPTED_LEN,
            );

            const ptr2 = receiveMessageModule._malloc(MESSAGE_LEN);
            const messageArray = new Uint8Array(
              receiveMessageModule.wasmMemory.buffer,
              ptr2,
              MESSAGE_LEN,
            );

            const ptr3 = receiveMessageModule._malloc(crypto_hash_sha512_BYTES);
            const merkleRootArray = new Uint8Array(
              receiveMessageModule.wasmMemory.buffer,
              ptr3,
              crypto_hash_sha512_BYTES,
            );

            const senderPublicKey = hexToUint8Array(message.fromPeerPublicKey);
            const ptr4 = receiveMessageModule._malloc(
              crypto_sign_ed25519_PUBLICKEYBYTES,
            );
            const senderPublicKeyArray = new Uint8Array(
              receiveMessageModule.wasmMemory.buffer,
              ptr4,
              crypto_sign_ed25519_PUBLICKEYBYTES,
            );
            senderPublicKeyArray.set(senderPublicKey);

            const receiverSecretKey = hexToUint8Array(keyPair.secretKey);
            const ptr5 = receiveMessageModule._malloc(
              crypto_sign_ed25519_SECRETKEYBYTES,
            );
            const receiverSecretKeyArray = new Uint8Array(
              receiveMessageModule.wasmMemory.buffer,
              ptr5,
              crypto_sign_ed25519_SECRETKEYBYTES,
            );
            receiverSecretKeyArray.set(receiverSecretKey);

            peerConnections.push({
              withPeerId: message.fromPeerId,
              withPeerPublicKey: message.fromPeerPublicKey,
              rooms: [
                {
                  roomId: message.roomId,
                  receiveMessageModule,
                  queue: [] as Uint8Array[],
                  seen: new Set<string>(),
                  draining: false,
                  ptr1,
                  decrypted,
                  ptr2,
                  messageArray,
                  ptr3,
                  merkleRootArray,
                  ptr4,
                  senderPublicKeyArray,
                  ptr5,
                  receiverSecretKeyArray,
                },
              ],
            });
          } else {
            const peerRoomIndex = peerConnections[
              peerIndex
            ].rooms.findLastIndex((r) => r.roomId === message.roomId);
            if (peerRoomIndex === -1) {
              const wasmMemory = cryptoMemory.getReceiveMessageMemory();
              const receiveMessageModule = await wasmLoader(wasmMemory);

              const ptr1 = receiveMessageModule._malloc(DECRYPTED_LEN);
              const decrypted = new Uint8Array(
                receiveMessageModule.wasmMemory.buffer,
                ptr1,
                DECRYPTED_LEN,
              );

              const ptr2 = receiveMessageModule._malloc(MESSAGE_LEN);
              const messageArray = new Uint8Array(
                receiveMessageModule.wasmMemory.buffer,
                ptr2,
                MESSAGE_LEN,
              );

              const ptr3 = receiveMessageModule._malloc(
                crypto_hash_sha512_BYTES,
              );
              const merkleRootArray = new Uint8Array(
                receiveMessageModule.wasmMemory.buffer,
                ptr3,
                crypto_hash_sha512_BYTES,
              );

              const ptr4 = receiveMessageModule._malloc(
                crypto_sign_ed25519_PUBLICKEYBYTES,
              );
              const senderPublicKeyArray = new Uint8Array(
                receiveMessageModule.wasmMemory.buffer,
                ptr4,
                crypto_sign_ed25519_PUBLICKEYBYTES,
              );

              const ptr5 = receiveMessageModule._malloc(
                crypto_sign_ed25519_SECRETKEYBYTES,
              );
              const receiverSecretKeyArray = new Uint8Array(
                receiveMessageModule.wasmMemory.buffer,
                ptr5,
                crypto_sign_ed25519_SECRETKEYBYTES,
              );

              peerConnections[peerIndex].rooms.push({
                roomId: message.roomId,
                receiveMessageModule,
                queue: [] as Uint8Array[],
                seen: new Set<string>(),
                draining: false,
                ptr1,
                decrypted,
                ptr2,
                messageArray,
                ptr3,
                merkleRootArray,
                ptr4,
                senderPublicKeyArray,
                ptr5,
                receiverSecretKeyArray,
              });
            }
          }
        }

        break;
      }

      case "error": {
        console.error(message);

        break;
      }

      default: {
        console.error("Unknown message type " + JSON.stringify(message));

        break;
      }
    }
  } catch (error) {
    return;
  }
};

export default handleWebSocketMessage;
