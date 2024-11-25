import { isUUID, isHexadecimal } from "class-validator";

import handleChallenge from "./handleChallenge";
import { handleSendMessageWebsocket } from "./handleSendMessageWebsocket";

import webrtcApi from "../api/webrtc";

import { setRoom, setPeer, setChannel } from "../reducers/roomSlice";
import { setChallengeId } from "../reducers/keyPairSlice";

import { hexToUint8Array } from "../utils/uint8array";
import {
  crypto_hash_sha512_BYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
} from "../cryptography/interfaces";

import libcrypto from "../cryptography/libcrypto";
import cryptoMemory from "../cryptography/memory";

import signalingServerApi from "../api/signalingServerApi";
import { handleReceiveMessage } from "./handleReceiveMessage";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateReceive,
  WebSocketMessagePeersResponse,
  WebSocketMessageSuccessfulChallenge,
  WebSocketMessageError,
  WebSocketMessagePingRequest,
  WebSocketMessagePeerConnectionResponse,
  WebSocketMessageMessageSendResponse,
} from "../utils/interfaces";

export const rtcDataChannelMessageLimit = 64 * 1024; // limit from RTCDataChannel is 64kb
export const messageLen =
  rtcDataChannelMessageLimit -
  crypto_hash_sha512_BYTES - // merkle root
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES - // nonce
  crypto_box_poly1305_AUTHTAGBYTES; // auth tag
export const encryptedLen =
  rtcDataChannelMessageLimit - crypto_hash_sha512_BYTES; // merkle root
const encryptionWasmMemory = cryptoMemory.encryptAsymmetricMemory(
  messageLen,
  crypto_hash_sha512_BYTES, // additional data is the merkle root
);

const decryptionWasmMemory = cryptoMemory.decryptAsymmetricMemory(
  64 * 1024,
  crypto_hash_sha512_BYTES, // additional data is the merkle root
);

const handleWebSocketMessage = async (
  event: MessageEvent,
  ws: WebSocket,
  api: BaseQueryApi,
) => {
  try {
    if (event.data === "PING") return ws.send("PONG");

    // console.log(event.data);

    const message:
      | WebSocketMessagePingRequest
      | WebSocketMessageChallengeRequest
      | WebSocketMessageRoomIdResponse
      | WebSocketMessageDescriptionReceive
      | WebSocketMessageCandidateReceive
      | WebSocketMessagePeersResponse
      | WebSocketMessageSuccessfulChallenge
      | WebSocketMessageError
      | WebSocketMessagePeerConnectionResponse
      | WebSocketMessageMessageSendResponse = JSON.parse(event.data);

    const { keyPair, room } = api.getState() as State;

    switch (message.type) {
      case "ping": {
        api.dispatch(
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
        const peerId = message.peerId ?? "";
        const challenge = message.challenge ?? "";

        const isNewPeerId =
          isUUID(peerId) &&
          isHexadecimal(challenge) &&
          challenge.length === 64 &&
          keyPair.challenge.length === 0 &&
          keyPair.signature.length === 0;

        const isNewDbEntry =
          isUUID(peerId) &&
          isUUID(keyPair.peerId) &&
          keyPair.peerId !== peerId &&
          isHexadecimal(challenge) &&
          challenge.length === 64;

        if (isNewPeerId || isNewDbEntry)
          await handleChallenge(keyPair, peerId, challenge, api);

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
        api.dispatch(setChallengeId(message.challengeId));

        break;
      }

      case "peers": {
        if (
          !isUUID(message.roomId) ||
          message.roomId !== room.id ||
          keyPair.publicKey.length === 0
        )
          break;

        const len = message.peers.length;
        if (len === 0) break;

        for (let i = 0; i < len; i++) {
          if (
            message.peers[i].publicKey === keyPair.publicKey ||
            message.peers[i].id === keyPair.peerId ||
            !isUUID(message.peers[i].id) ||
            message.peers[i].publicKey.length !== 64
          )
            continue;

          // api.dispatch(
          //   signalingServerApi.endpoints.connectWithPeer.initiate({
          //     roomId: message.roomId,
          //     peerId: message.peers[i].id,
          //     peerPublicKey: message.peers[i].publicKey,
          //   }),
          // );

          api.dispatch(
            webrtcApi.endpoints.connectWithPeer.initiate({
              roomId: message.roomId,
              peerId: message.peers[i].id,
              peerPublicKey: message.peers[i].publicKey,
              initiator: true,
              rtcConfig: room.rtcConfig,
            }),
          );
        }

        break;
      }

      case "description": {
        api.dispatch(
          webrtcApi.endpoints.setDescription.initiate({
            peerId: message.fromPeerId,
            peerPublicKey: message.fromPeerPublicKey,
            roomId: message.roomId,
            description: message.description,
          }),
        );

        break;
      }

      case "candidate": {
        api.dispatch(
          webrtcApi.endpoints.setCandidate.initiate({
            peerId: message.fromPeerId,
            // peerPublicKey: message.fromPeerPublicKey,
            // roomId: message.roomId,
            candidate: message.candidate,
          }),
        );

        break;
      }

      case "message": {
        const decryptionModule = await libcrypto({
          wasmMemory: decryptionWasmMemory,
        });

        const peerIndex = room.peers.findIndex(
          (p) => p.peerId === message.fromPeerId,
        );
        if (peerIndex === -1)
          throw new Error("Received a message from unknown peer");

        const peerPublicKeyHex = room.peers[peerIndex].peerPublicKey;
        const senderPublicKey = hexToUint8Array(peerPublicKeyHex);
        const receiverSecretKey = hexToUint8Array(keyPair.secretKey);
        const messageData = hexToUint8Array(message.message);

        await handleReceiveMessage(
          new Blob([messageData]), // hexToUint8Array(message.message),
          senderPublicKey,
          receiverSecretKey,
          decryptionModule,
          message.label,
          message.fromPeerId,
          api,
        );

        break;
      }

      case "connection": {
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
              peerId: message.fromPeerId,
              peerPublicKey: message.fromPeerPublicKey,
            }),
          );

          const encryptionModule = await libcrypto({
            wasmMemory: encryptionWasmMemory,
          });

          const CHANNELS_LEN = message.labels.length;
          for (let i = 0; i < CHANNELS_LEN; i++) {
            api.dispatch(
              setChannel({
                label: message.labels[i],
                peerId: message.fromPeerId,
              }),
            );

            const data = `Connected with ${keyPair.peerId} on channel ${message.labels[i]}`;
            await handleSendMessageWebsocket(
              data as string | File,
              encryptionModule,
              api,
              message.labels[i],
            );
          }
        }

        break;
      }

      case "error": {
        console.error(message);

        break;
      }

      default: {
        console.error("Unknown message type " + message);

        break;
      }
    }
  } catch (error) {
    return;
  }
};

export default handleWebSocketMessage;
