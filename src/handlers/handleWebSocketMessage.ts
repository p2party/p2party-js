import { isUUID, isHexadecimal } from "class-validator";

import handleChallenge from "./handleChallenge";
import { handleSendMessageWebsocket } from "./handleSendMessageWebsocket";
// import { handleReceiveMessage } from "./handleReceiveMessage";

import webrtcApi from "../api/webrtc";
import signalingServerApi from "../api/signalingServerApi";

import { setRoom, setPeer, setChannel } from "../reducers/roomSlice";
import { setChallengeId, setReconnectData } from "../reducers/keyPairSlice";

// import { hexToUint8Array } from "../utils/uint8array";
// import { PROOF_LEN } from "../utils/splitToChunks";

import {
  crypto_hash_sha512_BYTES,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
} from "../cryptography/interfaces";

import libcrypto from "../cryptography/libcrypto";
import cryptoMemory from "../cryptography/memory";

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
} from "../utils/interfaces";
import { getDBAddressBookEntry, getDBPeerIsBlacklisted } from "../db/api";

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

// const decryptionWasmMemory = cryptoMemory.decryptAsymmetricMemory(
//   100 * 64 * 1024,
//   crypto_hash_sha512_BYTES, // additional data is the merkle root
// );
//
// const merkleWasmMemory = cryptoMemory.verifyMerkleProofMemory(PROOF_LEN);

const handleWebSocketMessage = async (
  event: MessageEvent,
  ws: WebSocket,
  api: BaseQueryApi,
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

            // api.dispatch(
            //   signalingServerApi.endpoints.connectWithPeer.initiate({
            //     roomId: message.roomId,
            //     peerId: message.peers[i].id,
            //     peerPublicKey: message.peers[i].publicKey,
            //   }),
            // );

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

        if (!blacklisted)
          await api.dispatch(
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
        const blacklisted = await getDBPeerIsBlacklisted(message.fromPeerId);

        if (!blacklisted)
          await api.dispatch(
            webrtcApi.endpoints.setCandidate.initiate({
              peerId: message.fromPeerId,
              candidate: message.candidate,
            }),
          );

        break;
      }

      // case "message": {
      //   const decryptionModule = await libcrypto({
      //     wasmMemory: decryptionWasmMemory,
      //   });
      //
      //   const merkleModule = await libcrypto({
      //     wasmMemory: merkleWasmMemory,
      //   });
      //
      //   const { keyPair, rooms, commonState } = api.getState() as State;
      //
      //   const roomIndex =
      //     commonState.currentRoomUrl.length === 64
      //       ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
      //       : -1;
      //
      //   if (roomIndex > -1) {
      //     const peerIndex = rooms[roomIndex].peers.findIndex(
      //       (p) => p.peerId === message.fromPeerId,
      //     );
      //     if (peerIndex === -1)
      //       throw new Error("Received a message from unknown peer");
      //
      //     const peerPublicKeyHex =
      //       rooms[roomIndex].peers[peerIndex].peerPublicKey;
      //     const senderPublicKey = hexToUint8Array(peerPublicKeyHex);
      //     const receiverSecretKey = hexToUint8Array(keyPair.secretKey);
      //     const messageData = hexToUint8Array(message.message);
      //
      //     await handleReceiveMessage(
      //       messageData.buffer, // new Blob([messageData]), //
      //       new Uint8Array(),
      //       senderPublicKey,
      //       receiverSecretKey,
      //       rooms[roomIndex],
      //       decryptionModule,
      //       merkleModule,
      //       // message.label,
      //       // message.fromPeerId,
      //       // api,
      //     );
      //   }
      //
      //   break;
      // }

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

          const encryptionModule = await libcrypto({
            wasmMemory: encryptionWasmMemory,
          });

          const CHANNELS_LEN = message.labels.length;
          for (let i = 0; i < CHANNELS_LEN; i++) {
            api.dispatch(
              setChannel({
                roomId: message.roomId,
                label: message.labels[i],
                peerId: message.fromPeerId,
              }),
            );

            const data = `Connected with ${keyPair.peerId} on channel ${message.labels[i]}`;
            await handleSendMessageWebsocket(
              data as string | File,
              message.roomId,
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
        console.error("Unknown message type " + JSON.stringify(message));

        break;
      }
    }
  } catch (error) {
    return;
  }
};

export default handleWebSocketMessage;
