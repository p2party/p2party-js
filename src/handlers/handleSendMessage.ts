import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";
import { newKeyPair, sign } from "../cryptography/ed25519";

import {
  concatUint8Arrays,
  hexToUint8Array,
  // uint8ArrayToHex,
} from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { setDBSendQueue } from "../db/api";

import { handleOpenChannel, MAX_BUFFERED_AMOUNT } from "./handleOpenChannel";
import { compileChannelMessageLabel } from "../utils/channelLabel";

// import { deleteMessage } from "../reducers/roomSlice";

import { CHUNK_LEN } from "../utils/splitToChunks";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

export const wait = (milliseconds: number) => {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
};

const createChannelAndSendChunks = async (
  channelMessageLabel: string,
  senderSecretKey: Uint8Array,
  unencryptedChunks: Uint8Array[],
  merkleRoot: Uint8Array,
  epc: IRTCPeerConnection,
  api: BaseQueryApi,
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
) => {
  let putItemInDBSendQueue = false;
  const chunksLen = unencryptedChunks.length;
  // const merkleRootHex = uint8ArrayToHex(merkleRoot);
  const channel = await handleOpenChannel(
    {
      channel: channelMessageLabel,
      epc,
      dataChannels,
      decryptionModule,
      merkleModule,
    },
    api,
  );

  const peerPublicKeyHex = epc.withPeerPublicKey;
  const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);

  const indexes = Array.from({ length: chunksLen }, (_, i) => i);
  const indexesRandomized = await fisherYatesShuffle(indexes);
  for (let j = 0; j < chunksLen; j++) {
    const jRandom = indexesRandomized[j];

    const senderEphemeralKey = await newKeyPair(encryptionModule);
    const ephemeralSignature = await sign(
      senderEphemeralKey.publicKey,
      senderSecretKey,
      encryptionModule,
    );

    const encryptedMessage = await encryptAsymmetric(
      unencryptedChunks[jRandom],
      receiverPublicKey,
      senderEphemeralKey.secretKey, // senderSecretKey,
      merkleRoot,
      encryptionModule,
    );

    const message = (await concatUint8Arrays([
      senderEphemeralKey.publicKey,
      ephemeralSignature,
      encryptedMessage,
    ])) as Uint8Array<ArrayBuffer>;

    const timeoutMilliseconds = await randomNumberInRange(1, 10);
    await wait(timeoutMilliseconds);
    if (
      channel.readyState === "open" &&
      channel.bufferedAmount < MAX_BUFFERED_AMOUNT
    ) {
      channel.send(message.buffer);
    } else if (
      // channel.readyState !== "closing" &&
      channel.readyState !== "closed"
    ) {
      putItemInDBSendQueue = true;
      await setDBSendQueue({
        position: jRandom,
        label: channel.label,
        toPeerId: channel.withPeerId,
        encryptedData: message.buffer, // new Blob([message]),
      });
    }
  }

  if (!putItemInDBSendQueue) channel.close();
};

export const handleSendMessage = async (
  data: string | File,
  api: BaseQueryApi,
  label: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  minChunks = 3, // TODO errors when =2 due to merkle
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
) => {
  try {
    const { room, keyPair } = api.getState() as State;
    const senderSecretKey = hexToUint8Array(keyPair.secretKey);

    const channelIndex = room.channels.findIndex((c) => c.label === label);
    if (channelIndex === -1) throw new Error("No channel with label " + label);

    const { merkleRoot, merkleRootHex, hashHex, unencryptedChunks } =
      await splitToChunks(
        data,
        api,
        label,
        minChunks,
        chunkSize,
        percentageFilledChunk,
        metadataSchemaVersion,
      );

    const channelMessageLabel = await compileChannelMessageLabel(
      label,
      merkleRootHex,
      hashHex,
    );

    const PEERS_LEN = room.channels[channelIndex].peerIds.length;
    const promises: Promise<void>[] = [];
    for (let i = 0; i < PEERS_LEN; i++) {
      const peerIndex = peerConnections.findIndex(
        (p) => p.withPeerId === room.channels[channelIndex].peerIds[i],
      );
      if (peerIndex === -1) continue;

      promises.push(
        createChannelAndSendChunks(
          channelMessageLabel,
          senderSecretKey,
          unencryptedChunks,
          merkleRoot,
          peerConnections[peerIndex],
          api,
          dataChannels,
          encryptionModule,
          decryptionModule,
          merkleModule,
        ),
      );
    }

    await Promise.allSettled(promises);
  } catch (error) {
    console.error(error);
  }
};
