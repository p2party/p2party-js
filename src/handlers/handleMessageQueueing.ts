import { handleReceiveMessage } from "./handleReceiveMessage";

import { setDBRoomMessageData, closeReceiveFile } from "../db/api";

import { uint8ArrayToHex } from "../utils/uint8array";
import { compileChannelMessageLabel } from "../utils/channelLabel";

import {
  setMessage,
  setMessageAllChunks,
  incrementMessageStats,
} from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import signalingServerApi from "../api/signalingServerApi";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCDataChannel } from "../api/webrtc/interfaces";
import type { WebSocketMessageMessageSendRequest } from "../utils/interfaces";
import type { State } from "../store";

const k32 = (u8: Uint8Array) => {
  if (u8.byteLength < 32) {
    return `${String(u8.byteLength)}:${uint8ArrayToHex(u8)}`;
  }

  const head = new DataView(u8.buffer, u8.byteOffset, 16);
  const tail = new DataView(u8.buffer, u8.byteOffset + u8.byteLength - 16, 16);

  const h1 = head.getBigUint64(0, false).toString(16).padStart(16, "0");
  const h2 = head.getBigUint64(8, false).toString(16).padStart(16, "0");
  const t1 = tail.getBigUint64(0, false).toString(16).padStart(16, "0");
  const t2 = tail.getBigUint64(8, false).toString(16).padStart(16, "0");

  return h1 + h2 + t1 + t2;
};

const processingLocks = new Map<string, Promise<void>>();

const withProcessingLock = async <T>(
  key: string,
  fn: () => Promise<T>,
): Promise<T> => {
  const prev = processingLocks.get(key) ?? Promise.resolve();

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  processingLocks.set(
    key,
    prev.then(() => gate),
  );

  await prev;

  try {
    return await fn();
  } finally {
    release();

    if (processingLocks.get(key) === gate) {
      processingLocks.delete(key);
    }
  }
};

const processMessage = async (
  data: Uint8Array,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  merkleRoot: Uint8Array,
  extChannel: IRTCDataChannel | undefined,
  decrypted: Uint8Array | undefined,
  messageArray: Uint8Array | undefined,
  merkleRootArray: Uint8Array | undefined,
  senderPublicKeyArray: Uint8Array | undefined,
  receiverSecretKeyArray: Uint8Array | undefined,
  receiveMessageModule: LibCrypto,
): Promise<{ receivedFullSize: boolean }> => {
  if (
    decrypted &&
    messageArray &&
    merkleRootArray &&
    senderPublicKeyArray &&
    receiverSecretKeyArray
  ) {
    try {
      messageArray.set(data);
      merkleRootArray.set(merkleRoot);

      const {
        date,
        chunkSize,
        chunkIndex,
        receivedFullSize,
        chunkAlreadyExists,
        totalSize,
        messageType,
        filename,
        chunkHash,
        messageHash,
      } = await handleReceiveMessage(
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        receiveMessageModule,
      );

      const { signalingServer, keyPair } = api.getState() as State;

      if (
        totalSize > 0 &&
        chunkHash.length === crypto_hash_sha512_BYTES &&
        !chunkAlreadyExists
      ) {
        if (extChannel?.readyState === "open") {
          extChannel.send(chunkHash.buffer as ArrayBuffer);
        } else {
          const channel = await compileChannelMessageLabel(
            channelLabel,
            merkleRootHex,
          );

          if (signalingServer.isConnected) {
            await api.dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "message",
                  message: uint8ArrayToHex(chunkHash),
                  roomId,
                  fromPeerId: keyPair.peerId,
                  toPeerId: peerId,
                  label: channel,
                } as WebSocketMessageMessageSendRequest,
              }),
            );
          }
        }
      } else if (extChannel?.readyState === "open") {
        // Emit a uniform 64-byte receipt for every non-real frame (decoys,
        // already-stored, or crypto-failed) so the reverse receipt count equals
        // the forward frame count — a DTLS-record observer can no longer
        // subtract to recover the real chunk count. A fresh random token
        // matches no newChunk on the sender (handleReadReceipt is a no-op for
        // it) and is sent over the data channel only, to avoid junk relay
        // metadata.
        const decoyReceipt = new Uint8Array(crypto_hash_sha512_BYTES);
        crypto.getRandomValues(decoyReceipt);
        extChannel.send(decoyReceipt.buffer as ArrayBuffer);
      }

      const hashHex = uint8ArrayToHex(messageHash);

      if (receivedFullSize) {
        // Flush + close the OPFS write handle before flipping the UI to 100% so
        // readMessage can open the finished file without hitting the write lock.
        // No-op for text (no handle) and for a re-observed completion.
        await closeReceiveFile(merkleRootHex);

        await setDBRoomMessageData(
          roomId,
          merkleRootHex,
          hashHex,
          peerId,
          totalSize,
          totalSize,
          messageType,
          filename,
          channelLabel,
          date.getTime(),
        );

        api.dispatch(
          setMessageAllChunks({
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: peerId,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: date.getTime(),
            alsoSendFinishedMessage: true,
          }),
        );

        if (extChannel?.readyState === "open") {
          extChannel.send(messageHash.buffer as ArrayBuffer);
        } else {
          const channel = await compileChannelMessageLabel(
            channelLabel,
            merkleRootHex,
          );

          if (signalingServer.isConnected) {
            await api.dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "message",
                  message: uint8ArrayToHex(messageHash),
                  roomId,
                  fromPeerId: keyPair.peerId,
                  toPeerId: peerId,
                  label: channel,
                } as WebSocketMessageMessageSendRequest,
              }),
            );
          }
        }
      } else if (chunkSize > 0 && chunkIndex > -1 && !chunkAlreadyExists) {
        await setDBRoomMessageData(
          roomId,
          merkleRootHex,
          hashHex,
          peerId,
          chunkSize,
          totalSize,
          messageType,
          filename,
          channelLabel,
          date.getTime(),
        );

        api.dispatch(
          setMessage({
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: peerId,
            chunkSize,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: date.getTime(),
          }),
        );
      }

      // Telemetry: count every frame received (incl. decoys), flag the reals —
      // lets the UI show total ≫ real (the obfuscation working). Dispatched
      // AFTER the message is created above so the increment lands. Progress %
      // stays over the real message (savedSize / totalSize), unchanged.
      api.dispatch(
        incrementMessageStats({
          roomId,
          merkleRootHex,
          real: chunkSize > 0 && chunkIndex > -1 && !chunkAlreadyExists,
        }),
      );

      return { receivedFullSize };
    } catch (error) {
      console.error(error);

      return { receivedFullSize: false };
    }
  }

  return { receivedFullSize: false };
};

const drain = async (
  queue: Uint8Array[],
  seen: Set<string>,
  drainingRef: { value: boolean },
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  merkleRoot: Uint8Array,
  extChannel: IRTCDataChannel | undefined,
  decrypted: Uint8Array | undefined,
  messageArray: Uint8Array | undefined,
  merkleRootArray: Uint8Array | undefined,
  senderPublicKeyArray: Uint8Array | undefined,
  receiverSecretKeyArray: Uint8Array | undefined,
  receiveMessageModule: LibCrypto,
) => {
  if (drainingRef.value) return;
  drainingRef.value = true;
  const lockKey = `${roomId}:${peerId}`;
  try {
    for (;;) {
      const chunk = queue.pop();
      if (!chunk) break;

      // const { receivedFullSize } =
      await withProcessingLock(lockKey, async () =>
        processMessage(
          chunk,
          api,
          roomId,
          peerId,
          channelLabel,
          merkleRootHex,
          merkleRoot,
          extChannel,
          decrypted,
          messageArray,
          merkleRootArray,
          senderPublicKeyArray,
          receiverSecretKeyArray,
          receiveMessageModule,
        ),
      );

      // if (receivedFullSize) {
      //   queue = [];
      //   seen = new Set<string>();
      //
      //   break;
      // }
    }
  } finally {
    drainingRef.value = false;
    if (queue.length > 0)
      void drain(
        queue,
        seen,
        drainingRef,
        api,
        roomId,
        peerId,
        channelLabel,
        merkleRootHex,
        merkleRoot,
        extChannel,
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        receiveMessageModule,
      );
  }
};

export const enqueue = (
  data: Uint8Array,
  queue: Uint8Array[],
  seen: Set<string>,
  drainingRef: { value: boolean },
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  merkleRoot: Uint8Array,
  extChannel: IRTCDataChannel | undefined,
  decrypted: Uint8Array | undefined,
  messageArray: Uint8Array | undefined,
  merkleRootArray: Uint8Array | undefined,
  senderPublicKeyArray: Uint8Array | undefined,
  receiverSecretKeyArray: Uint8Array | undefined,
  receiveMessageModule: LibCrypto,
) => {
  const k = k32(data);
  if (seen.has(k)) return; // drop duplicate-in-queue
  seen.add(k);

  // Cap the seen set and queue to prevent unbounded memory growth
  const MAX_SEEN_SIZE = 100_000;
  const MAX_QUEUE_SIZE = 50_000;
  if (seen.size > MAX_SEEN_SIZE) seen.clear();
  if (queue.length > MAX_QUEUE_SIZE)
    queue.splice(0, queue.length - MAX_QUEUE_SIZE);

  queue.push(data);

  if (!drainingRef.value)
    void drain(
      queue,
      seen,
      drainingRef,
      api,
      roomId,
      peerId,
      channelLabel,
      merkleRootHex,
      merkleRoot,
      extChannel,
      decrypted,
      messageArray,
      merkleRootArray,
      senderPublicKeyArray,
      receiverSecretKeyArray,
      receiveMessageModule,
    );
};
