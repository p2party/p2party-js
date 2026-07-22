import { handleOpenChannel } from "./handleOpenChannel";

import signalingServerApi from "../api/signalingServerApi";

import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";
import { getMerkleProof } from "../cryptography/merkle";
import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../cryptography/interfaces";

import {
  concatUint8Arrays,
  hexToUint8Array,
  uint8ArrayToHex,
} from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import { getMimeType } from "../utils/messageTypes";
import {
  compileChannelMessageLabel,
  decompileChannelMessageLabel,
} from "../utils/channelLabel";
import { allocateSendMessage } from "../utils/allocators";
import { zeroFree } from "../utils/zeroFree";
import { waitForOpen } from "../utils/waitForOpen";
import { incrementMessageStats } from "../reducers/roomSlice";
import { clearTransfer, waitForCompletion, getAckedChunks } from "./reconcile";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  MAX_BUFFERED_AMOUNT,
  PROOF_LEN,
  CHUNK_AUTH_DOMAIN_BYTES,
  CHUNK_AUTH_TRANSCRIPT_LEN,
  MAX_RETRANSMITS,
  RETRANSMIT_TIMEOUT_MS,
  RECONNECT_RESUME_TIMEOUT_MS,
  RECONNECT_RESUME_POLL_MS,
  MAX_RESUME_ATTEMPTS,
} from "../utils/constants";

import {
  deleteDBNewChunk,
  deleteDBSendQueue,
  getDBNewChunk,
  getDBSendQueue,
  setDBChunk,
  setDBNewChunk,
  setDBSendQueue,
} from "../db/api";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { WebSocketMessageMessageSendRequest } from "../utils/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

// export const wait = (milliseconds: number) => {
//   return new Promise((resolve) => {
//     setTimeout(resolve, milliseconds);
//   });
// };

const sendChunks = async (
  channel: IRTCDataChannel | string,
  api: BaseQueryApi,
  roomId: string,
  senderSecretKey: Uint8Array,
  chunksLen: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  hashHex: string,
  // epc: IRTCPeerConnection,
  peerId: string,
  peerPublicKeyHex: string,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  // When set (reconcile: selective retransmit / resume), resend ONLY the un-acked
  // real chunks — skip decoys and already-acked reals.
  reconcileAcked?: Set<number>,
) => {
  let putItemInDBSendQueue = false;

  const { keyPair } = api.getState() as State;

  const { channelLabel, merkleRootHex } = await decompileChannelMessageLabel(
    typeof channel === "string" ? channel : channel.label,
  );

  const indexes = Array.from({ length: chunksLen }, (_, i) => i);
  const indexesRandomized = fisherYatesShuffle(indexes);

  const {
    ptr1,
    ptr5,
    ptr6,
    ptr7,
    ptr9,
    ptr10,
    ptrTranscript,
    senderEphemeralPublicKey,
    senderEphemeralSecretKey,
    seedBytes,
    senderEphemeralSignature,
    chunkArray,
    receiverPublicKeyArray,
    nonceArray,
    encryptedArray,
    authTranscript,
  } = allocateSendMessage(encryptionModule);

  // const peerPublicKeyHex = epc.withPeerPublicKey;
  // const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);
  receiverPublicKeyArray.set(hexToUint8Array(peerPublicKeyHex));

  // Constant parts of the per-chunk sender-auth transcript
  // (DOMAIN || merkle_root || ephemeral_pk); the ephemeral pk is filled per
  // chunk below, then the whole transcript is signed.
  authTranscript.set(CHUNK_AUTH_DOMAIN_BYTES, 0);
  authTranscript.set(merkleRoot, CHUNK_AUTH_DOMAIN_BYTES.length);

  for (let i = 0; i < chunksLen; i++) {
    const iRandom = indexesRandomized[i];

    window.crypto.getRandomValues(seedBytes);

    const newKeyPairResult = encryptionModule._keypair_from_seed(
      senderEphemeralPublicKey.byteOffset,
      senderEphemeralSecretKey.byteOffset,
      seedBytes.byteOffset,
    );

    if (newKeyPairResult !== 0) continue;

    // Bind the signature to the domain-separated transcript, not the bare
    // ephemeral pk, so a challenge-oracle signature cannot forge a chunk.
    authTranscript.set(
      senderEphemeralPublicKey,
      CHUNK_AUTH_DOMAIN_BYTES.length + merkleRoot.length,
    );

    const sigResult = encryptionModule._sign(
      CHUNK_AUTH_TRANSCRIPT_LEN,
      ptrTranscript,
      senderSecretKey.byteOffset,
      senderEphemeralSignature.byteOffset,
    );

    if (sigResult !== 0) continue;

    const unencryptedChunk = await getDBNewChunk(hashHex, iRandom);
    if (!unencryptedChunk) continue;

    const metadataArray = new Uint8Array(unencryptedChunk.metadata);
    const metadata = deserializeMetadata(metadataArray);

    // Reconcile: resend only un-acked REAL chunks. Real-vs-decoy is read from
    // the chunk's own metadata (SSOT) — a decoy has chunkEnd − chunkStart >
    // totalSize. Decoys are cover and never resent; acked reals are skipped.
    if (reconcileAcked !== undefined) {
      const isReal =
        metadata.chunkEndIndex > metadata.chunkStartIndex &&
        metadata.chunkEndIndex - metadata.chunkStartIndex <= metadata.totalSize;
      if (!isReal || reconcileAcked.has(metadata.chunkIndex)) continue;
    }

    if (
      metadata.chunkStartIndex >= 0 &&
      metadata.chunkEndIndex > metadata.chunkStartIndex &&
      metadata.chunkEndIndex - metadata.chunkStartIndex <= metadata.totalSize
    ) {
      const mimeType = getMimeType(metadata.messageType);
      const realChunk = unencryptedChunk.data.slice(
        metadata.chunkStartIndex,
        metadata.chunkEndIndex,
      );
      try {
        await setDBChunk({
          merkleRoot: merkleRootHex,
          hash: hashHex,
          chunkIndex: metadata.chunkIndex,
          data: realChunk,
          mimeType,
        });
      } catch {
        /* ignore */
      }
    }

    const merkleProof = new Uint8Array(PROOF_LEN);
    if (unencryptedChunk.merkleProof.byteLength === 0) {
      const m = await getMerkleProof(
        chunkHashes,
        hexToUint8Array(unencryptedChunk.realChunkHash),
        merkleModule,
        PROOF_LEN,
      );

      merkleProof.set(m);

      try {
        await setDBNewChunk({
          hash: hashHex,
          merkleRoot: merkleRootHex,
          realChunkHash: unencryptedChunk.realChunkHash,
          chunkIndex: iRandom,
          data: unencryptedChunk.data,
          metadata: unencryptedChunk.metadata,
          merkleProof: merkleProof.buffer,
        });
      } catch (error) {
        console.warn(error);
      }
    } else {
      merkleProof.set(new Uint8Array(unencryptedChunk.merkleProof));

      if (unencryptedChunk.merkleRoot.length === 0) {
        try {
          await setDBNewChunk({
            hash: hashHex,
            merkleRoot: merkleRootHex,
            realChunkHash: unencryptedChunk.realChunkHash,
            chunkIndex: iRandom,
            data: unencryptedChunk.data,
            metadata: unencryptedChunk.metadata,
            merkleProof: unencryptedChunk.merkleProof,
          });
        } catch (error) {
          console.warn(error);
        }
      }
    }

    if (
      DECRYPTED_LEN !==
      metadataArray.length +
        merkleProof.length +
        new Uint8Array(unencryptedChunk.data).length
    )
      continue;

    const chunk = await concatUint8Arrays([
      metadataArray,
      merkleProof,
      new Uint8Array(unencryptedChunk.data),
    ]);
    chunkArray.set(chunk);

    window.crypto.getRandomValues(nonceArray);

    const encResult = encryptionModule._encrypt_chachapoly_asymmetric(
      DECRYPTED_LEN,
      chunkArray.byteOffset,
      receiverPublicKeyArray.byteOffset,
      senderEphemeralSecretKey.byteOffset,
      nonceArray.byteOffset,
      crypto_hash_sha512_BYTES,
      merkleRoot.byteOffset,
      encryptedArray.byteOffset,
    );

    if (encResult !== 0) continue;

    const message = await concatUint8Arrays([
      senderEphemeralPublicKey,
      senderEphemeralSignature,
      encryptedArray,
    ]);

    if (
      typeof channel === "string" ||
      channel.readyState !== "open" ||
      channel.bufferedAmount >= MAX_BUFFERED_AMOUNT
    ) {
      await api.dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "message",
            message: uint8ArrayToHex(message),
            roomId,
            fromPeerId: keyPair.peerId,
            // toPeerId: epc.withPeerId,
            toPeerId: peerId,
            label: typeof channel === "string" ? channel : channel.label,
          } as WebSocketMessageMessageSendRequest,
        }),
      );
    } else if (
      (channel.readyState as string) === "open" &&
      channel.bufferedAmount < MAX_BUFFERED_AMOUNT
    ) {
      channel.send(message.buffer as ArrayBuffer);
    } else if (channel.bufferedAmount > MAX_BUFFERED_AMOUNT) {
      putItemInDBSendQueue = true;

      try {
        await setDBSendQueue({
          position: iRandom,
          label: channel.label,
          toPeerId: channel.withPeerId,
          encryptedData: message.buffer as ArrayBuffer,
        });
      } catch (error) {
        console.error(error);
      }
    } else {
      console.log(
        "Cannot send message because channel is " +
          channel.readyState +
          " and bufferedAmount is " +
          String(channel.bufferedAmount),
      );

      break;
    }
  }

  if (putItemInDBSendQueue) {
    if (typeof channel === "string") {
      const sendQueue = await getDBSendQueue(channel, peerId); // epc.withPeerId);
      while (sendQueue.length > 0) {
        let pos = await randomNumberInRange(0, sendQueue.length);
        if (pos === sendQueue.length) pos = 0;

        const [item] = sendQueue.splice(pos, 1);

        await api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "message",
              message: uint8ArrayToHex(new Uint8Array(item.encryptedData)),
              roomId,
              fromPeerId: keyPair.peerId,
              // toPeerId: epc.withPeerId,
              toPeerId: peerId,
              label: channelLabel,
            } as WebSocketMessageMessageSendRequest,
          }),
        );

        try {
          await deleteDBSendQueue(channel, peerId, item.position);
        } catch (error) {
          console.error(error);
        }
      }
    } else {
      while (
        channel.readyState === "open" &&
        channel.bufferedAmount < MAX_BUFFERED_AMOUNT
      ) {
        const sendQueue = await getDBSendQueue(channel.label, peerId); // epc.withPeerId);
        while (
          sendQueue.length > 0 &&
          channel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
          (channel.readyState as string) === "open"
        ) {
          let pos = await randomNumberInRange(0, sendQueue.length);
          if (pos === sendQueue.length) pos = 0;

          const [item] = sendQueue.splice(pos, 1);
          if ((channel.readyState as string) === "open") {
            channel.send(item.encryptedData);

            try {
              await deleteDBSendQueue(
                channel.label,
                // epc.withPeerId,
                peerId,
                item.position,
              );
            } catch (error) {
              console.error(error);
            }
          }
        }
      }
    }
  }

  encryptionModule._free(ptr1);
  zeroFree(encryptionModule, senderEphemeralSecretKey);
  zeroFree(encryptionModule, seedBytes);
  encryptionModule._free(ptr5);
  encryptionModule._free(ptr6);
  encryptionModule._free(ptr7);
  encryptionModule._free(ptr9);
  encryptionModule._free(ptr10);
  encryptionModule._free(ptrTranscript);
};

// Resume-on-reconnect: a FULL peer reconnect (new RTCPeerConnection) destroys the
// per-message channel — only "main" is auto-reopened, and frames buffered in the
// dead channel were lost and never relayed. Wait (bounded) for the peer's fresh
// connection, re-open the SAME Merkle-root-labeled channel on it, and return it
// so the reconcile loop continues. The label is a pure function of the message,
// so it is byte-identical across the reconnect; the receiver re-emits its stored
// receipts on the new channel's onopen, letting the sender resend only the reals
// still missing. Returns null if the peer does not come back in time.
const resumeChannel = async (
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelMessageLabel: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  timeoutMs: number,
): Promise<IRTCDataChannel | null> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const epc = peerConnections.find(
      (p) => p.withPeerId === peerId && p.connectionState === "connected",
    );
    if (!epc) {
      await new Promise((resolve) =>
        setTimeout(resolve, RECONNECT_RESUME_POLL_MS),
      );
      continue;
    }
    try {
      const ch = await handleOpenChannel(
        { channel: channelMessageLabel, epc, roomId, dataChannels },
        api,
      );
      // Await opening for the REMAINING budget rather than a fixed window, so a
      // slow-to-open channel is waited on — NOT re-created, which would spawn a
      // duplicate same-label channel that leaks receive buffers and blocks the
      // newChunks cleanup. If it still hasn't opened (timed out, or the pc died
      // again mid-open), neutralize it so it can never later open, push into
      // dataChannels, or malloc receive buffers, then look for a fresh epc.
      if (await waitForOpen(ch, deadline - Date.now())) return ch;
      try {
        ch.onopen = null;
        ch.onclose = null;
        ch.onerror = null;
        ch.onmessage = null;
        ch.onbufferedamountlow = null;
        if (ch.readyState !== "closed") ch.close();
      } catch (error) {
        console.error(error);
      }
    } catch (error) {
      console.error(error);
    }
  }
  return null;
};

// Send once (all chunks), then reconcile: resend ONLY the un-acked real chunks
// until the receiver confirms completion (its final message-hash receipt) or the
// retry budget is exhausted. The acked set is extrapolated from receipts in
// handleReadReceipt. Selective (never resend-all) so no dup frames pile up. On a
// full reconnect the loop re-establishes the per-message channel and continues
// (resume), rather than giving up — the same reconcile drives both.
const sendWithReconcile = async (
  channel: IRTCDataChannel | string,
  api: BaseQueryApi,
  roomId: string,
  senderSecretKey: Uint8Array,
  chunksLen: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  hashHex: string,
  peerId: string,
  peerPublicKeyHex: string,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
): Promise<void> => {
  clearTransfer(peerId, hashHex);

  let currentChannel = channel;
  // The per-message channel label is a pure function of the message, so the dead
  // channel's own label is exactly what we re-open on reconnect.
  const channelMessageLabel =
    typeof channel === "string" ? channel : channel.label;

  // Wait for the per-message channel to open before the first send, so its
  // initial frames aren't spilled to the WS relay while it is still connecting.
  if (typeof currentChannel !== "string") await waitForOpen(currentChannel);

  // Initial pass: all chunks (real + decoy).
  await sendChunks(
    currentChannel,
    api,
    roomId,
    senderSecretKey,
    chunksLen,
    chunkHashes,
    merkleRoot,
    hashHex,
    peerId,
    peerPublicKeyHex,
    encryptionModule,
    merkleModule,
  );

  let retries = 0;
  let resumeAttempts = 0;
  while (retries < MAX_RETRANSMITS) {
    const done = await waitForCompletion(
      peerId,
      hashHex,
      RETRANSMIT_TIMEOUT_MS * (retries + 1),
    );
    if (done) break;

    // Channel died — a full reconnect. Re-establish it on the peer's fresh
    // connection and continue; the receiver re-emits its receipts so we resend
    // only the still-missing reals. Bounded so a flapping peer can't loop. Only
    // treat a genuinely dead (closed/closing) channel as needing resume — a
    // still-"connecting" channel is given more time via waitForCompletion.
    if (
      typeof currentChannel !== "string" &&
      (currentChannel.readyState === "closed" ||
        currentChannel.readyState === "closing")
    ) {
      if (resumeAttempts >= MAX_RESUME_ATTEMPTS) break;
      resumeAttempts++;
      const resumed = await resumeChannel(
        api,
        roomId,
        peerId,
        channelMessageLabel,
        peerConnections,
        dataChannels,
        RECONNECT_RESUME_TIMEOUT_MS,
      );
      if (!resumed) break;
      currentChannel = resumed;
      retries = 0; // fresh retransmit budget for the resumed transfer

      // Telemetry: surface the reconnect recovery to the UI as a reliability
      // event (the user validates the transfer survived a dropped connection).
      api.dispatch(
        incrementMessageStats({ roomId, sha512Hex: hashHex, retransmit: true }),
      );
      continue;
    }

    // Reconcile: resend only the reals the receiver hasn't acked yet.
    await sendChunks(
      currentChannel,
      api,
      roomId,
      senderSecretKey,
      chunksLen,
      chunkHashes,
      merkleRoot,
      hashHex,
      peerId,
      peerPublicKeyHex,
      encryptionModule,
      merkleModule,
      getAckedChunks(peerId, hashHex),
    );
    retries++;

    // Telemetry: a retransmit round happened — lets the UI show reliability.
    api.dispatch(
      incrementMessageStats({ roomId, sha512Hex: hashHex, retransmit: true }),
    );
  }

  clearTransfer(peerId, hashHex);
};

export const handleSendMessage = async (
  data: string | File,
  api: BaseQueryApi,
  label: string,
  roomId: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  minChunks = 1,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
) => {
  try {
    const { rooms, keyPair, signalingServer } = api.getState() as State;

    const roomIndex = rooms.findIndex((r) => r.id === roomId);

    if (roomIndex > -1) {
      const channelIndex = rooms[roomIndex].channels.findIndex(
        (c) => c.label === label,
      );
      if (channelIndex === -1)
        throw new Error("No channel with label " + label);

      const { merkleRoot, merkleRootHex, hashHex, totalChunks, chunkHashes } =
        await splitToChunks(
          data,
          api,
          label,
          rooms[roomIndex],
          merkleModule,
          minChunks,
          chunkSize,
          percentageFilledChunk,
          metadataSchemaVersion,
        );

      if (
        merkleRoot.length === 0 ||
        hashHex.length === 0 ||
        totalChunks === 0 ||
        chunkHashes.length === 0
      )
        return;

      const channelMessageLabel = await compileChannelMessageLabel(
        label,
        merkleRootHex,
      );

      const ptr4 = encryptionModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
      const senderSecretKey = new Uint8Array(
        encryptionModule.wasmMemory.buffer,
        ptr4,
        crypto_sign_ed25519_SECRETKEYBYTES,
      );
      senderSecretKey.set(hexToUint8Array(keyPair.secretKey));

      const ptr8 = encryptionModule._malloc(crypto_hash_sha512_BYTES);
      const additionalData = new Uint8Array(
        encryptionModule.wasmMemory.buffer,
        ptr8,
        crypto_hash_sha512_BYTES,
      );
      additionalData.set(merkleRoot);

      const PEERS_LEN = rooms[roomIndex].channels[channelIndex].peerIds.length;
      const promises: Promise<void>[] = [];
      for (let i = 0; i < PEERS_LEN; i++) {
        const peerIndex = peerConnections.findIndex(
          (p) =>
            p.withPeerId === rooms[roomIndex].channels[channelIndex].peerIds[i],
        );
        if (peerIndex === -1 && !signalingServer.isConnected) continue;

        const channel = // channelMessageLabel;
          peerIndex > -1 &&
          peerConnections[peerIndex].connectionState === "connected"
            ? await handleOpenChannel(
                {
                  channel: channelMessageLabel,
                  epc: peerConnections[peerIndex],
                  roomId,
                  dataChannels,
                },
                api,
              )
            : channelMessageLabel;

        const peerId =
          peerIndex > -1
            ? peerConnections[peerIndex].withPeerId
            : rooms[roomIndex].channels[channelIndex].peerIds[i];

        const peerRoomIndex = rooms[roomIndex].peers.findIndex(
          (p) => p.peerId === peerId,
        );

        const peerPublicKeyHex =
          peerIndex > -1
            ? peerConnections[peerIndex].withPeerPublicKey
            : peerRoomIndex > -1
              ? rooms[roomIndex].peers[peerRoomIndex].peerPublicKey
              : "";

        if (
          peerPublicKeyHex.length ===
          crypto_sign_ed25519_PUBLICKEYBYTES * 2
        ) {
          promises.push(
            sendWithReconcile(
              channel,
              api,
              roomId,
              senderSecretKey,
              totalChunks,
              chunkHashes,
              additionalData,
              hashHex,
              peerId,
              peerPublicKeyHex,
              encryptionModule,
              merkleModule,
              peerConnections,
              dataChannels,
            ),
          );
        }
      }

      await Promise.allSettled(promises);

      // Every peer has now either completed (its newChunks were freed via the
      // transferComplete path) or permanently given up on resume. No resume is
      // outstanding, so reclaim any newChunks a give-up left behind — otherwise
      // an abandoned transfer would leak its whole (padded) body into IndexedDB.
      // Idempotent (no-op for already-freed completed peers) and multi-peer-safe
      // (runs only after ALL peers' sendWithReconcile settle).
      await deleteDBNewChunk(undefined, undefined, hashHex);

      zeroFree(encryptionModule, senderSecretKey);
      encryptionModule._free(ptr8);
    }
  } catch (error) {
    console.trace(error);
  }
};
