import {
  handleSendMessage,
  MessageDeliveryError,
} from "../../handlers/handleSendMessage";

import { wasmLoader } from "../../cryptography/wasmLoader";
import cryptoMemory from "../../cryptography/memory";
import { CHUNK_LEN } from "../../utils/constants";
import { planMessageChunkCount } from "../../utils/splitToChunks";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCSendMessageParams,
} from "./interfaces";
import type { SendMessageResult } from "../../handlers/handleSendMessage";

export interface RTCChannelMessageParamsExtension extends RTCSendMessageParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

/**
 * Every logical send owns independent fixed WASM memories. Large-file hashing,
 * per-message reconciliation, and reconnect waits therefore never hold a
 * process-wide crypto mutex or block sends in another room.
 */
const webrtcMessageQuery: BaseQueryFn<
  RTCChannelMessageParamsExtension,
  SendMessageResult | undefined
> = async (
  {
    data,
    transferId,
    label,
    roomId,
    peerConnections,
    dataChannels,
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  },
  api,
) => {
  const effectiveMinChunks = minChunks ?? 1;
  const effectiveChunkSize = chunkSize ?? CHUNK_LEN;
  const effectivePercentageFilledChunk = percentageFilledChunk ?? 0.9;
  const totalSize =
    typeof data === "string" ? new TextEncoder().encode(data).length : data.size;
  const totalChunks = planMessageChunkCount(
    totalSize,
    effectiveMinChunks,
    effectiveChunkSize,
    effectivePercentageFilledChunk,
  );
  const encryptionModule = await wasmLoader(cryptoMemory.protocolV3Memory());
  const merkleModule = await wasmLoader(
    cryptoMemory.getMerkleProofMemory(totalChunks),
  );

  // MessageDeliveryError must be RETURNED, not thrown. RTK Query serializes an
  // error that escapes a queryFn — the caller then receives a plain object, so
  // `instanceof MessageDeliveryError` is false and `.result` with its per-peer
  // outcomes is gone. Returning it as a rejected value carries the instance
  // through `unwrap()` intact, which is what MessageTransferHandle.done
  // documents and what the README tells callers to check.
  try {
    return { data: await sendOrThrow() };
  } catch (error) {
    if (error instanceof MessageDeliveryError) return { error };
    throw error;
  }

  async function sendOrThrow() {
    return await handleSendMessage(
    data,
    api,
    label,
    roomId,
    // Keep the live registry reference: reconnect/resume must observe a
    // replacement PC pushed after this send began. The handler scopes every
    // lookup by (roomId, peerId).
    peerConnections,
    dataChannels,
    encryptionModule,
    merkleModule,
    transferId,
    effectiveMinChunks,
    effectiveChunkSize,
    effectivePercentageFilledChunk,
    metadataSchemaVersion,
  );
  }
};

export default webrtcMessageQuery;
