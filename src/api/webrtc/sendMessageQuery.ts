import { handleSendMessage } from "../../handlers/handleSendMessage";

import { wasmLoader } from "../../cryptography/wasmLoader";

import { AsyncMutex } from "../../utils/mutex";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCSendMessageParams,
} from "./interfaces";

export interface RTCChannelMessageParamsExtension extends RTCSendMessageParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  encryptionWasmMemory: WebAssembly.Memory;
  merkleWasmMemory: WebAssembly.Memory;
}

/**
 * Serializes access to the shared encryptionWasmMemory and
 * merkleWasmMemory. Without this, concurrent sendMessage mutations
 * would interleave _malloc / _free / crypto calls on the same
 * WebAssembly linear memory, risking buffer corruption.
 */
const sendMutex = new AsyncMutex();

const webrtcMessageQuery: BaseQueryFn<
  RTCChannelMessageParamsExtension,
  undefined
> = async (
  {
    data,
    label,
    roomId,
    peerConnections,
    dataChannels,
    encryptionWasmMemory,
    merkleWasmMemory,
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  },
  api,
) => {
  return sendMutex.runExclusive(async () => {
    const encryptionModule = await wasmLoader(encryptionWasmMemory);
    const merkleModule = await wasmLoader(merkleWasmMemory);

    await handleSendMessage(
      data,
      api,
      label,
      roomId,
      peerConnections,
      dataChannels,
      encryptionModule,
      merkleModule,
      minChunks,
      chunkSize,
      percentageFilledChunk,
      metadataSchemaVersion,
    );

    return { data: undefined };
  });
};

export default webrtcMessageQuery;
