import { handleSendMessage } from "../../handlers/handleSendMessage";

import libcrypto from "../../cryptography/libcrypto";

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
  receiveMessageWasmMemory: WebAssembly.Memory;
}

const webrtcMessageQuery: BaseQueryFn<
  RTCChannelMessageParamsExtension,
  void,
  unknown
> = async (
  {
    data,
    label,
    roomId,
    peerConnections,
    dataChannels,
    encryptionWasmMemory,
    merkleWasmMemory,
    receiveMessageWasmMemory,
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  },
  api,
) => {
  const encryptionModule = await libcrypto({
    wasmMemory: encryptionWasmMemory,
  });

  const merkleModule = await libcrypto({
    wasmMemory: merkleWasmMemory,
  });

  const receiveMessageModule = await libcrypto({
    wasmMemory: receiveMessageWasmMemory,
  });

  await handleSendMessage(
    data,
    api,
    label,
    roomId,
    peerConnections,
    dataChannels,
    encryptionModule,
    merkleModule,
    receiveMessageModule,
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  );

  return { data: undefined };
};

export default webrtcMessageQuery;
