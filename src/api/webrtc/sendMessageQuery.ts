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
  // receiveMessageWasmMemory: WebAssembly.Memory;
  encryptionWasmMemory: WebAssembly.Memory;
  // decryptionWasmMemory: WebAssembly.Memory;
  merkleWasmMemory: WebAssembly.Memory;
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
    // receiveMessageWasmMemory,
    encryptionWasmMemory,
    // decryptionWasmMemory,
    merkleWasmMemory,
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  },
  api,
) => {
  // const receiveMessageModule = await libcrypto({
  //   wasmMemory: receiveMessageWasmMemory,
  // });

  const encryptionModule = await libcrypto({
    wasmMemory: encryptionWasmMemory,
  });

  // const decryptionModule = await libcrypto({
  //   wasmMemory: decryptionWasmMemory,
  // });

  const merkleModule = await libcrypto({
    wasmMemory: merkleWasmMemory,
  });

  await handleSendMessage(
    data,
    api,
    label,
    roomId,
    peerConnections,
    dataChannels,
    // receiveMessageModule,
    encryptionModule,
    // decryptionModule,
    merkleModule,
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  );

  return { data: undefined };
};

export default webrtcMessageQuery;
