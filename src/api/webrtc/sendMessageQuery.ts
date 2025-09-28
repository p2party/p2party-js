import { handleSendMessage } from "../../handlers/handleSendMessage";

// import libcrypto from "../../cryptography/libcrypto";
import { wasmLoader } from "../../cryptography/wasmLoader";

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
    minChunks,
    chunkSize,
    percentageFilledChunk,
    metadataSchemaVersion,
  },
  api,
) => {
  const encryptionModule = await wasmLoader(encryptionWasmMemory);
  // const encryptionModule = await libcrypto({
  //   wasmMemory: encryptionWasmMemory,
  // });

  const merkleModule = await wasmLoader(merkleWasmMemory);
  // const merkleModule = await libcrypto({
  //   wasmMemory: merkleWasmMemory,
  // });

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
};

export default webrtcMessageQuery;
