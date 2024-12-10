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
  decryptionWasmMemory: WebAssembly.Memory;
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
    peerConnections,
    dataChannels,
    encryptionWasmMemory,
    decryptionWasmMemory,
    merkleWasmMemory,
  },
  api,
) => {
  try {
    const encryptionModule = await libcrypto({
      wasmMemory: encryptionWasmMemory,
    });

    const decryptionModule = await libcrypto({
      wasmMemory: decryptionWasmMemory,
    });

    const merkleModule = await libcrypto({
      wasmMemory: merkleWasmMemory,
    });

    await handleSendMessage(
      data,
      peerConnections,
      dataChannels,
      encryptionModule,
      decryptionModule,
      merkleModule,
      api,
      label,
    );

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcMessageQuery;
