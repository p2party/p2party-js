import {
  deleteDBNewChunk,
  getDBChunk,
  getDBMessageData,
  getDBNewChunk,
} from "../db/api";

import { setMessage } from "../reducers/roomSlice";

import { uint8ArrayToHex } from "../utils/uint8array";
import { MessageType } from "../utils/messageTypes";

import type { IRTCDataChannel } from "../api/webrtc/interfaces";
import type { BaseQueryApi } from "@reduxjs/toolkit/dist/query";
import type { State } from "../store";

export const handleReadReceipt = async (
  receivedChunkHash: Uint8Array,
  channelLabel: string,
  api: BaseQueryApi,
  dataChannels: IRTCDataChannel[],
) => {
  try {
    const { keyPair } = api.getState() as State;

    const channelsSendingSameItem = dataChannels.filter(
      (dc) => dc.label === channelLabel,
    );

    const hex = uint8ArrayToHex(receivedChunkHash);

    const chunk = await getDBNewChunk(hex);

    if (chunk && chunk.chunkIndex > -1) {
      const messageData = await getDBMessageData(chunk.merkleRoot);
      const dbChunk = await getDBChunk(chunk.merkleRoot, chunk.chunkIndex);

      api.dispatch(
        setMessage({
          roomId: messageData?.roomId ?? "",
          merkleRootHex: chunk.merkleRoot,
          sha512Hex: chunk.hash,
          fromPeerId: keyPair.peerId,
          chunkSize: dbChunk?.byteLength ?? 0,
          totalSize:
            channelsSendingSameItem.length * (messageData?.totalSize ?? 0),
          messageType: messageData?.messageType ?? MessageType.Text,
          filename: messageData?.filename ?? "",
          channelLabel,
        }),
      );
    }

    // Only one peer receives the message
    if (channelsSendingSameItem.length === 1) {
      await deleteDBNewChunk(undefined, hex);
    }
  } catch (error) {
    console.error(error);
    throw error;
  }
};
