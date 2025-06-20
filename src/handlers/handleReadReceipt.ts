import { deleteDBNewChunk, getDBChunk, getDBNewChunk } from "../db/api";

import { setMessage, setMessageAllChunks } from "../reducers/roomSlice";

import { decompileChannelMessageLabel } from "../utils/channelLabel";
import { uint8ArrayToHex } from "../utils/uint8array";

import type { IRTCDataChannel } from "../api/webrtc/interfaces";
import type { BaseQueryApi } from "@reduxjs/toolkit/dist/query";
import type { Room } from "../reducers/roomSlice";

export const handleReadReceipt = async (
  receivedChunkHash: Uint8Array,
  channel: IRTCDataChannel,
  room: Room,
  api: BaseQueryApi,
  dataChannels: IRTCDataChannel[],
) => {
  try {
    const channelsSendingSameItem = dataChannels.filter(
      (dc) => dc.label === channel.label,
    );

    const hex = uint8ArrayToHex(receivedChunkHash);

    const { channelLabel, merkleRootHex, hashHex } =
      await decompileChannelMessageLabel(channel.label);

    if (hex === hashHex) {
      const messageIndex = room.messages.findLastIndex(
        (m) => m.merkleRootHex === merkleRootHex || m.sha512Hex === hashHex,
      );

      if (messageIndex > -1) {
        api.dispatch(
          setMessageAllChunks({
            roomId: room.id,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: room.messages[messageIndex].fromPeerId,
            totalSize: room.messages[messageIndex].totalSize,
            messageType: room.messages[messageIndex].messageType,
            filename: room.messages[messageIndex].filename,
            channelLabel,
            timestamp: room.messages[messageIndex].timestamp,
          }),
        );
      }
    } else {
      const chunk = await getDBNewChunk(hex);
      const chunkIndex = chunk?.chunkIndex ?? -1;
      if (chunk && chunkIndex > -1) {
        const messageIndex = room.messages.findLastIndex(
          (m) => m.merkleRootHex === merkleRootHex || m.sha512Hex === hashHex,
        );

        const dbChunk = await getDBChunk(merkleRootHex, chunkIndex);
        const chunkSize = dbChunk?.byteLength || 0;
        if (dbChunk && chunkSize > 0 && messageIndex > -1) {
          if (
            room.messages[messageIndex].savedSize + chunkSize ===
              room.messages[messageIndex].totalSize ||
            room.messages[messageIndex].savedSize ===
              room.messages[messageIndex].totalSize
          ) {
            api.dispatch(
              setMessageAllChunks({
                roomId: room.id,
                merkleRootHex,
                sha512Hex: hashHex,
                fromPeerId: room.messages[messageIndex].fromPeerId,
                totalSize: room.messages[messageIndex].totalSize,
                messageType: room.messages[messageIndex].messageType,
                filename: room.messages[messageIndex].filename,
                channelLabel,
                timestamp: room.messages[messageIndex].timestamp,
              }),
            );
          } else {
            api.dispatch(
              setMessage({
                roomId: room.id,
                merkleRootHex,
                sha512Hex: hashHex,
                fromPeerId: room.messages[messageIndex].fromPeerId,
                chunkSize,
                totalSize: room.messages[messageIndex].totalSize,
                messageType: room.messages[messageIndex].messageType,
                filename: room.messages[messageIndex].filename,
                channelLabel,
                timestamp: room.messages[messageIndex].timestamp,
              }),
            );
          }
        } else if (messageIndex === -1) {
          console.log("No message with hex " + hashHex);
        }
      } else {
        console.log(chunk?.hash);
        console.log("Did not find chunk with receipt hex", hex);
      }
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
