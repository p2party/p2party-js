import {
  deleteDBNewChunk,
  getDBChunk,
  // getDBMessageData,
  getDBNewChunk,
} from "../db/api";

import { setMessage } from "../reducers/roomSlice";

import { decompileChannelMessageLabel } from "../utils/channelLabel";
import { uint8ArrayToHex } from "../utils/uint8array";
// import { MessageType } from "../utils/messageTypes";

import type { IRTCDataChannel } from "../api/webrtc/interfaces";
import type { BaseQueryApi } from "@reduxjs/toolkit/dist/query";
// import type { State } from "../store";
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

    if (uint8ArrayToHex(receivedChunkHash) === hashHex) {
      const messageIndex = room.messages.findLastIndex(
        (m) => m.merkleRootHex === merkleRootHex || m.sha512Hex === hashHex,
      );

      if (messageIndex > -1) {
        api.dispatch(
          setMessage({
            roomId: room.id,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: room.messages[messageIndex].fromPeerId,
            chunkSize: room.messages[messageIndex].totalSize,
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
        if (dbChunk && messageIndex > -1) {
          const chunkSize = dbChunk.byteLength;
          if (
            chunkSize > 0 &&
            room.messages[messageIndex].totalSize >=
              room.messages[messageIndex].savedSize + chunkSize
          ) {
            // console.log(
            //   "Sent " +
            //     (room.messages[messageIndex].savedSize + chunkSize) +
            //     " of total " +
            //     room.messages[messageIndex].totalSize +
            //     " with chunk index " +
            //     chunkIndex,
            // );
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

            if (
              room.messages[messageIndex].savedSize + chunkSize ===
              room.messages[messageIndex].totalSize // ||
              // room.messages[messageIndex].savedSize ===
              //   room.messages[messageIndex].totalSize
            ) {
              channel.close();
            }
          } else if (
            room.messages[messageIndex].totalSize ===
            room.messages[messageIndex].savedSize
          ) {
            api.dispatch(
              setMessage({
                roomId: room.id,
                merkleRootHex,
                sha512Hex: hashHex,
                fromPeerId: room.messages[messageIndex].fromPeerId,
                chunkSize: room.messages[messageIndex].totalSize,
                totalSize: room.messages[messageIndex].totalSize,
                messageType: room.messages[messageIndex].messageType,
                filename: room.messages[messageIndex].filename,
                channelLabel,
                timestamp: room.messages[messageIndex].timestamp,
              }),
            );
          }
        }
      } else {
        console.log("Did not find chunk with receipt hex");
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
