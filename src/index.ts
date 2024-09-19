import { isUUID } from "class-validator";

import { room } from "./store/room";

import { getConnectedRoomPeers } from "./api/getConnectedRoomPeers";

import signalingServerApi from "./api/signalingServerApi";
import { peersSelector, setPeer, setPeerChannel } from "./reducers/peersSlice";
import { roomsSelector } from "./reducers/roomsSlice";
import { keyPairSelector } from "./reducers/keyPairSlice";
import {
  channelsSelector,
  deleteLabelChannels,
  sendMessageToChannel,
} from "./reducers/channelsSlice";
import {
  signalingServerSelector,
  signalingServerActions,
} from "./reducers/signalingServerSlice";

import type { AppDispatch, RoomState } from "./store/room";
import type { Room } from "./reducers/roomsSlice";
import type { Peer } from "./reducers/peersSlice";
import type { Channel } from "./reducers/channelsSlice";
import type { Message } from "./reducers/channelsSlice";

import type {
  WebSocketMessageRoomIdRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageChallengeRequest,
  WebSocketMessageChallengeResponse,
  WebSocketMessageDescriptionSend,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateSend,
  WebSocketMessageCandidateReceive,
  WebSocketMessageError,
} from "./utils/interfaces";

const dispatch: AppDispatch = room.dispatch;

const connectToSignalingServer = async (
  signalingServerUrl = "ws://localhost:3001/ws",
) => {
  dispatch(
    signalingServerApi.endpoints.connectWebSocket.initiate(signalingServerUrl)
  )
  // const { keyPair } = room.getState();
  // if (keyPair.secretKey.length === 0) {
  //   const pair = room.dispatch(setKeyPair());
  //   const res = unwrapResult(pair);
  // }
  //
  // room.dispatch(signalingServerActions.startConnecting(signalingServerUrl));
};

const connectToRoom = (roomUrl: string) => {
  const { keyPair, signalingServer, rooms } = room.getState();

  if (signalingServer.isConnected && isUUID(keyPair.peerId)) {
    if (rooms.length > 0) {
      const roomIndex = rooms.findIndex((r) => r.url === roomUrl);

      if (roomIndex === -1 || !isUUID(rooms[roomIndex].id)) {
        room.dispatch(
          signalingServerActions.sendMessage({
            content: {
              type: "room",
              fromPeerId: keyPair.peerId,
              roomUrl,
            } as WebSocketMessageRoomIdRequest,
          }),
        );
      }
    } else {
      room.dispatch(
        signalingServerActions.sendMessage({
          content: {
            type: "room",
            fromPeerId: keyPair.peerId,
            roomUrl,
          } as WebSocketMessageRoomIdRequest,
        }),
      );
    }
  }
};

const connectToRoomPeers = async (
  roomUrl: string,
  httpServerUrl = "http://localhost:3001",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
      },
    ],
  },
) => {
  const { keyPair, signalingServer, rooms } = room.getState();

  const roomIndex = rooms.findIndex((r) => r.url === roomUrl);

  if (signalingServer.isConnected && roomIndex > -1) {
    const connectedRoomPeers = await getConnectedRoomPeers(
      roomUrl,
      httpServerUrl,
    );

    console.log(connectedRoomPeers);

    const LEN = connectedRoomPeers.length;
    for (let i = 0; i < LEN; i++) {
      if (connectedRoomPeers[i].publicKey === keyPair.publicKey) continue;

      room.dispatch(
        setPeer({
          roomId: connectedRoomPeers[i].roomId,
          peerId: connectedRoomPeers[i].id,
          peerPublicKey: connectedRoomPeers[i].publicKey,
          initiate: true,
          rtcConfig,
        }),
      );
    }
  }
};

const disconnectFromSignalingServer = async () => {
  room.dispatch(signalingServerActions.disconnect());
};

const disconnectFromRoom = async (roomId: string, _deleteMessages = false) => {
  const { channels } = room.getState();

  let channelIndex = channels.findIndex((c) => {
    c.roomId === roomId;
  });
  while (channelIndex > -1) {
    room.dispatch(
      deleteLabelChannels({
        channel: channels[channelIndex].label,
      }),
    );

    channelIndex = channels.findIndex((c) => {
      c.roomId === roomId;
    });
  }
  // await rtcDisconnectFromRoom(deleteMessages);
};

const openChannel = async (
  label: string,
  roomId: string,
  withPeerIds?: string[],
) => {
  const { peers, channels } = room.getState();
  const PEERS_LEN =
    withPeerIds && withPeerIds.length > 0 ? withPeerIds.length : peers.length;
  if (PEERS_LEN === 0) throw new Error("Cannot open channel with no peers");

  for (let i = 0; i < PEERS_LEN; i++) {
    const peerIndex =
      withPeerIds && withPeerIds.length > 0
        ? peers.findIndex((p) => {
            p.id === withPeerIds[i];
          })
        : i;

    const channelIndex = channels.findIndex(
      (channel) =>
        channel.withPeerId === peers[peerIndex].id && channel.label === label,
    );
    if (channelIndex > -1) continue; // || peers[i].connectionState !== "connected") continue;

    room.dispatch(
      setPeerChannel({
        label,
        roomId,
        withPeerId: peers[peerIndex].id,
      }),
    );
  }
};

const sendMessage = async (message: string, toChannel: string) => {
  const { keyPair } = room.getState();
  room.dispatch(
    sendMessageToChannel({
      message,
      fromPeerId: keyPair.peerId,
      channel: toChannel,
    }),
  );
};

export default {
  room,
  signalingServerSelector,
  peersSelector,
  roomsSelector,
  keyPairSelector,
  channelsSelector,
  connectToSignalingServer,
  connectToRoom,
  connectToRoomPeers,
  disconnectFromSignalingServer,
  disconnectFromRoom,
  openChannel,
  sendMessage,
};

export type {
  RoomState,
  Room,
  Channel,
  Peer,
  Message,
  WebSocketMessageRoomIdRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageChallengeRequest,
  WebSocketMessageChallengeResponse,
  WebSocketMessageDescriptionSend,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateSend,
  WebSocketMessageCandidateReceive,
  WebSocketMessageError,
};
