import { isUUID } from "class-validator";

import { store, dispatch } from "./store";

import { getConnectedRoomPeers } from "./api/getConnectedRoomPeers";

import signalingServerApi from "./api/signalingServerApi";
import { peersSelector, setPeer, setPeerChannel } from "./reducers/peersSlice";
import {
  roomSelector,
  setConnectingToPeers,
  setRoom,
} from "./reducers/roomSlice";
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

import type { RootState } from "./store";
import type { Room } from "./reducers/roomSlice";
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

const connect = (
  roomUrl: string,
  signalingServerUrl = "ws://localhost:3001/ws",
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
      },
    ],
  },
) => {
  const { keyPair, signalingServer, room } = store.getState();

  dispatch(setRoom({ url: roomUrl, id: "", rtcConfig }));

  if (signalingServer.isConnected && isUUID(keyPair.peerId)) {
    if (!isUUID(room.id)) {
      dispatch(
        signalingServerApi.endpoints.sendMessage.initiate({
          content: {
            type: "room",
            fromPeerId: keyPair.peerId,
            roomUrl,
          } as WebSocketMessageRoomIdRequest,
        }),
      );
    } else {
      dispatch(setConnectingToPeers(true));
    }
  } else {
    dispatch(
      signalingServerApi.endpoints.connectWebSocket.initiate(
        signalingServerUrl,
      ),
    );
  }
};

const connectToSignalingServer = async (
  signalingServerUrl = "ws://localhost:3001/ws",
) => {
  dispatch(
    signalingServerApi.endpoints.connectWebSocket.initiate(signalingServerUrl),
  );
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
  const { keyPair, signalingServer, room } = store.getState();

  const roomIndex = room.url === roomUrl ? 1 : -1;

  if (signalingServer.isConnected && roomIndex > -1) {
    const connectedRoomPeers = await getConnectedRoomPeers(
      roomUrl,
      httpServerUrl,
    );

    console.log(connectedRoomPeers);

    const LEN = connectedRoomPeers.length;
    for (let i = 0; i < LEN; i++) {
      if (connectedRoomPeers[i].publicKey === keyPair.publicKey) continue;

      dispatch(
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
  dispatch(signalingServerActions.disconnect());
};

const disconnectFromRoom = async (roomId: string, _deleteMessages = false) => {
  const { channels } = store.getState();

  let channelIndex = channels.findIndex((c) => {
    c.roomId === roomId;
  });
  while (channelIndex > -1) {
    dispatch(
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
  const { peers, channels } = store.getState();
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

    dispatch(
      setPeerChannel({
        label,
        roomId,
        withPeerId: peers[peerIndex].id,
      }),
    );
  }
};

const sendMessage = async (message: string, toChannel: string) => {
  const { keyPair } = store.getState();
  dispatch(
    sendMessageToChannel({
      message,
      fromPeerId: keyPair.peerId,
      channel: toChannel,
    }),
  );
};

export default {
  partyState: store,
  signalingServerSelector,
  peersSelector,
  roomSelector,
  keyPairSelector,
  channelsSelector,
  connect,
  connectToSignalingServer,
  connectToRoomPeers,
  disconnectFromSignalingServer,
  disconnectFromRoom,
  openChannel,
  sendMessage,
};

export type {
  RootState,
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
