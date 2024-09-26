import {
  deleteAllPeers,
  deletePeer,
  setCandidate,
  setDescription,
  setPeer,
  setPeerChannel,
} from "../reducers/peersSlice";
import { setChannel } from "../reducers/channelsSlice";
import { setIsSettingRemoteAnswerPending } from "../reducers/isSettingRemoteAnswerPendingSlice";

import signalingServerApi from "../api/signalingServerApi";
// import { getConnectedRoomPeers } from "../api/getConnectedRoomPeers";

import type { Middleware } from "redux";
import type { AppDispatch, RootState } from "../store";
import type {
  IRTCPeerConnection,
  IRTCIceCandidate,
} from "../reducers/peersSlice";
import type {
  WebSocketMessagePeersRequest,
  WebSocketMessageCandidateSend,
  WebSocketMessageDescriptionSend,
} from "../utils/interfaces";

const peersMiddleware: Middleware = (store) => {
  const peerConnections: IRTCPeerConnection[] = [];
  const iceCandidates: IRTCIceCandidate[] = [];

  const dispatch: AppDispatch = store.dispatch;

  const rtcConnectWithPeer = async (
    peerId: string,
    peerPublicKey: string,
    roomId: string,
    initiator = true,
    rtcConfig: RTCConfiguration = {
      iceServers: [
        {
          urls: [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
          ],
        },
      ],
    },
  ) => {
    const { keyPair } = store.getState() as RootState;
    if (peerId === keyPair.peerId)
      throw new Error("Cannot create a connection with oneself.");

    const peerIndex = peerConnections.findIndex(
      (peer) => peer.withPeerId === peerId,
    );
    if (peerIndex !== -1) return peerConnections[peerIndex];

    if (initiator)
      console.log(`You have initiated a peer connection with ${peerId}.`);

    const pc = new RTCPeerConnection(rtcConfig);
    const epc = pc as IRTCPeerConnection;
    epc.peerIsInitiator = initiator;
    epc.withPeerId = peerId;
    epc.withPeerPublicKey = peerPublicKey;
    epc.makingOffer = false;

    epc.onnegotiationneeded = async () => {
      try {
        epc.makingOffer = true;
        await epc.setLocalDescription();
        const description = epc.localDescription;
        if (description) {
          const { keyPair } = store.getState() as RootState;

          dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "description",
                description,
                fromPeerId: keyPair.peerId,
                fromPeerPublicKey: keyPair.publicKey,
                toPeerId: peerId,
                roomId,
              } as WebSocketMessageDescriptionSend,
            }),
          );

          console.log(
            `Negotiation was needed with ${peerId} and you sent a description ${description.type}.`,
          );
        }
      } catch (err) {
        console.error(err);
      } finally {
        epc.makingOffer = false;
      }
    };

    epc.onicecandidate = ({ candidate }) => {
      if (candidate && candidate.candidate !== "") {
        const { keyPair } = store.getState() as RootState;
        dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "candidate",
              candidate,
              fromPeerId: keyPair.peerId,
              toPeerId: peerId,
              roomId,
            } as WebSocketMessageCandidateSend,
          }),
        );

        console.log(`ICE candidate was sent to ${peerId}.`);
      }
    };

    epc.onicecandidateerror = async () => {
      store.dispatch(deletePeer({ peerId: epc.withPeerId }));
      console.error(`ICE candidate error with ${peerId}`);
    };

    epc.oniceconnectionstatechange = async () => {
      console.log(
        `ICE candidate connection state with ${peerId} is ${epc.iceConnectionState}.`,
      );
      if (epc.iceConnectionState === "failed") {
        epc.restartIce();
      }
    };

    epc.onicegatheringstatechange = async () => {
      console.log(
        `ICE gathering state with ${peerId} is ${epc.iceGatheringState}.`,
      );
    };

    epc.onsignalingstatechange = async () => {
      console.log(`Signaling state with ${peerId} is ${epc.signalingState}.`);

      if (epc.signalingState === "stable" && initiator) {
        const CANDIDATES_LEN = iceCandidates.length;
        const indexes: number[] = [];
        for (let i = 0; i < CANDIDATES_LEN; i++) {
          if (iceCandidates[i].withPeerId !== peerId) continue;

          try {
            await epc.addIceCandidate(iceCandidates[i]);
            indexes.push(i);
          } catch (error) {
            throw error;
          }
        }

        while (indexes.length > 0) {
          iceCandidates.splice(indexes[0], 1);
          indexes.splice(0, 1);
        }
      }
    };

    epc.onconnectionstatechange = async () => {
      if (
        epc.connectionState === "closed" ||
        epc.connectionState === "failed" ||
        epc.connectionState === "disconnected"
      ) {
        store.dispatch(deletePeer({ peerId }));
        console.error(
          `Connection with peer ${peerId} has ${epc.connectionState}.`,
        );
      } else {
        console.log(
          `Connection status with peer ${peerId} is ${epc.connectionState}.`,
        );

        if (epc.connectionState === "connected" && !epc.peerIsInitiator) {
          // store.dispatch(
          //   setPeer({ roomId, peerId, peerPublicKey, initiate: false }),
          // );
          const { signalingServer } =
            store.getState() as RootState;
          if (
            signalingServer.isConnected // &&
            // isUUID(keyPair.peerId) &&
            // isUUID(room.id)
          ) {
            dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "peers",
                  fromPeerId: keyPair.peerId,
                  roomId,
                } as WebSocketMessagePeersRequest,
              }),
            );
          }
          // await rtcConnectWithRoom(roomId, true, rtcConfig);
        }
      }
    };

    epc.ondatachannel = async (e) => {
      // await openDataChannel(e.channel, epc);
      store.dispatch(
        setChannel({
          label: e.channel.label,
          channel: e.channel,
          roomId,
          epc,
        }),
      );
    };

    if (initiator) {
      store.dispatch(
        setChannel({
          label: "signaling",
          channel: "signaling",
          roomId,
          epc,
        }),
      );
    } // await openDataChannel("signaling", epc);

    return epc;
  };

  // const rtcConnectWithRoom = async (
  //   roomId: string,
  //   starConfig = false,
  //   rtcConfig: RTCConfiguration = {
  //     iceServers: [
  //       {
  //         urls: [
  //           "stun:stun.l.google.com:19302",
  //           "stun:stun1.l.google.com:19302",
  //         ],
  //       },
  //     ],
  //   },
  // ) => {
  //   try {
  //     const clientsInRoom = await getConnectedRoomPeers(roomId);
  //     const ROOM_CLIENTS_LEN = clientsInRoom.length;
  //
  //     const { keyPair } = store.getState();
  //
  //     if (
  //       roomId.length > 0 &&
  //       keyPair.peerId.length > 0 &&
  //       ROOM_CLIENTS_LEN > peerConnections.length + 1
  //     ) {
  //       for (let i = 0; i < ROOM_CLIENTS_LEN; i++) {
  //         const withPeerId = clientsInRoom[i].id;
  //         if (withPeerId === keyPair.peerId) continue;
  //
  //         const withPeerPublicKey = clientsInRoom[i].publicKey;
  //
  //         const peerIndex = peerConnections.findIndex(
  //           (peer) => peer.withPeerId === withPeerId,
  //         );
  //         if (peerIndex !== -1) continue;
  //
  //         if (!starConfig) {
  //           const epc = await rtcConnectWithPeer(
  //             withPeerId,
  //             withPeerPublicKey,
  //             roomId,
  //             true,
  //             rtcConfig,
  //           );
  //           peerConnections.push(epc);
  //         } else {
  //           const clientIndex = clientsInRoom.findIndex(
  //             (client) => client.id === keyPair.peerId,
  //           );
  //           if (clientIndex === -1)
  //             throw new Error("Impossible! Current client is not in the room");
  //
  //           if (
  //             clientsInRoom[clientIndex].createdAt > clientsInRoom[i].createdAt
  //           ) {
  //             // One of them needs to be an initiator and createdAt does not change
  //             await rtcConnectWithPeer(
  //               withPeerId,
  //               withPeerPublicKey,
  //               roomId,
  //               true,
  //               rtcConfig,
  //             );
  //           } else if (
  //             clientsInRoom[clientIndex].createdAt ===
  //             clientsInRoom[i].createdAt
  //           ) {
  //             if (
  //               clientsInRoom[clientIndex].updatedAt >
  //               clientsInRoom[i].updatedAt
  //             ) {
  //               const epc = await rtcConnectWithPeer(
  //                 withPeerId,
  //                 withPeerPublicKey,
  //                 roomId,
  //                 true,
  //                 rtcConfig,
  //               );
  //               peerConnections.push(epc);
  //             } else {
  //               continue;
  //             }
  //           } else {
  //             continue;
  //           }
  //         }
  //       }
  //     }
  //   } catch (error) {
  //     throw error;
  //   }
  // };

  return (next) => async (action) => {
    const { isSettingRemoteAnswerPending } = store.getState() as RootState;

    if (deletePeer.match(action)) {
      const { peerId } = action.payload;
      const peerIndex = peerConnections.findIndex(
        (peer) => peer.withPeerId === peerId,
      );

      if (
        peerIndex > -1 &&
        (peerConnections[peerIndex].connectionState === "connected" ||
          peerConnections[peerIndex].connectionState === "failed")
      ) {
        peerConnections[peerIndex].ontrack = null;
        peerConnections[peerIndex].ondatachannel = null;
        peerConnections[peerIndex].onicecandidate = null;
        peerConnections[peerIndex].onicecandidateerror = null;
        peerConnections[peerIndex].onnegotiationneeded = null;
        peerConnections[peerIndex].onsignalingstatechange = null;
        peerConnections[peerIndex].onconnectionstatechange = null;
        peerConnections[peerIndex].onicegatheringstatechange = null;
        peerConnections[peerIndex].oniceconnectionstatechange = null;
        peerConnections[peerIndex].close();
        peerConnections.splice(peerIndex, 1);
      }

      return next(action);
    }

    if (deleteAllPeers.match(action)) {
      const PEER_CONNECTIONS_LEN = peerConnections.length;
      for (let i = 0; i < PEER_CONNECTIONS_LEN; i++) {
        if (
          peerConnections[i].connectionState === "connected" ||
          peerConnections[i].connectionState === "failed"
        ) {
          peerConnections[i].ontrack = null;
          peerConnections[i].ondatachannel = null;
          peerConnections[i].onicecandidate = null;
          peerConnections[i].onicecandidateerror = null;
          peerConnections[i].onnegotiationneeded = null;
          peerConnections[i].onsignalingstatechange = null;
          peerConnections[i].onconnectionstatechange = null;
          peerConnections[i].onicegatheringstatechange = null;
          peerConnections[i].oniceconnectionstatechange = null;
          peerConnections[i].close();
        }
      }

      return next(action);
    }

    if (setDescription.match(action)) {
      const { peerId, peerPublicKey, roomId, description, rtcConfig } =
        action.payload;
      const connectionIndex = peerConnections.findIndex(
        (peer) => peer.withPeerId === peerId,
      );

      const epc =
        connectionIndex !== -1
          ? peerConnections[connectionIndex]
          : await rtcConnectWithPeer(
              peerId,
              peerPublicKey,
              roomId,
              false,
              rtcConfig,
            );

      const readyForOffer =
        !epc.makingOffer &&
        (epc.signalingState == "stable" || isSettingRemoteAnswerPending);

      const offerCollision = description.type === "offer" && !readyForOffer;

      // If clientIsInitiator then !polite
      const ignoreOffer = epc.peerIsInitiator && offerCollision;
      if (ignoreOffer) return next(action);

      const setPending = description.type === "answer";
      store.dispatch(setIsSettingRemoteAnswerPending(setPending));
      // await epc.setRemoteDescription(description);
      if (offerCollision) {
        await Promise.all([
          epc.setLocalDescription({ type: "rollback" }),
          epc.setRemoteDescription(description),
        ]);
      } else {
        if (epc.signalingState !== "stable") {
          await epc.setRemoteDescription(description);
        }
      }

      if (setPending) store.dispatch(setIsSettingRemoteAnswerPending(false));

      if (description.type == "offer") {
        await epc.setLocalDescription();
        const localDescription = epc.localDescription;
        if (!localDescription) {
          console.error(
            "Could not generate local description as answer to offer",
          );

          return next(action);
        }

        const { keyPair } = store.getState() as RootState;

        dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "description",
              description: localDescription,
              fromPeerId: keyPair.peerId,
              fromPeerPublicKey: keyPair.publicKey,
              toPeerId: peerId,
              roomId,
            } as WebSocketMessageDescriptionSend,
          }),
        );
      }

      return next(action);
    }

    if (setCandidate.match(action)) {
      const { peerId, candidate } = action.payload;
      const connectionIndex = peerConnections.findIndex(
        (peer) => peer.withPeerId === peerId,
      );

      if (connectionIndex === -1) {
        iceCandidates.push(Object.assign(candidate, { withPeerId: peerId }));

        return next(action);
      }

      const epc = peerConnections[connectionIndex];

      if (epc.peerIsInitiator && epc.signalingState !== "stable") {
        iceCandidates.push(
          Object.assign(candidate, {
            withPeerId: epc.withPeerId,
          }),
        );
      } else {
        try {
          await epc.addIceCandidate(candidate);
        } catch (error) {
          throw error;
        }
      }

      return next(action);
    }

    if (setPeer.match(action)) {
      const { peerId, peerPublicKey, roomId, initiate, rtcConfig } =
        action.payload;

      const connectionIndex = peerConnections.findIndex((peer) => {
        peer.withPeerId === peerId;
      });

      if (connectionIndex !== -1) return next(action);

      const epc = await rtcConnectWithPeer(
        peerId,
        peerPublicKey,
        roomId,
        initiate,
        rtcConfig,
      );

      peerConnections.push(epc);
    }

    if (setPeerChannel.match(action)) {
      const { label, roomId, withPeerId } = action.payload;

      const connectionIndex = peerConnections.findIndex((peer) => {
        peer.withPeerId === withPeerId;
      });

      if (connectionIndex !== -1) return next(action);

      store.dispatch(
        setChannel({
          label,
          channel: label,
          roomId,
          epc: peerConnections[connectionIndex],
        }),
      );
    }

    return next(action);
  };
};

export default peersMiddleware;
