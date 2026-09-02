import { deleteMessageStateOnly, deletePeer } from "../../reducers/roomSlice";
import { deleteRoomDataTerminal } from "./deleteRoomData";
import { forgetRetiredRemoteTransports } from "./retiredRemoteTransports";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromAllRoomsParams,
  DisconnectPeerTransport,
} from "./interfaces";

import type { State } from "../../store";

export interface RTCDisconnectFromAllRoomsParamsExtension extends RTCDisconnectFromAllRoomsParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  disconnectPeer: DisconnectPeerTransport;
}

const webrtcDisconnectAllRoomsQuery: BaseQueryFn<
  RTCDisconnectFromAllRoomsParamsExtension,
  undefined
> = async (
  {
    deleteMessages,
    exceptionRoomIds,
    peerConnections,
    dataChannels,
    disconnectPeer,
  },
  api,
) => {
  const exceptions = new Set(exceptionRoomIds ?? []);

  for (let i = dataChannels.length - 1; i >= 0; i--) {
    const channel = dataChannels[i];
    if (channel.roomIds.some((roomId) => exceptions.has(roomId))) continue;

    channel.releaseProtocolResources?.();
    channel.onopen = null;
    channel.onclose = null;
    channel.onerror = null;
    channel.onclosing = null;
    channel.onmessage = null;
    channel.onbufferedamountlow = null;
    if (channel.readyState !== "closed") channel.close();
    dataChannels.splice(i, 1);
  }

  const targets = peerConnections
    .filter((connection) => !exceptions.has(connection.roomId))
    .map((connection) => ({
      roomId: connection.roomId,
      peerId: connection.withPeerId,
    }));
  for (const target of targets) {
    await disconnectPeer(target);
    api.dispatch(deletePeer(target));
    // Every left room is terminal for its edges, exactly as in the
    // single-room path: their retired certificates are forgotten with them.
    forgetRetiredRemoteTransports(target.roomId, target.peerId);
  }

  if (deleteMessages) {
    const { rooms } = api.getState() as State;
    const failures: unknown[] = [];
    for (const room of rooms) {
      if (exceptions.has(room.id)) continue;
      try {
        await deleteRoomDataTerminal(room.id, (merkleRootHex) => {
          api.dispatch(
            deleteMessageStateOnly({
              roomId: room.id,
              merkleRootHex,
            }),
          );
        });
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length > 0)
      throw new AggregateError(
        failures,
        "All-room data deletion did not fully settle",
      );
  }

  return { data: undefined };
};

export default webrtcDisconnectAllRoomsQuery;
