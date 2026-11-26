import { teardownEdgeGeneration } from "./disconnectFromPeerQuery";

import type { EdgeTeardownContext } from "./disconnectFromPeerQuery";
import type { IRTCPeerConnection } from "./interfaces";

const cloneIceServer = (server: RTCIceServer): RTCIceServer => ({
  ...server,
  urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
});

const hasStartedNegotiation = (connection: IRTCPeerConnection): boolean =>
  connection.localDescription != null || connection.remoteDescription != null;

/**
 * Apply the room's current effective ICE servers to every live transport.
 *
 * getConfiguration() preserves construction-time WebRTC options that browsers
 * do not allow setConfiguration() to change. Only the refreshable ICE list is
 * replaced.
 *
 * A transport that cannot hold the authoritative configuration is retired
 * through the shared edge teardown, never just closed: pc.close() fires no
 * event, so until something retires the closed transport nothing would wipe
 * its ratchet and PQ state or stop its healing interval. It stays registered,
 * closed, for the next introduction or description to retire and rebuild.
 * `teardown` carries the registry and dispatch for that teardown when the
 * caller holds them.
 */
export const applyRoomIceConfiguration = (
  peerConnections: readonly IRTCPeerConnection[],
  roomId: string,
  rtcConfig: RTCConfiguration,
  restartIceAfterApply = false,
  failurePolicy: "rollback" | "close" = "rollback",
  teardown: EdgeTeardownContext = {},
): number => {
  const live = peerConnections.filter(
    (connection) =>
      connection.roomId === roomId &&
      connection.connectionState !== "closed" &&
      (connection.signalingState as string) !== "closed",
  );
  const iceServers = (rtcConfig.iceServers ?? []).map(cloneIceServer);
  const snapshots = live.map((connection) => ({
    connection,
    configuration: connection.getConfiguration(),
  }));

  const rollbackOrClose = (): void => {
    for (const { connection, configuration } of snapshots) {
      try {
        connection.setConfiguration(configuration);
        if (restartIceAfterApply && hasStartedNegotiation(connection))
          connection.restartIce();
      } catch {
        // A room must never retain a mixture of old and new relay
        // generations. If authoritative restoration is impossible, retire
        // that transport and let normal room signaling recreate it.
        teardownEdgeGeneration(connection, teardown);
      }
    }
  };

  try {
    for (const { connection, configuration } of snapshots) {
      connection.setConfiguration({
        ...configuration,
        iceServers: iceServers.map(cloneIceServer),
      });
    }
    if (restartIceAfterApply)
      for (const { connection } of snapshots)
        if (hasStartedNegotiation(connection)) connection.restartIce();
  } catch (error) {
    if (failurePolicy === "close")
      for (const { connection } of snapshots)
        teardownEdgeGeneration(connection, teardown);
    else rollbackOrClose();
    throw error;
  }
  return live.length;
};
