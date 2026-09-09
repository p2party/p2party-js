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
 */
export const applyRoomIceConfiguration = (
  peerConnections: readonly IRTCPeerConnection[],
  roomId: string,
  rtcConfig: RTCConfiguration,
  restartIceAfterApply = false,
  failurePolicy: "rollback" | "close" = "rollback",
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
        // generations. If authoritative restoration is impossible, remove
        // that transport and let normal room signaling recreate it.
        connection.close();
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
      for (const { connection } of snapshots) connection.close();
    else rollbackOrClose();
    throw error;
  }
  return live.length;
};
