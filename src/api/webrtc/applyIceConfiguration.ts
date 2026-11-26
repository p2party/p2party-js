import type { IRTCPeerConnection } from "./interfaces";

/**
 * How a transport that cannot hold the room's configuration is abandoned.
 * Production passes the shared edge teardown with the API's registry and
 * dispatch (src/api/webrtc/index.ts). It is passed in rather than imported so
 * this module stays a leaf: the teardown's module graph reaches the Redux
 * store at import time.
 */
export type RetireTransport = (connection: IRTCPeerConnection) => void;

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
 * A transport that cannot hold the authoritative configuration is handed to
 * `retire`, never just closed here: pc.close() fires no event, so nothing
 * else would wipe its ratchet and PQ state or stop its healing interval. It
 * stays registered, closed, for the next introduction or description to
 * retire and rebuild.
 */
export const applyRoomIceConfiguration = (
  peerConnections: readonly IRTCPeerConnection[],
  roomId: string,
  rtcConfig: RTCConfiguration,
  restartIceAfterApply: boolean,
  failurePolicy: "rollback" | "close",
  retire: RetireTransport,
): number => {
  const live = peerConnections.filter(
    (connection) =>
      connection.roomId === roomId &&
      connection.connectionState !== "closed" &&
      (connection.signalingState as string) !== "closed",
  );
  const iceServers = (rtcConfig.iceServers ?? []).map(cloneIceServer);

  // Every transport that must go is retired, even if retiring one throws: a
  // failed teardown is reported and the next connection is still torn down,
  // and the configuration error that started it stays the one thrown.
  const retireOne = (connection: IRTCPeerConnection): void => {
    try {
      retire(connection);
    } catch (retireError) {
      console.error(
        "p2party: could not retire a transport that cannot hold the room's ICE configuration",
        retireError,
      );
    }
  };
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
        retireOne(connection);
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
      for (const { connection } of snapshots) retireOne(connection);
    else rollbackOrClose();
    throw error;
  }
  return live.length;
};
