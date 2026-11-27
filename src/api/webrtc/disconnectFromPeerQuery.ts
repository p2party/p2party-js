import {
  clearPeerHandshakeStatus,
  deleteChannel,
  deleteMessage,
  deletePeer,
} from "../../reducers/roomSlice";
import { wipeRatchet } from "../../cryptography/ratchet";
import { clearHandshakeChannel } from "../../handlers/handleHandshake";
import { destroyPqHealingOrchestrator } from "../../handlers/pqHealingOrchestrator";
import { releaseRatchetPersistence } from "../../handlers/ratchetPersist";
import { teardownCoverEdge } from "../../handlers/coverEdge";
import {
  isCurrentRatchetGateLease,
  rejectRatchetGate,
} from "../../handlers/ratchetGate";
import { releaseRoomPeerMutex } from "./negotiationLock";
import { discardPendingIceCandidates } from "./pendingIceCandidates";
import { clearRebindAuthenticationDeadline } from "./rebindDeadline";
import { retireRemoteTransport } from "./retiredRemoteTransports";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCIceCandidate,
  IRTCPeerConnection,
  RTCDisconnectFromPeerParams,
} from "./interfaces";
import type { State } from "../../store";

export interface RTCDisconnectFromPeerParamsExtension extends RTCDisconnectFromPeerParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  iceCandidates: IRTCIceCandidate[];
}

/**
 * Detach every handler from one data channel, release its queue accounting,
 * close it and drop it from the shared registry. A channel that is already
 * closed is released and unregistered but never closed again.
 */
const releaseDataChannel = (
  channel: IRTCDataChannel,
  dataChannels: IRTCDataChannel[],
): void => {
  channel.releaseProtocolResources?.();
  channel.onopen = null;
  channel.onclose = null;
  channel.onerror = null;
  channel.onclosing = null;
  channel.onmessage = null;
  channel.onbufferedamountlow = null;
  if (channel.readyState !== "closed") channel.close();
  const index = dataChannels.indexOf(channel);
  if (index > -1) dataChannels.splice(index, 1);
};

/** What a caller of the shared edge teardown can hand it. */
export interface EdgeTeardownContext {
  /**
   * The shared data-channel registry. A caller that does not hold it passes
   * none: the channels the connection references itself are still detached
   * and closed, and whatever else this room/peer has registered is
   * unregistered by the later teardown that retires the closed transport.
   */
  readonly dataChannels?: IRTCDataChannel[];
  /**
   * Redux dispatch. With it, the generation's non-failed handshake status is
   * cleared at once; without it, that happens when the closed transport is
   * retired.
   */
  readonly dispatch?: (
    action: ReturnType<typeof clearPeerHandshakeStatus>,
  ) => unknown;
}

/**
 * Release everything one transport generation of a room/peer edge owns, and
 * close it. This is the one teardown behind every path that abandons a
 * transport: `disconnectFromPeer` (and through it room leave, purge, the
 * grace-timer and ICE-failure teardowns and the certificate-change
 * replacement), the generation retire in baseQuery, a failed handshake and a
 * failed PQ healing exchange in handleOpenChannel, a failed transport
 * initialization in handleConnectToPeer, and an ICE configuration that could
 * not be applied or restored (applyIceConfiguration).
 *
 * It wipes the ratchet, the sparse-PQ runtime and the derived message keys,
 * stops the PQ healing interval, stops scheduled cover (which releases its
 * queued receipts), releases the generation's data channels and its re-bind
 * deadline, deletes the edge's persisted ratchet row while this connection
 * still owns it (releaseRatchetPersistence, ordered under the per-edge
 * persistence lock), clears its non-failed handshake status, detaches every
 * handler and closes the RTCPeerConnection. It does NOT remove the connection
 * from the registry or touch the roster: a caller that replaces the transport
 * and a terminal handshake failure (which leaves the closed transport
 * registered on purpose, C2) both need that left to them.
 *
 * State kept per ROOM/PEER rather than per connection (the ratchet gate, the
 * handshake inbox, the handshake status, the channels registered for this
 * room/peer) is released only while this connection still holds the current
 * gate lease. Once a replacement has claimed the gate, that state is the
 * replacement's, and a teardown that reaches a superseded generation late
 * releases only what the connection itself references. A connection without a
 * lease (it never claimed one) keeps the force-teardown behaviour.
 *
 * Idempotent: a second call finds nothing left to release.
 */
export const teardownEdgeGeneration = (
  connection: IRTCPeerConnection,
  { dataChannels = [], dispatch }: EdgeTeardownContext = {},
): void => {
  const { roomId, withPeerId: peerId } = connection;
  const ownsRoomPeerState =
    connection.ratchetGateLease === undefined ||
    isCurrentRatchetGateLease(roomId, peerId, connection.ratchetGateLease);

  // The wrapped row on disk goes with the generation that wrote it. Its own
  // ownership check (not the gate lease) decides: only the connection that
  // currently owns the edge's row deletes it, so a late teardown never
  // removes a replacement's seed.
  void releaseRatchetPersistence(connection, roomId).catch((error: unknown) => {
    console.error(
      "p2party: could not delete a retired edge's persisted ratchet",
      error,
    );
  });

  // This side stops believing in the remote transport this connection was
  // bound to. The peer may still hold it (its ICE consent survived a freeze
  // this side gave up on) and answer an offer it queued before the
  // teardown; that answer would otherwise land on the replacement
  // transport, which has no remote description to compare a fingerprint
  // against, and bind it to a certificate we just retired. An offer from
  // the same transport is still accepted — it proves the peer negotiates
  // there — and un-retires it (see retiredRemoteTransports).
  retireRemoteTransport(roomId, peerId, connection.remoteDescription?.sdp);

  if (ownsRoomPeerState) {
    const teardownError = new Error(
      `Room/peer transport closed (${roomId}, ${peerId})`,
    );
    clearHandshakeChannel(roomId, peerId, teardownError);
    rejectRatchetGate(roomId, peerId, teardownError);
    dispatch?.(clearPeerHandshakeStatus({ roomId, peerId }));
  }
  if (connection.ratchetState) {
    wipeRatchet(connection.ratchetState);
    connection.ratchetState = undefined;
  }
  // Stop scheduled cover first: its timers and lane channels must not fire
  // against a torn-down edge, and any queued scheduled receipts are wiped
  // (teardownCoverEdge releases them itself).
  teardownCoverEdge(connection);
  // Destroy the sparse-PQ runtime with the ratchet: its machine, message
  // root, sealed outbox, replay/ACK caches, and active combined receive keys
  // are all wiped by destroy(). The edge serializer hook dies with it so a
  // late persistence call cannot serialize a destroyed runtime. The
  // orchestrator's timers and admission gate die first.
  destroyPqHealingOrchestrator(connection);
  if (connection.pqHealingState) {
    connection.pqHealingState.destroy();
    connection.pqHealingState = undefined;
  }
  connection.serializeEdgeCryptoState = undefined;
  if (connection.messageKeyCache) {
    for (const messageKey of connection.messageKeyCache.values())
      messageKey.fill(0);
    connection.messageKeyCache.clear();
    connection.messageKeyCache = undefined;
  }
  connection.messageKeyByMerkleRoot?.clear();
  connection.messageKeyByMerkleRoot = undefined;

  // The generation's channels: the ones it references itself, plus, while it
  // still owns the edge, everything registered for this room/peer (a cover
  // lane mid-close, a channel whose own accounting already let go of it).
  // Their handlers are detached BEFORE anything closes: a retired main's
  // close or error handler would otherwise run disconnectFromPeer against
  // whatever owns the edge by the time the event is delivered.
  const channels = new Set<IRTCDataChannel>(connection.messageChannels);
  if (connection.mainChannel) channels.add(connection.mainChannel);
  if (ownsRoomPeerState)
    for (const channel of dataChannels)
      if (channel.withPeerId === peerId && channel.roomIds.includes(roomId))
        channels.add(channel);
  for (const channel of channels) releaseDataChannel(channel, dataChannels);
  connection.messageChannels?.clear();
  connection.messageChannels = undefined;
  connection.mainChannel = undefined;

  // A transport being torn down here can carry an armed in-place re-bind
  // deadline (remoteTransportChange). Release it with everything else this
  // connection owns: the edge is going away now, and the deadline's own job
  // — tearing it down and re-dialling — is exactly what is happening.
  clearRebindAuthenticationDeadline(connection);
  connection.clearTransportTimers?.();
  connection.clearTransportTimers = undefined;
  connection.resumeDeferredNegotiation = undefined;

  connection.ontrack = null;
  connection.ondatachannel = null;
  connection.onicecandidate = null;
  connection.onicecandidateerror = null;
  connection.onnegotiationneeded = null;
  connection.onsignalingstatechange = null;
  connection.onconnectionstatechange = null;
  connection.onicegatheringstatechange = null;
  connection.oniceconnectionstatechange = null;
  if (connection.connectionState !== "closed") connection.close();
};

const webrtcDisconnectPeerQuery: BaseQueryFn<
  RTCDisconnectFromPeerParamsExtension,
  undefined
> = (
  {
    peerId,
    roomId,
    expectedPeerPublicKey,
    alsoDeleteData,
    peerConnections,
    dataChannels,
    iceCandidates,
  },
  api,
) => {
  if (expectedPeerPublicKey !== undefined) {
    const live = peerConnections.find(
      (entry) => entry.roomId === roomId && entry.withPeerId === peerId,
    );
    if (live?.withPeerPublicKey !== expectedPeerPublicKey)
      return { data: undefined };
  }
  const terminalRoomIds = new Set<string>();
  for (let i = peerConnections.length - 1; i >= 0; i--) {
    const connection = peerConnections[i];
    if (
      connection.withPeerId !== peerId ||
      (roomId !== undefined && connection.roomId !== roomId)
    )
      continue;
    terminalRoomIds.add(connection.roomId);
    teardownEdgeGeneration(connection, {
      dataChannels,
      dispatch: api.dispatch,
    });
    peerConnections.splice(i, 1);
  }

  if (roomId !== undefined) terminalRoomIds.add(roomId);
  for (const terminalRoomId of terminalRoomIds) {
    discardPendingIceCandidates(iceCandidates, terminalRoomId, peerId);
    releaseRoomPeerMutex(terminalRoomId, peerId);
  }

  // Omitting roomId is the explicitly peer-wide operation.
  api.dispatch(deletePeer({ peerId, roomId }));
  api.dispatch(deleteChannel({ peerId, roomId }));

  // Channels of this peer that no registered transport claimed (each
  // transport's own were released with it above). Omitting roomId sweeps
  // every room.
  for (let i = dataChannels.length - 1; i >= 0; i--) {
    const channel = dataChannels[i];
    if (
      channel.withPeerId !== peerId ||
      (roomId !== undefined && !channel.roomIds.includes(roomId))
    )
      continue;
    releaseDataChannel(channel, dataChannels);
  }

  if (alsoDeleteData) {
    const { rooms } = api.getState() as State;
    const roomsLen = rooms.length;
    for (let i = 0; i < roomsLen; i++) {
      if (roomId !== undefined && rooms[i].id !== roomId) continue;

      const messagesLen = rooms[i].messages.length;
      for (let j = 0; j < messagesLen; j++) {
        if (rooms[i].messages[j].fromPeerId === peerId) {
          api.dispatch(
            deleteMessage({
              roomId: rooms[i].id,
              merkleRootHex: rooms[i].messages[j].merkleRootHex,
            }),
          );
        }
      }
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectPeerQuery;
