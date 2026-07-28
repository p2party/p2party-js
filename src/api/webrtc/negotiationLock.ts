import { AsyncMutex } from "../../utils/mutex";

/**
 * Per-room/peer negotiation mutexes.
 *
 * Concurrent SDP/ICE signaling messages for the same transport can interleave
 * at `await` points, so `epc.signalingState` checks go stale and
 * `setRemoteDescription` gets called in the wrong state (e.g. "Failed to
 * set remote answer sdp: Called in wrong state: stable").
 *
 * A peer can participate in multiple rooms at once, and each room/peer pair
 * has its own RTCPeerConnection. Those independent negotiations must not block
 * one another, so the room is part of the mutex identity.
 */
const roomPeerMutexes = new Map<string, AsyncMutex>();
const roomIdentityMutexes = new Map<string, AsyncMutex>();
const roomIceConfigurationMutexes = new Map<string, AsyncMutex>();
const roomResponseCommitMutex = new AsyncMutex();

const roomPeerKey = (roomId: string, peerId: string): string =>
  `${String(roomId.length)}:${roomId}${peerId}`;
const roomIdentityKey = (roomId: string, peerPublicKey: string): string =>
  `${String(roomId.length)}:${roomId}${peerPublicKey}`;

const releaseMutexWhenIdle = (
  registry: Map<string, AsyncMutex>,
  key: string,
  mutex: AsyncMutex,
): void => {
  void (async () => {
    for (;;) {
      await mutex.whenIdle();
      if (!mutex.isIdle()) continue;
      if (registry.get(key) === mutex) registry.delete(key);
      return;
    }
  })();
};

export const getRoomPeerMutex = (
  roomId: string,
  peerId: string,
): AsyncMutex => {
  const key = roomPeerKey(roomId, peerId);
  let mutex = roomPeerMutexes.get(key);
  if (!mutex) {
    mutex = new AsyncMutex();
    roomPeerMutexes.set(key, mutex);
  }

  return mutex;
};

/**
 * Forget a terminal edge only after its current owner and queued signaling
 * operations drain. Deleting a locked mutex would permit a second instance to
 * enter the same critical section concurrently.
 */
export const releaseRoomPeerMutex = (roomId: string, peerId: string): void => {
  const key = roomPeerKey(roomId, peerId);
  const mutex = roomPeerMutexes.get(key);
  if (!mutex) return;

  releaseMutexWhenIdle(roomPeerMutexes, key, mutex);
};

/**
 * Serialize one negotiation operation and release its registry key once every
 * queued owner drains. This must wrap nonterminal frames too: otherwise valid
 * unknown-peer SDP/ICE identifiers can grow the mutex registry forever.
 */
export const runRoomPeerExclusive = async <T>(
  roomId: string,
  peerId: string,
  operation: () => Promise<T>,
): Promise<T> => {
  const mutex = getRoomPeerMutex(roomId, peerId);
  try {
    return await mutex.runExclusive(operation);
  } finally {
    releaseRoomPeerMutex(roomId, peerId);
  }
};

/** Narrow test visibility without exposing the mutable registry. */
export const hasRoomPeerMutex = (roomId: string, peerId: string): boolean =>
  roomPeerMutexes.has(roomPeerKey(roomId, peerId));

/** Narrow test visibility without exposing the mutable registry. */
export const roomPeerMutexCount = (): number => roomPeerMutexes.size;

export const getRoomIdentityMutex = (
  roomId: string,
  peerPublicKey: string,
): AsyncMutex => {
  const key = roomIdentityKey(roomId, peerPublicKey);
  let mutex = roomIdentityMutexes.get(key);
  if (!mutex) {
    mutex = new AsyncMutex();
    roomIdentityMutexes.set(key, mutex);
  }
  return mutex;
};

export const releaseRoomIdentityMutex = (
  roomId: string,
  peerPublicKey: string,
): void => {
  const key = roomIdentityKey(roomId, peerPublicKey);
  const mutex = roomIdentityMutexes.get(key);
  if (!mutex) return;
  releaseMutexWhenIdle(roomIdentityMutexes, key, mutex);
};

/**
 * Serializes caller configuration mutation and a room-response live sweep +
 * Redux publication with the final configuration read, construction, and
 * registry insertion of a new PC. The key is the stable room URL, including
 * while the room is still awaiting its server-assigned id.
 */
export const getRoomIceConfigurationMutex = (roomUrl: string): AsyncMutex => {
  let mutex = roomIceConfigurationMutexes.get(roomUrl);
  if (!mutex) {
    mutex = new AsyncMutex();
    roomIceConfigurationMutexes.set(roomUrl, mutex);
  }
  return mutex;
};

export const releaseRoomIceConfigurationMutex = (roomUrl: string): void => {
  const mutex = roomIceConfigurationMutexes.get(roomUrl);
  if (!mutex) return;
  releaseMutexWhenIdle(roomIceConfigurationMutexes, roomUrl, mutex);
};

/** Narrow test visibility without exposing the mutable registry. */
export const hasRoomIceConfigurationMutex = (roomUrl: string): boolean =>
  roomIceConfigurationMutexes.has(roomUrl);

/**
 * Server-assigned room ids are globally unique, so validation, live apply, and
 * publication of assignments must be one global transaction. Room responses
 * are rare; serializing them is simpler and safer than multi-key lock ordering.
 */
export const runRoomResponseCommitExclusive = <T>(
  operation: () => Promise<T>,
): Promise<T> => roomResponseCommitMutex.runExclusive(operation);
