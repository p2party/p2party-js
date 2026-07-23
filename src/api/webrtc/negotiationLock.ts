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

const roomPeerKey = (roomId: string, peerId: string): string =>
  `${String(roomId.length)}:${roomId}${peerId}`;
const roomIdentityKey = (roomId: string, peerPublicKey: string): string =>
  `${String(roomId.length)}:${roomId}${peerPublicKey}`;

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
export const releaseRoomPeerMutex = (
  roomId: string,
  peerId: string,
): void => {
  const key = roomPeerKey(roomId, peerId);
  const mutex = roomPeerMutexes.get(key);
  if (!mutex) return;

  void (async () => {
    for (;;) {
      await mutex.whenIdle();
      if (!mutex.isIdle()) continue;
      if (roomPeerMutexes.get(key) === mutex) roomPeerMutexes.delete(key);
      return;
    }
  })();
};

/** Narrow test visibility without exposing the mutable registry. */
export const hasRoomPeerMutex = (roomId: string, peerId: string): boolean =>
  roomPeerMutexes.has(roomPeerKey(roomId, peerId));

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
  void mutex.whenIdle().then(() => {
    if (mutex.isIdle() && roomIdentityMutexes.get(key) === mutex)
      roomIdentityMutexes.delete(key);
  });
};
