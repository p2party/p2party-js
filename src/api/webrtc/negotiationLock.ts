import { AsyncMutex } from "../../utils/mutex";

/**
 * Per-peer negotiation mutexes.
 *
 * Concurrent SDP/ICE signaling messages for the same peer can interleave
 * at `await` points, so `epc.signalingState` checks go stale and
 * `setRemoteDescription` gets called in the wrong state (e.g. "Failed to
 * set remote answer sdp: Called in wrong state: stable").
 *
 * Serializing description + candidate processing per peer guarantees that
 * for a given peerId the whole negotiation path runs strictly sequentially,
 * so state checks stay reliable. Different peers still negotiate in
 * parallel because each gets its own mutex.
 */
const peerMutexes = new Map<string, AsyncMutex>();

/**
 * Returns the AsyncMutex for the given peerId, creating one on first use.
 */
export const getPeerMutex = (peerId: string): AsyncMutex => {
  let mutex = peerMutexes.get(peerId);
  if (!mutex) {
    mutex = new AsyncMutex();
    peerMutexes.set(peerId, mutex);
  }

  return mutex;
};
