import { wipeRatchet } from "../../cryptography/ratchet";
import { clearHandshakeChannel } from "../../handlers/handleHandshake";
import { destroyPqHealingOrchestrator } from "../../handlers/pqHealingOrchestrator";
import { releaseScheduledReceipts } from "../../handlers/coverTransfer";
import { teardownCoverEdge } from "../../handlers/coverEdge";
import { resetRatchetGate } from "../../handlers/ratchetGate";
import { setPeerHandshakeStatus } from "../../reducers/roomSlice";
import { parseFingerprintFromSdp } from "../../utils/sdpFingerprint";
import { debugLog } from "../../utils/debug";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCPeerConnection } from "./interfaces";

/**
 * True iff both SDPs declare a sha-256 DTLS fingerprint and the two differ.
 *
 * A remote description whose fingerprint differs from the one already applied
 * on this RTCPeerConnection means the peer built a NEW RTCPeerConnection (a
 * fresh DTLS certificate is minted per PC) while this side kept its old one.
 * The browser accepts the change and re-runs DTLS on the same PC, but every
 * piece of edge authentication this side holds — handshake transcript (which
 * binds both fingerprints), ratchet, PQ runtime, message keys — was proven
 * against the OLD certificate and must not survive onto the new transport.
 *
 * Missing or malformed fingerprints on either side are not a change: there is
 * nothing to compare, and the handshake itself rejects such SDPs later.
 */
export const detectRemoteTransportChange = (
  previousSdp: string | undefined,
  nextSdp: string,
): boolean => {
  if (previousSdp === undefined) return false;
  let previous: Uint8Array;
  let next: Uint8Array;
  try {
    previous = parseFingerprintFromSdp(previousSdp);
    next = parseFingerprintFromSdp(nextSdp);
  } catch {
    return false;
  }
  if (previous.length !== next.length) return true;
  for (let i = 0; i < previous.length; i++)
    if (previous[i] !== next[i]) return true;
  return false;
};

export interface ResetEdgeAuthenticationParams {
  epc: IRTCPeerConnection;
  roomId: string;
  peerId: string;
  api: Pick<BaseQueryApi, "dispatch">;
  reason: Error;
}

/**
 * Drop everything that authenticated this room/peer edge against the previous
 * remote DTLS certificate, WITHOUT tearing the RTCPeerConnection down.
 *
 * The PC itself survives: the browser renegotiates DTLS on it against the new
 * remote certificate, and the identity initiator then opens a fresh `main` on
 * this same PC so a new handshake binds the new fingerprint pair. The old
 * `main` is closed here; its onclose handler observes a stale gate lease
 * (replaced below) and returns early, so closing it never cascades into a
 * disconnectFromPeer of the edge we are keeping. Per-message channels are
 * left alone: they are gated on the ratchet lease and drain/close on their
 * own once their transfer settles or the lease check fails.
 */
export const resetEdgeAuthenticationForNewRemoteTransport = ({
  epc,
  roomId,
  peerId,
  api,
  reason,
}: ResetEdgeAuthenticationParams): void => {
  // Reject any in-flight handshake step on the old transcript first, then
  // replace the gate so every awaiter of the old authenticated state (sends,
  // receipt replay, message channels) fails over to the new attempt.
  clearHandshakeChannel(roomId, peerId, reason);
  epc.ratchetGateLease = resetRatchetGate(roomId, peerId, reason);

  // Same wipe order as disconnectFromPeerQuery: orchestrator timers die
  // before the PQ runtime, then the ratchet, then the derived caches.
  destroyPqHealingOrchestrator(epc);
  if (epc.pqHealingState) {
    epc.pqHealingState.destroy();
    epc.pqHealingState = undefined;
  }
  if (epc.ratchetState) {
    wipeRatchet(epc.ratchetState);
    epc.ratchetState = undefined;
  }
  if (epc.messageKeyCache) {
    for (const messageKey of epc.messageKeyCache.values()) messageKey.fill(0);
    epc.messageKeyCache.clear();
    epc.messageKeyCache = undefined;
  }
  epc.messageKeyByMerkleRoot?.clear();
  epc.messageKeyByMerkleRoot = undefined;
  epc.serializeEdgeCryptoState = undefined;
  teardownCoverEdge(epc);
  releaseScheduledReceipts(epc);

  const previousMain = epc.mainChannel;
  epc.mainChannel = undefined;
  if (previousMain && previousMain.readyState !== "closed")
    previousMain.close();

  api.dispatch(
    setPeerHandshakeStatus({ roomId, peerId, status: "authenticating" }),
  );
  debugLog(
    `Remote DTLS certificate changed for ${peerId} in ${roomId}; edge authentication reset`,
  );
};
