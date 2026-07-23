import { serializeRatchet } from "../cryptography/ratchet";
import { setRatchetSession } from "../db/api";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { RatchetSession } from "../db/types";

// Persist the peer's LIVE ratchet state (`epc.ratchetState`) to IndexedDB after
// it advances (send: the sending chain stepped once for a message; receive: a
// DH/receiving step). Built from the PLAINTEXT `serializeRatchet` output — the DB
// worker's fnSetRatchetSession wraps the secret fields exactly once (wrapping here
// too would double-wrap into an unreadable session). Keyed to the STABLE identity
// edge (roomId, peerPublicKey) so it survives reconnect/reload, exactly like the
// handshake seed (handleHandshake.ts). Unlike the handshake, `skippedMessageKeys`
// is carried through (the receive ratchet may have stashed out-of-order keys).
export const persistRatchetSession = async (
  epc: IRTCPeerConnection,
  roomId: string,
): Promise<void> => {
  if (!epc.ratchetState) return;
  const s = serializeRatchet(epc.ratchetState);
  const session: RatchetSession = {
    roomId: roomId || epc.session?.roomId || epc.rooms[0]?.roomId || "",
    peerPublicKey: epc.withPeerPublicKey,
    peerId: epc.withPeerId,
    rootKey: s.rootKey,
    sendingChainKey: s.sendingChainKey,
    receivingChainKey: s.receivingChainKey,
    dhSelfPub: s.dhSelfPub,
    dhSelfSec: s.dhSelfSec,
    dhRemotePub: s.dhRemotePub,
    Ns: s.Ns,
    Nr: s.Nr,
    PN: s.PN,
    skippedMessageKeys: s.skippedMessageKeys,
    updatedAt: Date.now(),
  };
  await setRatchetSession(session);
  epc.session = session;
};
