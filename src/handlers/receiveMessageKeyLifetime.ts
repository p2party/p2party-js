import {
  forgetReceiveMessageKey,
  forgetReceiveMessageKeyIfCurrent,
} from "./ratchetPersist";
import { isRatchetGateOpen } from "./ratchetGate";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { MessageData } from "../db/types";

const bindingRevisions = new WeakMap<IRTCPeerConnection, Map<string, symbol>>();

type ForgetReceiveMessageKey = typeof forgetReceiveMessageKey;
type ReceiveProgress = Pick<MessageData, "savedSize" | "totalSize">;
const retirements = new WeakMap<
  IRTCPeerConnection,
  Map<string, Promise<boolean>>
>();

/**
 * Bind the authenticated transfer root to the receive-ratchet key used by all
 * of its cells. Completion of the real bytes does not end this lifetime: valid
 * padded/cover cells may still be draining from an unordered data channel.
 */
export const bindReceiveMessageKey = (
  epc: IRTCPeerConnection,
  merkleRootHex: string,
  cacheKey: string,
): void => {
  epc.messageKeyByMerkleRoot ??= new Map<string, string>();
  epc.messageKeyByMerkleRoot.set(merkleRootHex, cacheKey);
  let revisions = bindingRevisions.get(epc);
  if (!revisions) {
    revisions = new Map();
    bindingRevisions.set(epc, revisions);
  }
  revisions.set(merkleRootHex, Symbol("receive-binding"));
  // Bound stale revision metadata when the receive-cache eviction path removed
  // mappings directly. Live mappings are already limited by its key budget.
  if (revisions.size > epc.messageKeyByMerkleRoot.size + 16)
    for (const root of revisions.keys())
      if (!epc.messageKeyByMerkleRoot.has(root)) revisions.delete(root);
};

const isComplete = (progress: ReceiveProgress | undefined): boolean =>
  progress !== undefined &&
  Number.isSafeInteger(progress.savedSize) &&
  Number.isSafeInteger(progress.totalSize) &&
  progress.savedSize >= 0 &&
  progress.totalSize > 0 &&
  progress.savedSize === progress.totalSize;

/**
 * Retire the live message key before releasing its transfer-root binding.
 */
export const forgetMappedReceiveMessageKey = async (
  epc: IRTCPeerConnection,
  roomId: string,
  merkleRootHex: string,
  forget: ForgetReceiveMessageKey = forgetReceiveMessageKey,
): Promise<boolean> => {
  let connectionRetirements = retirements.get(epc);
  const existing = connectionRetirements?.get(merkleRootHex);
  if (existing) return existing;

  const retirement = (async (): Promise<boolean> => {
    const cacheKey = epc.messageKeyByMerkleRoot?.get(merkleRootHex);
    const cache = epc.messageKeyCache;
    if (!cacheKey || !cache) return false;

    await forget(epc, roomId, cache, cacheKey);
    if (epc.messageKeyByMerkleRoot?.get(merkleRootHex) === cacheKey)
      epc.messageKeyByMerkleRoot.delete(merkleRootHex);
    return true;
  })();
  connectionRetirements ??= new Map<string, Promise<boolean>>();
  connectionRetirements.set(merkleRootHex, retirement);
  retirements.set(epc, connectionRetirements);

  try {
    return await retirement;
  } finally {
    if (connectionRetirements.get(merkleRootHex) === retirement)
      connectionRetirements.delete(merkleRootHex);
    if (connectionRetirements.size === 0) retirements.delete(epc);
  }
};

/**
 * A normal channel close retires a receive key only after its queue drained and
 * the durable manifest confirms all real bytes. Incomplete transfers retain
 * their key so a failed transport can resume; explicit cancel uses the
 * unconditional helper above.
 */
export const forgetCompletedReceiveMessageKey = async (
  epc: IRTCPeerConnection,
  roomId: string,
  merkleRootHex: string,
  progress: ReceiveProgress | undefined,
  forget: ForgetReceiveMessageKey = forgetReceiveMessageKey,
): Promise<boolean> => {
  if (!isComplete(progress)) return false;
  return forgetMappedReceiveMessageKey(epc, roomId, merkleRootHex, forget);
};

/** Capture BEFORE expiry touches storage; a later receive may reuse the root. */
export const captureReceiveMessageKey = (
  epc: IRTCPeerConnection,
  merkleRootHex: string,
) => {
  const roomId = epc.roomId;
  const peerId = epc.withPeerId;
  const gate = epc.ratchetGateLease;
  const ratchet = epc.ratchetState;
  const cache = epc.messageKeyCache;
  const cacheKey = epc.messageKeyByMerkleRoot?.get(merkleRootHex);
  const messageKey = cacheKey ? cache?.get(cacheKey) : undefined;
  const revision = bindingRevisions.get(epc)?.get(merkleRootHex);
  if (!gate || !ratchet || !cache || !cacheKey || !messageKey) return undefined;
  const sameBinding = () =>
    epc.roomId === roomId &&
    epc.withPeerId === peerId &&
    epc.ratchetGateLease === gate &&
    isRatchetGateOpen(roomId, peerId, gate) &&
    epc.ratchetState === ratchet &&
    epc.messageKeyCache === cache &&
    epc.messageKeyByMerkleRoot?.get(merkleRootHex) === cacheKey &&
    bindingRevisions.get(epc)?.get(merkleRootHex) === revision;
  const isCurrent = () => sameBinding() && cache.get(cacheKey) === messageKey;
  const clearBinding = () => {
    if (sameBinding()) {
      epc.messageKeyByMerkleRoot?.delete(merkleRootHex);
      bindingRevisions.get(epc)?.delete(merkleRootHex);
    }
  };
  return {
    epc,
    roomId,
    peerId,
    merkleRootHex,
    cache,
    cacheKey,
    isCurrent,
    clearBinding,
  };
};

export type ReceiveMessageKeySnapshot = NonNullable<
  ReturnType<typeof captureReceiveMessageKey>
>;

/** Absence and generation checks execute INSIDE the crypto mutation lock. */
export const forgetExpiredReceiveMessageKey = async (
  snapshot: ReceiveMessageKeySnapshot,
  stillAbsent: () => Promise<boolean>,
  forget = forgetReceiveMessageKeyIfCurrent,
): Promise<boolean> => {
  if (!snapshot.isCurrent()) return false;
  const retired = await forget(
    snapshot.epc,
    snapshot.roomId,
    snapshot.cache,
    snapshot.cacheKey,
    async () => (await stillAbsent()) && snapshot.isCurrent(),
  );
  if (retired) snapshot.clearBinding();
  return retired;
};
