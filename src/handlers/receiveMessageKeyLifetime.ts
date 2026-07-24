import { forgetReceiveMessageKeyDurably } from "./ratchetPersist";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { MessageData } from "../db/types";

type ForgetReceiveMessageKey = typeof forgetReceiveMessageKeyDurably;
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
};

const isComplete = (progress: ReceiveProgress | undefined): boolean =>
  progress !== undefined &&
  Number.isSafeInteger(progress.savedSize) &&
  Number.isSafeInteger(progress.totalSize) &&
  progress.savedSize >= 0 &&
  progress.totalSize > 0 &&
  progress.savedSize === progress.totalSize;

/**
 * Durably retire the key mapped to one transfer. The root binding is removed
 * only after persistence succeeds, so failure leaves an idempotent retry path.
 */
export const forgetMappedReceiveMessageKey = async (
  epc: IRTCPeerConnection,
  roomId: string,
  merkleRootHex: string,
  forget: ForgetReceiveMessageKey = forgetReceiveMessageKeyDurably,
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
  forget: ForgetReceiveMessageKey = forgetReceiveMessageKeyDurably,
): Promise<boolean> => {
  if (!isComplete(progress)) return false;
  return forgetMappedReceiveMessageKey(epc, roomId, merkleRootHex, forget);
};
