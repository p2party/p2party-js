import {
  adoptRatchet,
  cloneRatchet,
  ratchetEncrypt,
  serializeRatchet,
  wipeRatchet,
} from "../cryptography/ratchet";
import { deleteRatchetSession, setRatchetSession } from "../db/api";
import { MAX_SKIP_SESSION } from "../utils/constants";
import { decryptMessageChunk, messageCacheKey } from "./messageChunkCrypto";
import { parseChunkFrameHeader } from "./chunkFrame";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { RatchetSession } from "../db/types";
import type { RatchetHeader, RatchetState } from "../cryptography/ratchet";
import type { DecryptedChunk } from "./messageChunkCrypto";

const wipeSerializedSession = (session: RatchetSession): void => {
  new Uint8Array(session.rootKey).fill(0);
  if (session.sendingChainKey) new Uint8Array(session.sendingChainKey).fill(0);
  if (session.receivingChainKey)
    new Uint8Array(session.receivingChainKey).fill(0);
  new Uint8Array(session.dhSelfSec).fill(0);
  for (const skipped of session.skippedMessageKeys)
    new Uint8Array(skipped.messageKey).fill(0);
};

const persistenceKey = (roomId: string, peerPublicKey: string): string =>
  `${roomId.length}:${roomId}${peerPublicKey.length}:${peerPublicKey}`;

// Persistence must be ordered by the stable room/identity edge, not by one
// transient RTCPeerConnection. A replacement connection can exist while an old
// worker write is still in flight.
const edgePersistenceTails = new Map<string, Promise<void>>();
const edgeOwnerTokens = new Map<string, symbol>();
const epcOwnerTokens = new WeakMap<IRTCPeerConnection, symbol>();

const withEdgePersistenceLock = async <T>(
  roomId: string,
  peerPublicKey: string,
  operation: () => Promise<T>,
): Promise<T> => {
  const key = persistenceKey(roomId, peerPublicKey);
  const previous = edgePersistenceTails.get(key) ?? Promise.resolve();
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.catch(() => undefined).then(() => held);
  edgePersistenceTails.set(key, tail);
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release();
    if (edgePersistenceTails.get(key) === tail)
      edgePersistenceTails.delete(key);
  }
};

/**
 * Claim the stable persistence edge before a replacement handshake writes its
 * seed. The synchronous claim invalidates queued mutations from the old PC;
 * the edge-wide write lock ensures any already-running old write finishes
 * before the replacement seed is written last.
 */
export const claimRatchetPersistence = (
  epc: IRTCPeerConnection,
  roomId: string,
): void => {
  const key = persistenceKey(roomId, epc.withPeerPublicKey);
  const existing = epcOwnerTokens.get(epc);
  if (existing) {
    if (edgeOwnerTokens.get(key) !== existing)
      throw new Error(
        "ratchet persistence: stale connection cannot reclaim edge",
      );
    return;
  }
  const token = Symbol(key);
  epcOwnerTokens.set(epc, token);
  edgeOwnerTokens.set(key, token);
};

const assertCurrentPersistenceOwner = (
  epc: IRTCPeerConnection,
  roomId: string,
): void => {
  const key = persistenceKey(roomId, epc.withPeerPublicKey);
  const token = epcOwnerTokens.get(epc);
  if (!token || edgeOwnerTokens.get(key) !== token)
    throw new Error("ratchet persistence: stale connection owner");
};

/**
 * Persist one live ratchet state. The worker owns the at-rest wrapping; this
 * boundary owns and erases the plaintext serialization copy after postMessage
 * has completed.
 */
const persistRatchetStateUnlocked = async (
  state: RatchetState,
  roomId: string,
  peerPublicKey: string,
  peerId: string,
): Promise<void> => {
  const s = serializeRatchet(state);
  const session: RatchetSession = {
    rootSuite: s.rootSuite,
    roomId,
    peerPublicKey,
    peerId,
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
  try {
    await setRatchetSession(session);
  } finally {
    wipeSerializedSession(session);
  }
};

export const persistRatchetState = async (
  state: RatchetState,
  roomId: string,
  peerPublicKey: string,
  peerId: string,
): Promise<void> =>
  withEdgePersistenceLock(roomId, peerPublicKey, () =>
    persistRatchetStateUnlocked(state, roomId, peerPublicKey, peerId),
  );

export const persistClaimedRatchetState = async (
  epc: IRTCPeerConnection,
  state: RatchetState,
  roomId: string,
): Promise<void> =>
  withEdgePersistenceLock(roomId, epc.withPeerPublicKey, async () => {
    assertCurrentPersistenceOwner(epc, roomId);
    await persistRatchetStateUnlocked(
      state,
      roomId,
      epc.withPeerPublicKey,
      epc.withPeerId,
    );
    assertCurrentPersistenceOwner(epc, roomId);
  });

type PersistInitialRatchetState = (
  state: RatchetState,
  roomId: string,
  peerPublicKey: string,
  peerId: string,
) => Promise<void>;

type RollbackInitialRatchetState = (
  roomId: string,
  peerPublicKey: string,
) => Promise<void>;

/**
 * Atomically order the initial durable seed and its synchronous gate/RAM
 * activation under the stable-edge lock. If close/replacement settles the gate
 * while the worker write is in flight, delete that just-written seed before a
 * replacement is allowed to write. This prevents a never-established root from
 * being restored later.
 */
export const persistAndActivateClaimedRatchetState = async (
  epc: IRTCPeerConnection,
  state: RatchetState,
  roomId: string,
  activate: () => void,
  persist: PersistInitialRatchetState = persistRatchetStateUnlocked,
  rollback: RollbackInitialRatchetState = deleteRatchetSession,
): Promise<void> =>
  withEdgePersistenceLock(roomId, epc.withPeerPublicKey, async () => {
    assertCurrentPersistenceOwner(epc, roomId);
    let writeStarted = false;
    try {
      writeStarted = true;
      await persist(state, roomId, epc.withPeerPublicKey, epc.withPeerId);
      assertCurrentPersistenceOwner(epc, roomId);
      // Must remain synchronous: resolving the gate schedules its waiters for
      // a later microtask, so activate can install epc.ratchetState in the
      // same stack before any queued channel resumes.
      activate();
    } catch (error) {
      if (writeStarted) {
        try {
          await rollback(roomId, epc.withPeerPublicKey);
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            "Ratchet establishment failed and persisted-seed rollback failed",
          );
        }
      }
      throw error;
    }
  });

export type PersistRatchetState = typeof persistRatchetState;

// Ratchet transitions contain an async durability boundary. Without a per-edge
// lock, two concurrent sends can clone the same state and derive the same
// message key, while concurrent send/receive writes can persist snapshots out
// of order. Keep the queue outside Redux/DB and key it by the live transport.
const ratchetMutationTails = new WeakMap<IRTCPeerConnection, Promise<void>>();

const withRatchetMutationLock = async <T>(
  epc: IRTCPeerConnection,
  mutation: () => Promise<T>,
): Promise<T> => {
  const previous = ratchetMutationTails.get(epc) ?? Promise.resolve();
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.catch(() => undefined).then(() => held);
  ratchetMutationTails.set(epc, tail);

  await previous.catch(() => undefined);
  try {
    return await mutation();
  } finally {
    release();
    if (ratchetMutationTails.get(epc) === tail)
      ratchetMutationTails.delete(epc);
  }
};

interface StagedRatchetMutation<T> {
  value: T;
  /** True only when `candidate` contains a successor that must be durable. */
  advanced: boolean;
  /** Publish non-ratchet side state (for example the message-key cache). */
  commit?: () => void;
  /** Erase staged side state if persistence/adoption cannot complete. */
  rollback?: () => void;
}

/**
 * Run one mutation as a write-ahead ratchet transaction:
 *
 *   clone live -> mutate clone -> persist clone -> adopt live -> publish cache
 *
 * No caller-observable ciphertext/plaintext is returned before the successor is
 * durable. A failed write leaves the live state untouched and erases staged
 * secrets. Successful persistence followed by an in-process failure may consume
 * one ratchet step without sending/delivering it; that is an availability loss,
 * but it fails closed and can never reuse a message key after restart.
 */
const mutateRatchetDurably = async <T>(
  epc: IRTCPeerConnection,
  roomId: string,
  stage: (candidate: RatchetState) => StagedRatchetMutation<T>,
  persist: PersistRatchetState,
): Promise<T> =>
  withRatchetMutationLock(epc, async () => {
    const live = epc.ratchetState;
    if (!live) throw new Error("ratchet persistence: no live ratchet state");

    const candidate = cloneRatchet(live);
    let staged: StagedRatchetMutation<T> | undefined;
    let adopted = false;
    try {
      staged = stage(candidate);
      if (staged.advanced) {
        if (persist === persistRatchetState) {
          await withEdgePersistenceLock(
            roomId,
            epc.withPeerPublicKey,
            async () => {
              assertCurrentPersistenceOwner(epc, roomId);
              if (epc.ratchetState !== live)
                throw new Error("ratchet persistence: live state changed");
              await persistRatchetStateUnlocked(
                candidate,
                roomId,
                epc.withPeerPublicKey,
                epc.withPeerId,
              );
              assertCurrentPersistenceOwner(epc, roomId);
            },
          );
        } else {
          await persist(
            candidate,
            roomId,
            epc.withPeerPublicKey,
            epc.withPeerId,
          );
        }

        // A connection teardown/handshake replacement must not let an old async
        // write overwrite a newly installed live handle.
        if (epc.ratchetState !== live)
          throw new Error("ratchet persistence: live state changed");

        adoptRatchet(live, candidate);
        adopted = true;
      } else {
        wipeRatchet(candidate);
      }

      staged.commit?.();
      return staged.value;
    } catch (error) {
      if (!adopted) wipeRatchet(candidate);
      staged?.rollback?.();
      throw error;
    }
  });

/**
 * Advance the sending chain exactly once, durably, before its key/header can be
 * used to build a frame. The returned message key remains caller-owned.
 */
export const ratchetEncryptDurably = async (
  epc: IRTCPeerConnection,
  roomId: string,
  module: LibCrypto,
  persist: PersistRatchetState = persistRatchetState,
): Promise<{ messageKey: Uint8Array; header: RatchetHeader }> =>
  mutateRatchetDurably(
    epc,
    roomId,
    (candidate) => {
      const stepped = ratchetEncrypt(candidate, module);
      return {
        value: stepped,
        advanced: true,
        rollback: () => stepped.messageKey.fill(0),
      };
    },
    persist,
  );

/**
 * Decrypt one inbound chunk with a staged state/cache. An authenticated ratchet
 * advance becomes visible only after its snapshot is durable; persistence
 * failure rejects without advancing live state, caching a key, or exposing the
 * decrypted bytes. Cache hits do not advance or persist the ratchet.
 */
export const decryptMessageChunkDurably = async (
  epc: IRTCPeerConnection,
  roomId: string,
  frame: Uint8Array,
  cache: Map<string, Uint8Array>,
  merkleRoot: Uint8Array,
  module: LibCrypto,
  persist: PersistRatchetState = persistRatchetState,
): Promise<DecryptedChunk> =>
  mutateRatchetDurably(
    epc,
    roomId,
    (candidate) => {
      const { header } = parseChunkFrameHeader(frame);
      const cacheKey = messageCacheKey(header.dhPub, header.N);
      const stagedCache = new Map(cache);
      const decrypted = decryptMessageChunk(
        candidate,
        frame,
        stagedCache,
        merkleRoot,
        module,
      );

      if (!decrypted.stateAdvanced)
        return { value: decrypted, advanced: false };

      const stagedMessageKey = stagedCache.get(cacheKey);
      if (!stagedMessageKey || cache.has(cacheKey)) {
        decrypted.decrypted?.fill(0);
        throw new Error("ratchet persistence: invalid staged receive cache");
      }

      // A logical message spans many independently delivered chunks. Retain an
      // independently owned copy in the persisted skipped-key map until the
      // authoritative chunk manifest completes. A restored state can therefore
      // rebuild the RAM cache and decrypt the remaining chunks; the live WebRTC
      // path must still load getRatchetSession on reconnect to use that ability.
      const durableMessageKey = Uint8Array.from(stagedMessageKey);
      candidate.skipped.set(cacheKey, durableMessageKey);
      while (candidate.skipped.size > MAX_SKIP_SESSION) {
        const oldest = candidate.skipped.keys().next().value as
          string | undefined;
        if (oldest === undefined) break;
        candidate.skipped.get(oldest)?.fill(0);
        candidate.skipped.delete(oldest);
      }

      return {
        value: decrypted,
        advanced: true,
        commit: () => cache.set(cacheKey, stagedMessageKey),
        rollback: () => {
          durableMessageKey.fill(0);
          stagedMessageKey.fill(0);
          decrypted.decrypted?.fill(0);
        },
      };
    },
    persist,
  );

/**
 * Durably retire the active receive key after the atomic chunk manifest reports
 * completion, then erase the RAM cache copy. If persistence fails, both copies
 * remain usable for an idempotent retransmit/retry rather than diverging.
 */
export const forgetReceiveMessageKeyDurably = async (
  epc: IRTCPeerConnection,
  roomId: string,
  cache: Map<string, Uint8Array>,
  cacheKey: string,
  persist: PersistRatchetState = persistRatchetState,
): Promise<void> =>
  mutateRatchetDurably(
    epc,
    roomId,
    (candidate) => {
      const durableMessageKey = candidate.skipped.get(cacheKey);
      if (durableMessageKey) {
        candidate.skipped.delete(cacheKey);
        durableMessageKey.fill(0);
      }
      return {
        value: undefined,
        advanced: durableMessageKey !== undefined,
        commit: () => {
          cache.get(cacheKey)?.fill(0);
          cache.delete(cacheKey);
        },
      };
    },
    persist,
  );

// Persist the peer's LIVE ratchet after it advances. The stable DB key is
// (roomId, peerPublicKey); peerId is reconnect-local metadata.
export const persistRatchetSession = async (
  epc: IRTCPeerConnection,
  roomId: string,
): Promise<void> => {
  if (!epc.ratchetState) return;
  await persistClaimedRatchetState(epc, epc.ratchetState, roomId);
};
