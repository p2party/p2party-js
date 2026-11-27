import {
  adoptRatchet,
  cloneRatchet,
  ratchetEncrypt,
  wipeRatchet,
} from "../cryptography/ratchet";
import { MAX_SKIP_SESSION } from "../utils/constants";
import {
  decryptMessageChunk,
  decryptMessageChunkClassicalOnlyForTests,
  messageCacheKey,
} from "./messageChunkCrypto";
import { parseChunkFrameHeader } from "./chunkFrame";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { PqMessageKeyContext } from "../cryptography/pqMessageKey";
import type { RatchetHeader, RatchetState } from "../cryptography/ratchet";
import type { DecryptedChunk } from "./messageChunkCrypto";

const edgeIdentityKey = (roomId: string, peerPublicKey: string): string =>
  `${roomId.length}:${roomId}${peerPublicKey.length}:${peerPublicKey}`;

// Only the current transport generation may publish a state transition.
const edgeOwnerTokens = new Map<string, symbol>();
const epcOwnerTokens = new WeakMap<IRTCPeerConnection, symbol>();

/** Claim this authenticated identity edge for its new transport generation. */
export const claimRatchetGeneration = (
  epc: IRTCPeerConnection,
  roomId: string,
): void => {
  const key = edgeIdentityKey(roomId, epc.withPeerPublicKey);
  const existing = epcOwnerTokens.get(epc);
  if (existing) {
    if (edgeOwnerTokens.get(key) !== existing)
      throw new Error("browser ratchet: stale connection cannot reclaim edge");
    return;
  }
  const token = Symbol(key);
  epcOwnerTokens.set(epc, token);
  edgeOwnerTokens.set(key, token);
};

/** Revocation is synchronous so queued work cannot reactivate a retired edge. */
export const releaseRatchetGeneration = (
  epc: IRTCPeerConnection,
  roomId: string,
): void => {
  const owner = epcOwnerTokens.get(epc);
  if (!owner) return;
  const key = edgeIdentityKey(roomId, epc.withPeerPublicKey);
  if (edgeOwnerTokens.get(key) === owner) edgeOwnerTokens.delete(key);
};

export const assertCurrentRatchetGeneration = (
  epc: IRTCPeerConnection,
  roomId: string,
): void => {
  const key = edgeIdentityKey(roomId, epc.withPeerPublicKey);
  const token = epcOwnerTokens.get(epc);
  if (!token || edgeOwnerTokens.get(key) !== token)
    throw new Error("browser ratchet: stale connection owner");
};

/** Optional instrumentation for testing staged transitions. */
export type RatchetTransitionHook = (
  state: RatchetState,
  roomId: string,
  peerPublicKey: string,
  peerId: string,
  edgeCryptoState?: Uint8Array | null,
) => Promise<void>;

// Serialize sends, receives and PQ transitions on the live transport so two
// concurrent operations cannot derive or publish from the same state.
const ratchetMutationTails = new WeakMap<IRTCPeerConnection, Promise<void>>();

export const withEdgeCryptoMutationLock = async <T>(
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
  /** True only when `candidate` contains a successor to adopt. */
  advanced: boolean;
  /** Optional diagnostic snapshot, evaluated only by an explicit test hook. */
  stageEdgeCryptoState?: () => Uint8Array;
  /** Publish non-ratchet side state (for example the message-key cache). */
  commit?: () => void;
  /** Erase staged side state if adoption cannot complete. */
  rollback?: () => void;
}

/** Stage a transition, recheck the live generation and adopt it before exposing its result. */
const mutateLiveRatchet = async <T>(
  epc: IRTCPeerConnection,
  roomId: string,
  stage: (candidate: RatchetState) => StagedRatchetMutation<T>,
  beforeCommit: RatchetTransitionHook | undefined,
  precondition?: { check: () => Promise<boolean>; skipped: T },
): Promise<T> =>
  withEdgeCryptoMutationLock(epc, async () => {
    if (precondition && !(await precondition.check()))
      return precondition.skipped;
    const requireOwner = !beforeCommit || epcOwnerTokens.has(epc);
    if (requireOwner) assertCurrentRatchetGeneration(epc, roomId);
    const live = epc.ratchetState;
    if (!live) throw new Error("browser ratchet: no live ratchet state");

    const candidate = cloneRatchet(live);
    let staged: StagedRatchetMutation<T> | undefined;
    let adopted = false;
    try {
      staged = stage(candidate);
      if (staged.advanced) {
        if (beforeCommit) {
          const edgeCryptoState =
            staged.stageEdgeCryptoState?.() ??
            epc.pqHealingState?.serialize() ??
            null;
          try {
            await beforeCommit(
              candidate,
              roomId,
              epc.withPeerPublicKey,
              epc.withPeerId,
              edgeCryptoState,
            );
          } finally {
            edgeCryptoState?.fill(0);
          }
          if (requireOwner) assertCurrentRatchetGeneration(epc, roomId);
        }

        // Adoption and publication happen together in this turn.
        if (epc.ratchetState !== live)
          throw new Error("browser ratchet: live state changed");

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

// Edges a test explicitly allowed to send under raw classical ratchet keys.
// Production never adds to it (see allowClassicalOnlySendForTests).
const classicalOnlySendTestEdges = new WeakSet<IRTCPeerConnection>();

/**
 * TESTS ONLY. Lets `advanceSendingRatchet` step this edge without an
 * installed PQ runtime; the step then returns a null PQ context, which only
 * `sealChunkClassicalOnlyForTests` accepts. Without this the step refuses
 * such an edge. tests/handlers/messageChunkCrypto.test.ts checks that no
 * production module calls it.
 */
export const allowClassicalOnlySendForTests = (
  epc: IRTCPeerConnection,
): void => {
  classicalOnlySendTestEdges.add(epc);
};

/**
 * Advance the sending chain exactly once before its key/header can be
 * used to build a frame. The returned message key remains caller-owned, as is
 * the returned OWNED copy of the current PQ message context. Capturing the
 * context and counting the application message happen inside the same edge
 * transaction as the ratchet step, so a concurrent PQ healing transition
 * cannot interleave.
 *
 * A live edge always installs its PQ runtime together with its ratchet
 * (`activateEdgeCrypto`), and every v4 message key is PQ-combined.
 * An edge with a ratchet but no PQ runtime therefore means that invariant
 * broke; the step rejects before touching the ratchet. The context is null
 * only for an edge a test opted in with `allowClassicalOnlySendForTests`.
 */
export const advanceSendingRatchet = async (
  epc: IRTCPeerConnection,
  roomId: string,
  module: LibCrypto,
  beforeCommit?: RatchetTransitionHook,
): Promise<{
  messageKey: Uint8Array;
  header: RatchetHeader;
  pqContext: PqMessageKeyContext | null;
}> =>
  mutateLiveRatchet(
    epc,
    roomId,
    (candidate) => {
      const pq = epc.pqHealingState;
      if (!pq && !classicalOnlySendTestEdges.has(epc))
        throw new Error(
          "browser ratchet: edge has no PQ runtime; refusing a classical-only encrypt",
        );
      const stepped = ratchetEncrypt(candidate, module);
      let pqContext: PqMessageKeyContext | null = null;
      if (pq) {
        const live = pq.currentMessageContext();
        pqContext = {
          rootKey: Uint8Array.from(live.rootKey),
          binding: Uint8Array.from(live.binding),
          rootSuite: live.rootSuite,
          epoch: live.epoch,
        };
      }
      return {
        value: {
          messageKey: stepped.messageKey,
          header: stepped.header,
          pqContext,
        },
        advanced: true,
        // One logical DR step == one application message toward the sparse
        // healing cadence — never one per chunk or retransmit round.
        commit: () => epc.pqHealingState?.noteApplicationMessage(),
        rollback: () => {
          stepped.messageKey.fill(0);
          pqContext?.rootKey.fill(0);
        },
      };
    },
    beforeCommit,
  );

// Edges a test explicitly allowed to receive under raw classical ratchet keys.
// Production never adds to it (see allowClassicalOnlyReceiveForTests).
const classicalOnlyReceiveTestEdges = new WeakSet<IRTCPeerConnection>();

/**
 * TESTS ONLY. Lets this edge receive without an installed PQ runtime, under
 * raw classical ratchet keys (`decryptMessageChunkClassicalOnlyForTests`),
 * with the classical key kept in the skipped map until retirement.
 * Without this, `decryptChunkWithLiveRatchet` refuses such an edge.
 * tests/handlers/messageChunkCrypto.test.ts checks that no production module
 * calls it.
 */
export const allowClassicalOnlyReceiveForTests = (
  epc: IRTCPeerConnection,
): void => {
  classicalOnlyReceiveTestEdges.add(epc);
};

/**
 * Decrypt one inbound chunk with a staged state/cache. An authenticated ratchet
 * advance is adopted before exposing decrypted bytes. A cache hit reuses the
 * message key held by this live generation.
 *
 * A live edge always installs its PQ runtime together with its ratchet
 * (`activateEdgeCrypto`), and every v4 message key is PQ-combined.
 * An edge with a ratchet but no PQ runtime therefore means that invariant
 * broke; the decrypt rejects before touching the ratchet rather than falling
 * back to the raw classical key.
 */
export const decryptChunkWithLiveRatchet = async (
  epc: IRTCPeerConnection,
  roomId: string,
  frame: Uint8Array,
  cache: Map<string, Uint8Array>,
  merkleRoot: Uint8Array,
  module: LibCrypto,
  beforeCommit?: RatchetTransitionHook,
): Promise<DecryptedChunk> =>
  mutateLiveRatchet(
    epc,
    roomId,
    (candidate) => {
      const pq = epc.pqHealingState;
      if (!pq && !classicalOnlyReceiveTestEdges.has(epc))
        throw new Error(
          "browser ratchet: edge has no PQ runtime; refusing a classical-only decrypt",
        );
      const { header, pqEpoch } = parseChunkFrameHeader(frame);
      const cacheKey = messageCacheKey(
        header.dhPub,
        header.N,
        pq ? pqEpoch : undefined,
      );
      const stagedCache = new Map(cache);
      const decrypted = pq
        ? decryptMessageChunk(
            candidate,
            frame,
            stagedCache,
            merkleRoot,
            module,
            (epoch: bigint): PqMessageKeyContext | null =>
              pq.resolveMessageContext(epoch),
          )
        : decryptMessageChunkClassicalOnlyForTests(
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
        throw new Error("browser ratchet: invalid staged receive cache");
      }

      if (pq) {
        // This epoch-bound key is already PQ-combined; keep it out of the
        // classical skipped-key collection.
        return {
          value: decrypted,
          advanced: true,
          stageEdgeCryptoState: () => pq.serialize(stagedCache),
          commit: () => {
            cache.set(cacheKey, stagedMessageKey);
            // One authenticated DR receive step == one application message
            // toward the sparse healing cadence.
            pq.noteApplicationMessage();
          },
          rollback: () => {
            stagedMessageKey.fill(0);
            decrypted.decrypted?.fill(0);
          },
        };
      }

      // A classical-only test edge keeps an independently owned skipped key.
      const skippedKey = Uint8Array.from(stagedMessageKey);
      candidate.skipped.set(cacheKey, skippedKey);
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
          skippedKey.fill(0);
          stagedMessageKey.fill(0);
          decrypted.decrypted?.fill(0);
        },
      };
    },
    beforeCommit,
  );

/**
 * Erase the active receive key when the atomic chunk manifest is complete.
 */
export const forgetReceiveMessageKeyIfCurrent = async (
  epc: IRTCPeerConnection,
  roomId: string,
  cache: Map<string, Uint8Array>,
  cacheKey: string,
  canRetire: (() => Promise<boolean>) | undefined,
  beforeCommit?: RatchetTransitionHook,
): Promise<boolean> =>
  mutateLiveRatchet(
    epc,
    roomId,
    (candidate) => {
      const pq = epc.pqHealingState;
      if (pq) {
        // A PQ-combined key belongs only to the live epoch-bound cache.
        if (!cache.has(cacheKey)) return { value: true, advanced: false };
        return {
          value: true,
          advanced: true,
          stageEdgeCryptoState: () => {
            const view = new Map(cache);
            view.delete(cacheKey);
            return pq.serialize(view);
          },
          commit: () => {
            cache.get(cacheKey)?.fill(0);
            cache.delete(cacheKey);
          },
        };
      }

      const skippedKey = candidate.skipped.get(cacheKey);
      if (skippedKey) {
        candidate.skipped.delete(cacheKey);
        skippedKey.fill(0);
      }
      return {
        value: true,
        advanced: skippedKey !== undefined,
        commit: () => {
          cache.get(cacheKey)?.fill(0);
          cache.delete(cacheKey);
        },
      };
    },
    beforeCommit,
    canRetire ? { check: canRetire, skipped: false } : undefined,
  );

export const forgetReceiveMessageKey = async (
  epc: IRTCPeerConnection,
  roomId: string,
  cache: Map<string, Uint8Array>,
  cacheKey: string,
  beforeCommit?: RatchetTransitionHook,
): Promise<void> => {
  await forgetReceiveMessageKeyIfCurrent(
    epc,
    roomId,
    cache,
    cacheKey,
    undefined,
    beforeCommit,
  );
};
