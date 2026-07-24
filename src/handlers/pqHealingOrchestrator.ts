import { PQ_HEAL_MAX_RETRIES } from "./pqHealingRuntime";
import { persistClaimedRatchetState } from "./ratchetPersist";
import { withEdgeCryptoMutationLock } from "./ratchetPersist";
import {
  hasQueuedEdgeReceiveWork,
  waitForEdgeReceiveQuiescence,
} from "./handleMessageQueueing";
import { WIRE_CHUNK_FRAME_LEN } from "../utils/constants";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { RatchetState } from "../cryptography/ratchet";
import type { SparsePqHealingState } from "./pqHealingRuntime";

// ── protocol-v4 live sparse-healing orchestrator ─────────────────────────────
//
// One orchestrator owns the WebRTC lifetime of one edge's SparsePqHealingState:
// due-time initiation, exact-frame retransmission, inbound OFFER/ADVANCE/ACK
// routing, and application-traffic admission. Every state transition follows
// the v4 edge-crypto transaction:
//
//   clone runtime → mutate/authenticate clone → persist ratchet + candidate
//   checkpoint in ONE row → adopt clone → dispatch exact bytes
//
// under the same per-edge mutation lock the message send/receive paths use, so
// a PQ transition can never interleave with a Double-Ratchet step. A storage
// failure destroys the clone and leaves the live runtime byte-identical; the
// next tick retries. Retry exhaustion and unauthenticated/forked control
// frames fail the authenticated edge — there is no fallback root, epoch, or
// suite.

/** Persist the (unchanged) live ratchet plus one candidate edge checkpoint. */
export type PersistEdgeCheckpoint = (
  epc: IRTCPeerConnection,
  state: RatchetState,
  roomId: string,
  serializeCandidate: () => Uint8Array,
) => Promise<void>;

export interface PqOrchestratorHooks {
  /** Dispatch one exact sealed control cell; false when the lane is not open. */
  readonly sendControlFrame: (frame: Uint8Array) => boolean;
  /** Fail/reconnect the authenticated edge (retry exhaustion, fork). */
  readonly failEdge: (reason: Error) => void;
  /** Injectable clock for deterministic tests. */
  readonly now?: () => number;
  /** Injectable persistence for fault-injection tests. */
  readonly persistEdge?: PersistEdgeCheckpoint;
  /** Tick cadence for the due/retry timer; 0 disables the interval (tests). */
  readonly tickMs?: number;
}

interface OrchestratorState {
  readonly roomId: string;
  readonly hooks: PqOrchestratorHooks;
  readonly now: () => number;
  readonly persistEdge: PersistEdgeCheckpoint;
  interval: ReturnType<typeof setInterval> | null;
  /** Serializes orchestrator-level operations (tick vs inbound frame). */
  busy: boolean;
  /** An inbound control frame arrived; block new app sends until processed. */
  inboundBlocked: boolean;
  destroyed: boolean;
  failed: boolean;
}

const orchestrators = new WeakMap<IRTCPeerConnection, OrchestratorState>();

const DEFAULT_TICK_MS = 1_000;

const defaultPersistEdge: PersistEdgeCheckpoint = (
  epc,
  state,
  roomId,
  serializeCandidate,
) => persistClaimedRatchetState(epc, state, roomId, serializeCandidate);

const fail = (message: string): never => {
  throw new Error(`pqHealingOrchestrator: ${message}`);
};

/**
 * A durable-write failure is transient: the live runtime is byte-identical and
 * the exchange recovers through the peer's (or our own) exact retransmit. It
 * must never be classified as a protocol fork.
 */
class PqPersistenceError extends Error {
  constructor(cause: unknown) {
    super("pqHealingOrchestrator: edge checkpoint persistence failed", {
      cause,
    });
    this.name = "PqPersistenceError";
  }
}

/**
 * True while new application sends must not derive a message key on this edge:
 * either the runtime's machine is mid-exchange, or an inbound control frame is
 * being processed and the local gate has already closed.
 */
export const isPqApplicationTrafficBlocked = (
  epc: IRTCPeerConnection,
): boolean => {
  const state = orchestrators.get(epc);
  if (state && (state.inboundBlocked || state.failed)) return true;
  return epc.pqHealingState?.trafficBlocked ?? false;
};

/**
 * Local initiation waits for a quiescent transfer boundary: no live
 * per-message channels and no queued/in-flight inbound frames on the edge.
 */
const isEdgeQuiescentForHealing = (
  epc: IRTCPeerConnection,
  roomId: string,
): boolean =>
  (epc.messageChannels?.size ?? 0) === 0 &&
  !hasQueuedEdgeReceiveWork(roomId, epc.withPeerId);

/**
 * Run one durable PQ transition. `mutate` receives the CLONE and returns the
 * exact cell(s) to dispatch after adoption (empty for no-op transitions).
 * Duplicate responses (mutate returns `dispatch` with `persist: false`) are
 * sent without a write, exactly as persisted earlier.
 */
const mutatePqDurably = async (
  epc: IRTCPeerConnection,
  state: OrchestratorState,
  mutate: (
    candidate: SparsePqHealingState,
  ) => Promise<{ dispatch: Uint8Array | null; persist: boolean }>,
): Promise<void> =>
  withEdgeCryptoMutationLock(epc, async () => {
    const live = epc.pqHealingState;
    const ratchet = epc.ratchetState;
    if (!live || !ratchet)
      return fail("edge has no live PQ runtime or ratchet");

    const candidate = live.clone();
    let outcome: { dispatch: Uint8Array | null; persist: boolean };
    try {
      outcome = await mutate(candidate);
      if (outcome.persist) {
        try {
          await state.persistEdge(epc, ratchet, state.roomId, () =>
            candidate.serialize(),
          );
        } catch (persistError) {
          throw new PqPersistenceError(persistError);
        }
        if (epc.pqHealingState !== live)
          throw new PqPersistenceError(
            new Error("live PQ runtime changed during persistence"),
          );
        live.adopt(candidate);
        // adopt() moves the clone's active-key map INTO the live runtime, so
        // the per-edge cache alias must follow the new map object.
        epc.messageKeyCache = live.activeReceiveKeys;
      } else {
        candidate.destroy();
      }
    } catch (error) {
      candidate.destroy();
      throw error;
    }

    if (outcome.dispatch) {
      outcome.dispatch = Uint8Array.from(outcome.dispatch);
      if (!state.hooks.sendControlFrame(outcome.dispatch))
        // The lane is closed; the persisted outbox retries on a later tick or
        // on the replacement transport after a fresh handshake.
        outcome.dispatch.fill(0);
    }
  });

/**
 * Install the live orchestrator after a successful handshake has installed
 * `epc.pqHealingState`. Idempotent per connection: a replacement handshake on
 * the same connection object reuses the interval with the fresh runtime.
 */
export const installPqHealingOrchestrator = (
  epc: IRTCPeerConnection,
  roomId: string,
  hooks: PqOrchestratorHooks,
): void => {
  if (!epc.pqHealingState)
    fail("cannot install an orchestrator without a PQ runtime");
  destroyPqHealingOrchestrator(epc);
  const state: OrchestratorState = {
    roomId,
    hooks,
    now: hooks.now ?? Date.now,
    persistEdge: hooks.persistEdge ?? defaultPersistEdge,
    interval: null,
    busy: false,
    inboundBlocked: false,
    destroyed: false,
    failed: false,
  };
  orchestrators.set(epc, state);
  const tickMs = hooks.tickMs ?? DEFAULT_TICK_MS;
  if (tickMs > 0)
    state.interval = setInterval(() => {
      void tickPqHealing(epc);
    }, tickMs);
};

export const destroyPqHealingOrchestrator = (
  epc: IRTCPeerConnection,
): void => {
  const state = orchestrators.get(epc);
  if (!state) return;
  state.destroyed = true;
  if (state.interval !== null) clearInterval(state.interval);
  state.interval = null;
  orchestrators.delete(epc);
};

const failEdgeOnce = (state: OrchestratorState, reason: Error): void => {
  if (state.failed) return;
  state.failed = true;
  state.hooks.failEdge(reason);
};

/**
 * One due/retry pass. Retransmits the exact persisted control frame when its
 * 5-second deadline passed (durably counting the attempt first), fails the
 * edge after the 8-attempt budget, and starts a due local exchange only when
 * the stable role owns the turn and the edge is at a quiescent boundary.
 * Exported for deterministic tests; the installed interval calls it.
 */
export const tickPqHealing = async (
  epc: IRTCPeerConnection,
): Promise<void> => {
  const state = orchestrators.get(epc);
  const pq = epc.pqHealingState;
  if (!state || state.destroyed || state.failed || state.busy || !pq) return;
  state.busy = true;
  try {
    const now = state.now();

    const retryAt = pq.pendingRetryAt;
    if (retryAt !== null && now >= retryAt) {
      if (pq.pendingAttempts >= PQ_HEAL_MAX_RETRIES) {
        failEdgeOnce(
          state,
          new Error(
            "pqHealingOrchestrator: control retry budget exhausted; failing the authenticated edge",
          ),
        );
        return;
      }
      await mutatePqDurably(epc, state, (candidate) => {
        candidate.markPendingDispatched(now);
        const frame = candidate.copyPendingFrame();
        if (!frame) return fail("retry tick found no persisted outbox");
        return Promise.resolve({ dispatch: frame, persist: true });
      });
      return;
    }

    if (
      pq.healingDue(now) &&
      !pq.trafficBlocked &&
      !state.inboundBlocked &&
      isEdgeQuiescentForHealing(epc, state.roomId)
    ) {
      await mutatePqDurably(epc, state, async (candidate) => {
        const frame = await candidate.prepareHealingOffer(now);
        candidate.markPendingDispatched(now);
        return { dispatch: frame, persist: true };
      });
    }
  } catch (error) {
    // A failed durable transition left the live runtime untouched; retry on a
    // later tick. Only exhaustion/forks fail the edge.
    console.error("pqHealingOrchestrator: tick transition failed", error);
  } finally {
    state.busy = false;
  }
};

/**
 * Route one authenticated-transport FRAME_TYPE_PQ_CONTROL cell. Closes the
 * local application gate, drains queued inbound frames to the quiescent
 * boundary, then runs the exact durable OFFER/ADVANCE/ACK ordering. An exact
 * duplicate re-emits the exact persisted response without a write. Any
 * authentication failure is a fork/replay outside the protocol and fails the
 * authenticated edge.
 */
export const handleInboundPqControlFrame = async (
  epc: IRTCPeerConnection,
  roomId: string,
  frame: Uint8Array,
): Promise<void> => {
  const state = orchestrators.get(epc);
  const pq = epc.pqHealingState;
  if (!state || state.destroyed || state.failed || !pq) return;
  if (frame.length !== WIRE_CHUNK_FRAME_LEN) {
    failEdgeOnce(
      state,
      new Error("pqHealingOrchestrator: malformed control cell length"),
    );
    return;
  }

  state.inboundBlocked = true;
  try {
    // Old-epoch frames already queued decrypt against their cached keys after
    // the transition; new first-chunks must not race the epoch commit.
    await waitForEdgeReceiveQuiescence(roomId, epc.withPeerId);
    const now = state.now();
    await mutatePqDurably(epc, state, async (candidate) => {
      const result = await candidate.acceptControlFrame(
        Uint8Array.from(frame),
        now,
      );
      if (!result.changed)
        return { dispatch: result.dispatch, persist: false };
      // A produced ADVANCE enters the retry schedule with its dispatch.
      if (result.dispatch !== null && candidate.pendingRetryAt !== null)
        candidate.markPendingDispatched(now);
      return { dispatch: result.dispatch, persist: true };
    });
  } catch (error) {
    if (error instanceof PqPersistenceError) {
      // Live state is untouched; the peer's exact retransmit reprocesses the
      // same slot once storage recovers.
      console.error("pqHealingOrchestrator: inbound transition not durable", error);
      return;
    }
    failEdgeOnce(
      state,
      new Error(
        "pqHealingOrchestrator: unauthenticated or forked control cell; failing the authenticated edge",
        { cause: error },
      ),
    );
  } finally {
    state.inboundBlocked = false;
  }
};
