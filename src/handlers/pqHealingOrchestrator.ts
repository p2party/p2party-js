import { PQ_HEAL_MAX_RETRIES } from "./pqHealingRuntime";
import { assertCurrentRatchetGeneration } from "./ratchetPersist";
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
//   clone → authenticate and mutate → check generation → adopt → dispatch
//
// The same per-edge lock serializes PQ and message-key transitions. Each
// replacement connection negotiates fresh keys, including its initial epoch.

/** Observe a candidate transition in a test before its live adoption. */
export type PqTransitionHook = (
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
  /** Optional pre-commit hook for fault-injection tests. */
  readonly beforeCommit?: PqTransitionHook;
  /** Tick cadence for the due/retry timer; 0 disables the interval (tests). */
  readonly tickMs?: number;
}

interface OrchestratorState {
  readonly roomId: string;
  readonly hooks: PqOrchestratorHooks;
  readonly now: () => number;
  readonly beforeCommit?: PqTransitionHook;
  interval: ReturnType<typeof setInterval> | null;
  /** Serializes orchestrator-level operations (tick vs inbound frame). */
  busy: boolean;
  /** An inbound control frame arrived; block new app sends until processed. */
  inboundBlocked: number;
  localInitiating: boolean;
  destroyed: boolean;
  failed: boolean;
}

const orchestrators = new WeakMap<IRTCPeerConnection, OrchestratorState>();

interface ApplicationReservations {
  count: number;
  readonly drained: Set<() => void>;
}
const applicationReservations = new WeakMap<
  IRTCPeerConnection,
  ApplicationReservations
>();

/**
 * Atomically reserve the derive-to-enqueue gap after the caller's admission
 * wait. null means a PQ transition won that race; retry admission. Existing
 * reservations drain before an inbound transition changes the epoch.
 */
export const tryReservePqApplicationTraffic = (
  epc: IRTCPeerConnection,
): (() => void) | null => {
  if (isPqApplicationTrafficBlocked(epc)) return null;
  let reservation = applicationReservations.get(epc);
  if (!reservation) {
    reservation = { count: 0, drained: new Set() };
    applicationReservations.set(epc, reservation);
  }
  reservation.count++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--reservation.count === 0) {
      applicationReservations.delete(epc);
      for (const notify of reservation.drained) notify();
      reservation.drained.clear();
    }
  };
};

const waitForApplicationReservations = (
  epc: IRTCPeerConnection,
): Promise<void> => {
  const reservation = applicationReservations.get(epc);
  return reservation && reservation.count > 0
    ? new Promise<void>((resolve) => reservation.drained.add(resolve))
    : Promise.resolve();
};

const DEFAULT_TICK_MS = 1_000;

const fail = (message: string): never => {
  throw new Error(`pqHealingOrchestrator: ${message}`);
};

/** A failed test checkpoint leaves the live runtime available for retransmission. */
class PqTransitionInterrupted extends Error {
  constructor(cause: unknown) {
    super("pqHealingOrchestrator: edge transition interrupted", {
      cause,
    });
    this.name = "PqTransitionInterrupted";
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
  if (
    state &&
    (state.inboundBlocked > 0 || state.localInitiating || state.failed)
  )
    return true;
  return epc.pqHealingState?.trafficBlocked ?? false;
};

/**
 * Local initiation waits for a quiescent transfer boundary: no live
 * per-message channels, scheduled real producers, derive-to-enqueue reservations,
 * or queued/in-flight inbound frames. Continuous dummy/control cover is idle.
 */
const isEdgeQuiescentForHealing = (
  epc: IRTCPeerConnection,
  roomId: string,
): boolean =>
  (epc.messageChannels?.size ?? 0) === 0 &&
  !(epc.coverRuntime?.hasPendingRealJobs() ?? false) &&
  (applicationReservations.get(epc)?.count ?? 0) === 0 &&
  !hasQueuedEdgeReceiveWork(roomId, epc.withPeerId);

/**
 * Stage one authenticated PQ transition. `mutate` receives the CLONE and returns the
 * exact cell(s) to dispatch after adoption (empty for no-op transitions).
 * Duplicate responses (mutate returns `dispatch` with `changed: false`) are
 * sent without a write, exactly as cached earlier.
 */
const mutateLivePq = async (
  epc: IRTCPeerConnection,
  state: OrchestratorState,
  mutate: (
    candidate: SparsePqHealingState,
  ) => Promise<{ dispatch: Uint8Array | null; changed: boolean }>,
): Promise<void> =>
  withEdgeCryptoMutationLock(epc, async () => {
    if (state.destroyed || orchestrators.get(epc) !== state) return;
    const live = epc.pqHealingState;
    const ratchet = epc.ratchetState;
    if (!live || !ratchet)
      return fail("edge has no live PQ runtime or ratchet");

    const candidate = live.clone();
    let outcome: { dispatch: Uint8Array | null; changed: boolean };
    try {
      outcome = await mutate(candidate);
      if (state.beforeCommit && outcome.changed) {
        try {
          await state.beforeCommit(epc, ratchet, state.roomId, () =>
            candidate.serialize(),
          );
        } catch (error) {
          throw new PqTransitionInterrupted(error);
        }
      }
      if (
        state.destroyed ||
        orchestrators.get(epc) !== state ||
        epc.pqHealingState !== live
      ) {
        candidate.destroy();
        return;
      }
      if (!state.beforeCommit)
        assertCurrentRatchetGeneration(epc, state.roomId);
      if (outcome.changed) {
        const previousEpoch = live.epoch;
        live.adopt(candidate);
        // adopt() moves the clone's active-key map INTO the live runtime, so
        // the per-edge cache alias must follow the new map object.
        epc.messageKeyCache = live.activeReceiveKeys;
        if (live.epoch !== previousEpoch) epc.coverRuntime?.onPqEpochChanged();
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
        // The lane is closed; the live outbox retries on a later tick or
        // while this authenticated generation is live.
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
    beforeCommit: hooks.beforeCommit,
    interval: null,
    busy: false,
    inboundBlocked: 0,
    localInitiating: false,
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

export const destroyPqHealingOrchestrator = (epc: IRTCPeerConnection): void => {
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
 * One due/retry pass. Retransmits the exact pending control frame when its
 * 5-second deadline passed (counting the attempt in the live epoch first), fails the
 * edge after the 8-attempt budget, and starts a due local exchange only when
 * the stable role owns the turn and the edge is at a quiescent boundary.
 * Exported for deterministic tests; the installed interval calls it.
 */
export const tickPqHealing = async (epc: IRTCPeerConnection): Promise<void> => {
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
      await mutateLivePq(epc, state, (candidate) => {
        candidate.markPendingDispatched(now);
        const frame = candidate.copyPendingFrame();
        if (!frame) return fail("retry tick found no live outbox");
        return Promise.resolve({ dispatch: frame, changed: true });
      });
      return;
    }

    if (
      pq.healingDue(now) &&
      !pq.trafficBlocked &&
      state.inboundBlocked === 0 &&
      isEdgeQuiescentForHealing(epc, state.roomId)
    ) {
      state.localInitiating = true;
      await mutateLivePq(epc, state, async (candidate) => {
        // Admission or a real job may have appeared while the crypto lock was
        // held by another transition. The gate above blocks later arrivals.
        if (
          !isEdgeQuiescentForHealing(epc, state.roomId) ||
          state.inboundBlocked > 0
        )
          return { dispatch: null, changed: false };
        const frame = await candidate.prepareHealingOffer(now);
        candidate.markPendingDispatched(now);
        return { dispatch: frame, changed: true };
      });
    }
  } catch (error) {
    // A failed transition left the live runtime untouched; retry on a
    // later tick. Only exhaustion/forks fail the edge.
    console.error("pqHealingOrchestrator: tick transition failed", error);
  } finally {
    state.localInitiating = false;
    state.busy = false;
  }
};

/**
 * Route one authenticated-transport FRAME_TYPE_PQ_CONTROL cell. Closes the
 * local application gate, drains queued inbound frames to the quiescent
 * boundary, then runs the exact authenticated OFFER/ADVANCE/ACK ordering. An exact
 * duplicate re-emits the exact cached response without a write. Any
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

  state.inboundBlocked++;
  try {
    await waitForApplicationReservations(epc);
    if (state.destroyed || orchestrators.get(epc) !== state) return;
    // Old-epoch frames already queued decrypt against their cached keys after
    // the transition; new first-chunks must not race the epoch commit.
    await waitForEdgeReceiveQuiescence(roomId, epc.withPeerId);
    const now = state.now();
    await mutateLivePq(epc, state, async (candidate) => {
      const result = await candidate.acceptControlFrame(
        Uint8Array.from(frame),
        now,
      );
      if (!result.changed) return { dispatch: result.dispatch, changed: false };
      // A produced ADVANCE enters the retry schedule with its dispatch.
      if (result.dispatch !== null && candidate.pendingRetryAt !== null)
        candidate.markPendingDispatched(now);
      return { dispatch: result.dispatch, changed: true };
    });
  } catch (error) {
    if (error instanceof PqTransitionInterrupted) {
      // Live state is untouched; the peer's exact retransmit reprocesses the
      // same slot on a later delivery.
      console.error(
        "pqHealingOrchestrator: inbound transition interrupted",
        error,
      );
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
    state.inboundBlocked--;
  }
};
