import {
  coverSlotSpacingMs,
  createCoverScheduler,
  type CoverClock,
  type CoverJob,
  type CoverJobInterruption,
  type CoverJobProgress,
  type CoverJobResult,
  type CoverLane,
  type CoverLaneCloseContext,
  type CoverLaneOpenContext,
  type CoverSchedule,
  type CoverScheduler,
  type CoverSchedulerStatus,
  type CoverSendRequest,
  type CoverSlot,
  type CoverStatusChange,
} from "./coverScheduler";
import {
  openCoverCell,
  sealCoverCell,
  type CoverCellContent,
  type CoverCellDirection,
} from "../cryptography/coverCell";
import { compileChannelMessageLabel } from "../utils/channelLabel";
import { debugLog } from "../utils/debug";
import { createCoverTimerClock } from "./coverTimerWorker";
import { uint8ArrayToHex } from "../utils/uint8array";
import { MAX_BUFFERED_AMOUNT, WIRE_CHUNK_FRAME_LEN } from "../utils/constants";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type {
  CoverTimerClock,
  CoverTimerEnvironment,
} from "./coverTimerWorker";

// ── protocol-v4 scheduled-cover WebRTC adapter ───────────────────────────────
//
// One CoverRuntime owns the scheduled-cover lifecycle of ONE peer edge: it
// derives the absolute room phase from the authenticated policy hash, opens
// exactly `coverLanes` outbound channels at every cycle boundary, keeps dummy
// and real lanes byte-shape-identical (same label format, same 65,490-byte
// cells, same lifecycle), and closes lanes only at the fixed boundary. Real
// data, receipts, and CANCEL substitute into already-scheduled slots — the
// runtime never accelerates, never sends a catch-up burst after a suspension,
// and never falls back to the WebSocket relay for any payload.
//
// Sparse-PQ control cells do NOT substitute into cover slots. The only
// outbound path for one is `sendControlFrame`, and the sole implementation
// (handleOpenChannel, at orchestrator install) writes it to the persistent
// `main` channel in every room, scheduled or not. The `"control"` CoverJob
// kind here carries scheduled RECEIPTS (coverTransfer's receipt drain job),
// not PQ controls. Inbound routing accepts a PQ control frame arriving on a
// cover lane, but nothing on this side puts one there.
// Browser freeze/pagehide/offline events suspend cover; resume targets a
// strictly future cycle boundary, and the surfaced status makes the
// suspension gap visible to the UI instead of silently claiming cover. A
// hidden page is not suspended: its schedule stays armed, woken by a dedicated
// timer worker because a hidden page's own timers are throttled (see
// coverTimerWorker and #onVisibilityChange for what remains observable).

/** The transport surface a cover lane needs from an RTCDataChannel. */
export interface CoverLaneChannel {
  readonly label: string;
  readonly readyState: RTCDataChannelState | string;
  readonly bufferedAmount: number;
  send(data: ArrayBuffer): void;
  close(): void;
}

export interface CoverRuntimeOptions {
  readonly epc: IRTCPeerConnection;
  readonly roomId: string;
  readonly module: LibCrypto;
  readonly amInitiator: boolean;
  /** Authenticated room policy values (already validated by roomPolicy). */
  readonly schedule: Omit<CoverSchedule, "phaseOffsetMs">;
  /** Authenticated canonical room-policy hash: the shared phase source. */
  readonly policyHash: Uint8Array;
  /** Constant-shape name element shared by real and dummy lane labels. */
  readonly laneLabelName: string;
  /** Open one outbound lane; the caller owns RTCDataChannel construction. */
  readonly openLaneChannel: (label: string) => CoverLaneChannel;
  readonly onStatusChange?: (change: CoverStatusChange) => void;
  readonly onJobResult?: (result: CoverJobResult) => void;
  readonly onJobInterrupted?: (interruption: CoverJobInterruption) => void;
  /** Durable PQ epoch changed; senders may re-derive retired real producers. */
  readonly onKeyEpochChanged?: () => void;
  /**
   * Real-timer drift tolerance. Defaults to just under one slot spacing so a
   * healthy browser's setTimeout jitter does not suspend cover; a larger slip
   * still degrades. Deterministic (fake-clock) tests pass 0.
   */
  readonly maxTimerDriftMs?: number;
  /** Authenticated remote CANCEL for one transfer root (lowercase hex). */
  readonly onRemoteCancel?: (merkleRootHex: string) => void;
  /** Authenticated scheduled receipt token scoped to its transfer root. */
  readonly onScheduledReceipt?: (
    merkleRootHex: string,
    token: Uint8Array,
  ) => void;
  readonly onScheduledChunkReceipts?: (
    merkleRootHex: string,
    tokens: readonly Uint8Array[],
  ) => void;
  /**
   * A clock to drive the schedule with, owned by the caller (deterministic
   * tests). Without one the runtime creates its own timer-worker clock
   * (coverTimerWorker) and destroys it with itself.
   */
  readonly clock?: CoverClock;
  /** Where that own clock gets time, page timers and its worker (tests). */
  readonly timerEnvironment?: CoverTimerEnvironment;
}

/** Browser events that suspend cover, each lifted only by its own wake event. */
type EnvironmentSuspension = "pagehide" | "freeze" | "offline";

/**
 * True while the page is hidden: the condition under which a scheduled send's
 * delivery idle budget is held (scheduledCoverIsSuspended). False outside a
 * browser.
 */
export const isPageHidden = (): boolean =>
  typeof document !== "undefined" && document.visibilityState === "hidden";

/**
 * Every peer derives the identical absolute phase from the authenticated
 * policy hash, so all edges of the room share one cycle grid without any
 * negotiation message.
 */
export const deriveCoverPhaseOffsetMs = (
  policyHash: Uint8Array,
  coverCadenceMs: number,
): number => {
  if (policyHash.length < 8)
    throw new Error("coverRuntime: policy hash must be at least 8 bytes");
  if (!Number.isSafeInteger(coverCadenceMs) || coverCadenceMs <= 0)
    throw new Error("coverRuntime: cover cadence must be a positive integer");
  const view = new DataView(
    policyHash.buffer,
    policyHash.byteOffset,
    policyHash.byteLength,
  );
  return Number(view.getBigUint64(0, false) % BigInt(coverCadenceMs));
};

export class CoverRuntime {
  readonly #epc: IRTCPeerConnection;
  readonly #module: LibCrypto;
  readonly #options: CoverRuntimeOptions;
  readonly #outboundDirection: CoverCellDirection;
  readonly #inboundDirection: CoverCellDirection;
  readonly #scheduler: CoverScheduler;
  #outboundCounter = 0n;
  // Cover cells ride C independent lanes, so cross-lane arrival order is not
  // counter order. Replay protection is a sliding window over the counter
  // space: any counter is accepted at most once, and counters older than the
  // window behind the highest accepted one are rejected outright.
  #inboundHighestCounter: bigint | null = null;
  readonly #inboundSeenCounters = new Set<bigint>();
  static readonly #REPLAY_WINDOW = 1024n;
  readonly #jobSettledCallbacks = new Map<string, () => void>();
  #environmentAttached = false;
  readonly #environmentSuspensions = new Set<EnvironmentSuspension>();
  readonly #timerClock: CoverTimerClock | undefined;
  #destroyed = false;
  #lastStatus: CoverSchedulerStatus = "stopped";

  constructor(options: CoverRuntimeOptions) {
    this.#epc = options.epc;
    this.#module = options.module;
    this.#options = options;
    this.#outboundDirection = options.amInitiator
      ? "initiator-to-responder"
      : "responder-to-initiator";
    this.#inboundDirection = options.amInitiator
      ? "responder-to-initiator"
      : "initiator-to-responder";

    const schedule: CoverSchedule = {
      ...options.schedule,
      phaseOffsetMs: deriveCoverPhaseOffsetMs(
        options.policyHash,
        options.schedule.coverCadenceMs,
      ),
    };
    // A real browser's setTimeout always fires a few ms late (more under GC or
    // load), so a zero drift tolerance would suspend cover on the very first
    // tick. Tolerate up to just under one slot spacing (capped): a cell late by
    // less than a slot is still on-schedule; a larger slip degrades honestly.
    const slotSpacing = coverSlotSpacingMs(schedule);
    const maxTimerDriftMs =
      options.maxTimerDriftMs ??
      Math.max(0, Math.min(Math.floor(slotSpacing) - 1, 500));
    // Slot wake-ups come from the page's shared timer worker, which a hidden
    // page does not throttle (see coverTimerWorker for the one clock lateness
    // is judged on and for the fallback to page timers).
    const timerClock = options.clock
      ? undefined
      : createCoverTimerClock(options.timerEnvironment);
    this.#timerClock = timerClock;
    let scheduler: CoverScheduler;
    try {
      scheduler = this.#createScheduler(
        options,
        schedule,
        maxTimerDriftMs,
        options.clock ?? timerClock!,
      );
    } catch (error) {
      // A schedule the scheduler refuses must not hold the shared worker.
      timerClock?.destroy();
      throw error;
    }
    this.#scheduler = scheduler;
  }

  #createScheduler(
    options: CoverRuntimeOptions,
    schedule: CoverSchedule,
    maxTimerDriftMs: number,
    clock: CoverClock,
  ): CoverScheduler {
    return createCoverScheduler({
      schedule,
      maxTimerDriftMs,
      clock,
      laneFactory: (context) => this.#openLane(context),
      makeDummy: (slot) => this.#sealDummy(slot),
      onStatusChange: (change) => {
        this.#lastStatus = change.status;
        options.onStatusChange?.(change);
      },
      onJobResult: (result) => {
        const callback = this.#jobSettledCallbacks.get(result.jobId);
        if (callback) {
          this.#jobSettledCallbacks.delete(result.jobId);
          callback();
        }
        options.onJobResult?.(result);
      },
      onJobInterrupted: options.onJobInterrupted,
    });
  }

  /** Total cells one lane emits over a full cycle: F × D. */
  cellsPerLanePerCycle(): number {
    return (
      this.#options.schedule.coverFramesPerCell *
      this.#options.schedule.coverDurationEpochs
    );
  }

  /**
   * Fire a one-shot callback when the given job settles (completed, cancelled,
   * or failed). Used to re-arm a long control backlog across cycles.
   */
  onJobSettled(jobId: string, callback: () => void): void {
    this.#assertLive();
    this.#jobSettledCallbacks.set(jobId, callback);
  }

  /** A constant-shape lane label with a fresh random root (dummy/control). */
  randomLaneLabel(): string {
    return this.#syncDummyLaneLabel();
  }

  /** starting | active | degraded | suspended | stopped */
  get status(): CoverSchedulerStatus {
    return this.#lastStatus;
  }

  start(): void {
    this.#assertLive();
    this.#attachEnvironment();
    this.#scheduler.start();
  }

  stop(): void {
    this.#detachEnvironment();
    this.#environmentSuspensions.clear();
    this.#scheduler.stop();
  }

  /**
   * Stop for good. The runtime's own timer worker is terminated and every
   * pending wake-up dropped, including the boundary close a stop() pins: the
   * edge teardown that destroys a runtime closes its lanes itself.
   */
  destroy(): void {
    if (this.#destroyed) return;
    this.stop();
    this.#timerClock?.destroy();
    this.#destroyed = true;
  }

  /** Which source drives the schedule's wake-ups: the timer worker or the page. */
  get timerSource(): "worker" | "page" {
    return this.#timerClock?.source ?? "page";
  }

  /** A browser-imposed gap: close at the boundary, never claim the gap. */
  suspend(reason: string): void {
    this.#assertLive();
    this.#scheduler.suspend(reason);
  }

  /** Resume begins at a strictly future cycle boundary; gaps stay gaps. */
  resume(): void {
    this.#assertLive();
    this.#scheduler.resume();
  }

  enqueue(job: CoverJob): void {
    this.#assertLive();
    this.#scheduler.enqueue(job);
  }

  cancel(jobId: string): ReturnType<CoverScheduler["cancel"]> {
    this.#assertLive();
    return this.#scheduler.cancel(jobId);
  }

  complete(jobId: string): void {
    this.#assertLive();
    this.#scheduler.complete(jobId);
  }

  getQueuedJobIds(): readonly string[] {
    return this.#scheduler.getQueuedJobIds();
  }

  hasPendingRealJobs(): boolean {
    return this.#scheduler.hasPendingRealJobs();
  }

  /** Called only after the new epoch is durable and adopted. */
  onPqEpochChanged(): void {
    this.#assertLive();
    this.#scheduler.invalidateRealJobsForRekey();
    this.#options.onKeyEpochChanged?.();
  }

  /**
   * Live scheduler progress for one job, or undefined once it has settled.
   * Deliberately NOT `#assertLive()`-guarded: a delivery wait polls this and
   * must keep answering (with "gone") after the edge is destroyed rather than
   * throwing into the sender's loop.
   */
  getJobProgress(jobId: string): CoverJobProgress | undefined {
    return this.#scheduler.getJobProgress(jobId);
  }

  /**
   * Seal one authenticated non-dummy cover cell (CANCEL or scheduled receipt)
   * for substitution into an already-scheduled slot.
   */
  sealCoverContent(content: CoverCellContent): Uint8Array {
    this.#assertLive();
    return this.#seal(content);
  }

  /**
   * Authenticate one inbound FRAME_TYPE_COVER cell. Dummy cells vanish;
   * CANCEL/receipt dispatch to their hooks bound to the transfer root. An
   * unauthentic, replayed, or wrong-epoch cell is dropped (returns false) —
   * cover lanes may legitimately race an epoch transition by one flight.
   */
  processInboundCoverCell(frame: Uint8Array): boolean {
    this.#assertLive();
    const pq = this.#epc.pqHealingState;
    if (!pq || frame.length !== WIRE_CHUNK_FRAME_LEN) return false;
    const context = pq.currentMessageContext();
    try {
      const opened = openCoverCell({
        module: this.#module,
        rootSuite: context.rootSuite,
        rootKey: context.rootKey,
        binding: context.binding,
        direction: this.#inboundDirection,
        keyEpoch: context.epoch,
        frame,
      });
      if (!this.#admitInboundCounter(opened.counter)) return false;
      if (opened.content.subtype === "cancel")
        this.#options.onRemoteCancel?.(
          uint8ArrayToHex(opened.content.merkleRoot),
        );
      else if (opened.content.subtype === "receipt")
        this.#options.onScheduledReceipt?.(
          uint8ArrayToHex(opened.content.merkleRoot),
          opened.content.token,
        );
      else if (opened.content.subtype === "chunk-receipts")
        this.#options.onScheduledChunkReceipts?.(
          uint8ArrayToHex(opened.content.merkleRoot),
          opened.content.tokens,
        );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * A dummy lane advertises a plausible same-shape label: the identical name
   * element with a fresh random 64-byte "Merkle root". Labels are visible to
   * the authenticated peer only — never to the signaling server or a network
   * observer — so shape (not secrecy) is the requirement.
   */
  async makeDummyLaneLabel(): Promise<string> {
    const randomRoot = new Uint8Array(64);
    crypto.getRandomValues(randomRoot);
    return compileChannelMessageLabel(this.#options.laneLabelName, randomRoot);
  }

  #admitInboundCounter(counter: bigint): boolean {
    const highest = this.#inboundHighestCounter;
    if (
      highest !== null &&
      highest >= CoverRuntime.#REPLAY_WINDOW &&
      counter <= highest - CoverRuntime.#REPLAY_WINDOW
    )
      return false;
    if (this.#inboundSeenCounters.has(counter)) return false;
    this.#inboundSeenCounters.add(counter);
    if (highest === null || counter > highest) {
      this.#inboundHighestCounter = counter;
      if (counter >= CoverRuntime.#REPLAY_WINDOW) {
        const floor = counter - CoverRuntime.#REPLAY_WINDOW;
        for (const seen of this.#inboundSeenCounters)
          if (seen <= floor) this.#inboundSeenCounters.delete(seen);
      }
    }
    return true;
  }

  #seal(content: CoverCellContent): Uint8Array {
    const pq = this.#epc.pqHealingState;
    if (!pq) throw new Error("coverRuntime: edge has no live PQ runtime");
    const context = pq.currentMessageContext();
    const counter = this.#outboundCounter;
    this.#outboundCounter += 1n;
    return sealCoverCell({
      module: this.#module,
      rootSuite: context.rootSuite,
      rootKey: context.rootKey,
      binding: context.binding,
      direction: this.#outboundDirection,
      keyEpoch: context.epoch,
      counter,
      content,
    });
  }

  #sealDummy(_slot: CoverSlot): Uint8Array {
    return this.#seal({ subtype: "dummy" });
  }

  #openLane(context: CoverLaneOpenContext): CoverLane {
    // A real lane reuses its message's own root label (the job id IS the
    // label); a dummy lane synthesizes the same shape with a random root.
    // Label construction is async only for real compile parity; the dummy
    // label is produced synchronously here to keep the lane factory sync.
    const label =
      context.job !== null ? context.job.id : this.#syncDummyLaneLabel();
    const channel = this.#options.openLaneChannel(label);
    return {
      send: (request: CoverSendRequest): boolean => {
        if (request.cell.length !== WIRE_CHUNK_FRAME_LEN)
          throw new Error(
            "coverRuntime: refusing a non-uniform cell at the lane boundary",
          );
        // A just-created SCTP stream may not be "open" for the first slot(s) of
        // its cycle; treat that as backpressure (cell retained for retry), not
        // a hard failure — a thrown send would degrade the whole lane.
        if (channel.readyState !== "open") return false;
        // Backpressure marks the slot failed/requeued; a later burst would be
        // an observable timing artifact, so the cell is simply not sent now.
        if (channel.bufferedAmount >= MAX_BUFFERED_AMOUNT) return false;
        const owned = Uint8Array.from(request.cell);
        channel.send(owned.buffer as ArrayBuffer);
        return true;
      },
      close: (_closeContext: CoverLaneCloseContext): void => {
        // Only the scheduler calls this, and only at the fixed boundary (or
        // its late-cleanup of an already-suspended cycle).
        if (channel.readyState !== "closed") channel.close();
      },
    };
  }

  #syncDummyLaneLabel(): string {
    const nameBytes = new TextEncoder().encode(this.#options.laneLabelName);
    const namePadded = new Uint8Array(32);
    namePadded.set(nameBytes.subarray(0, Math.min(32, nameBytes.length)));
    const randomRoot = new Uint8Array(64);
    crypto.getRandomValues(randomRoot);
    return `${uint8ArrayToHex(namePadded)}~${uint8ArrayToHex(randomRoot)}`;
  }

  // ── browser environment: degraded/suspended cover is never claimed ────────

  // A hidden page keeps its schedule armed: suspending it showed tab
  // visibility on the wire as cover on/off, and a hidden receiver stopped
  // acknowledging, so its sender's idle budget ran out. The schedule's
  // wake-ups come from the page's shared timer worker, because a hidden page's
  // own timers are throttled to one wake-up a second (later one a minute), and
  // a slot past its drift tolerance degrades its cycle, which the status
  // reports.
  //
  // That does not make tab visibility unreadable. Measured in Chrome for
  // Testing 159 on macOS (docs/protocol-v4-pq-cover-architecture.md,
  // docs/e2e/cover-timers/): with 100 ms slots, page timers sent no cell while
  // hidden; the worker sent 89 % of them, and 19 % of cycles still degraded.
  // With 500 ms slots no cycle degraded. Even then cells are sent when their
  // wake-up runs on the page, and on the hidden page that was tens of
  // milliseconds after the slot (median 50-60 ms, against at most 6 ms
  // visible), so visibility is readable from cell timing against the slot grid
  // without any degraded cycle. Closing that needs the send itself to happen
  // off the page's event loop (from the worker), which this does not do. Not
  // measured and also observable: a frozen or discarded page (freeze suspends
  // cover), a browser that throttles worker timers, a suspended process, and
  // the page-timer fallback.
  //
  // A scheduled send's idle budget is held while the page stays hidden
  // (scheduledCoverIsSuspended). The diagnostic names no peer and no room.
  readonly #onVisibilityChange = (): void => {
    if (typeof document === "undefined") return;
    if (isPageHidden())
      debugLog(
        this.timerSource === "worker"
          ? "p2party: page hidden; scheduled cover stays armed on its timer worker"
          : "p2party: page hidden; scheduled cover stays armed, but on page timers, which the browser may throttle, so late cells degrade the cycle",
      );
    // Visible again: the page is neither hidden in the back/forward cache nor
    // frozen any more. That lifts a pagehide or freeze suspension in a browser
    // without the Page Lifecycle `resume` event, and never an offline one.
    else this.#liftEnvironmentSuspension("pagehide", "freeze");
  };

  readonly #onPageHide = (): void => {
    this.#suspendForEnvironment("pagehide");
  };

  readonly #onFreeze = (): void => {
    this.#suspendForEnvironment("freeze");
  };

  readonly #onResume = (): void => {
    this.#liftEnvironmentSuspension("freeze");
  };

  readonly #onOffline = (): void => {
    this.#suspendForEnvironment("offline");
  };

  readonly #onOnline = (): void => {
    this.#liftEnvironmentSuspension("offline");
  };

  // Each browser event owns its own suspension: a wake event lifts only the
  // ones it owns, and the schedule resumes once none is left. A `resume` after
  // a freeze therefore leaves an offline suspension in place.
  #suspendForEnvironment(cause: EnvironmentSuspension): void {
    this.#environmentSuspensions.add(cause);
    this.#scheduler.suspend(cause);
  }

  #liftEnvironmentSuspension(...causes: EnvironmentSuspension[]): void {
    let lifted = false;
    for (const cause of causes)
      lifted = this.#environmentSuspensions.delete(cause) || lifted;
    if (lifted && this.#environmentSuspensions.size === 0)
      this.#scheduler.resume();
  }

  // The Page Lifecycle `freeze` and `resume` events fire on document only; a
  // listener for them on window never runs.
  #attachEnvironment(): void {
    if (this.#environmentAttached) return;
    this.#environmentAttached = true;
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", this.#onVisibilityChange);
      document.addEventListener("freeze", this.#onFreeze);
      document.addEventListener("resume", this.#onResume);
    }
    if (typeof window !== "undefined") {
      window.addEventListener("pagehide", this.#onPageHide);
      window.addEventListener("offline", this.#onOffline);
      window.addEventListener("online", this.#onOnline);
    }
  }

  #detachEnvironment(): void {
    if (!this.#environmentAttached) return;
    this.#environmentAttached = false;
    if (typeof document !== "undefined") {
      document.removeEventListener(
        "visibilitychange",
        this.#onVisibilityChange,
      );
      document.removeEventListener("freeze", this.#onFreeze);
      document.removeEventListener("resume", this.#onResume);
    }
    if (typeof window !== "undefined") {
      window.removeEventListener("pagehide", this.#onPageHide);
      window.removeEventListener("offline", this.#onOffline);
      window.removeEventListener("online", this.#onOnline);
    }
  }

  #assertLive(): void {
    if (this.#destroyed) throw new Error("coverRuntime: runtime is destroyed");
  }
}
