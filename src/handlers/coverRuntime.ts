import {
  createCoverScheduler,
  type CoverClock,
  type CoverJob,
  type CoverJobInterruption,
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
import { uint8ArrayToHex } from "../utils/uint8array";
import {
  MAX_BUFFERED_AMOUNT,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";

// ── protocol-v4 scheduled-cover WebRTC adapter ───────────────────────────────
//
// One CoverRuntime owns the scheduled-cover lifecycle of ONE peer edge: it
// derives the absolute room phase from the authenticated policy hash, opens
// exactly `coverLanes` outbound channels at every cycle boundary, keeps dummy
// and real lanes byte-shape-identical (same label format, same 65,490-byte
// cells, same lifecycle), and closes lanes only at the fixed boundary. Real
// data, PQ controls, receipts, and CANCEL substitute into already-scheduled
// slots — the runtime never accelerates, never sends a catch-up burst after a
// suspension, and never falls back to the WebSocket relay for any payload.
// Browser visibility/freeze/pagehide/offline events suspend cover; resume
// targets a strictly future cycle boundary, and the surfaced status makes the
// suspension gap visible to the UI instead of silently claiming cover.

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
  /** Authenticated remote CANCEL for one transfer root (lowercase hex). */
  readonly onRemoteCancel?: (merkleRootHex: string) => void;
  /** Authenticated scheduled receipt token scoped to its transfer root. */
  readonly onScheduledReceipt?: (
    merkleRootHex: string,
    token: Uint8Array,
  ) => void;
  readonly clock?: CoverClock;
}

const realClock: CoverClock = {
  now: () => Date.now(),
  setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimeout: (handle) => clearTimeout(handle as Parameters<typeof clearTimeout>[0]),
};

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
  #environmentAttached = false;
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
    this.#scheduler = createCoverScheduler({
      schedule,
      clock: options.clock ?? realClock,
      laneFactory: (context) => this.#openLane(context),
      makeDummy: (slot) => this.#sealDummy(slot),
      onStatusChange: (change) => {
        this.#lastStatus = change.status;
        options.onStatusChange?.(change);
      },
      onJobResult: options.onJobResult,
      onJobInterrupted: options.onJobInterrupted,
    });
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
    this.#scheduler.stop();
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.stop();
    this.#destroyed = true;
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
    return compileChannelMessageLabel(
      this.#options.laneLabelName,
      randomRoot,
    );
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
    if (!pq)
      throw new Error("coverRuntime: edge has no live PQ runtime");
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
      context.job !== null
        ? context.job.id
        : this.#syncDummyLaneLabel();
    const channel = this.#options.openLaneChannel(label);
    return {
      send: (request: CoverSendRequest): boolean => {
        if (request.cell.length !== WIRE_CHUNK_FRAME_LEN)
          throw new Error(
            "coverRuntime: refusing a non-uniform cell at the lane boundary",
          );
        if (channel.readyState !== "open")
          throw new Error("coverRuntime: lane channel is not open");
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

  readonly #onVisibilityChange = (): void => {
    if (typeof document === "undefined") return;
    if (document.visibilityState === "hidden")
      this.#scheduler.suspend("page-hidden");
    else this.#scheduler.resume();
  };

  readonly #onPageHide = (): void => {
    this.#scheduler.suspend("pagehide");
  };

  readonly #onFreeze = (): void => {
    this.#scheduler.suspend("freeze");
  };

  readonly #onOffline = (): void => {
    this.#scheduler.suspend("offline");
  };

  readonly #onOnline = (): void => {
    this.#scheduler.resume();
  };

  #attachEnvironment(): void {
    if (this.#environmentAttached) return;
    this.#environmentAttached = true;
    if (typeof document !== "undefined")
      document.addEventListener("visibilitychange", this.#onVisibilityChange);
    if (typeof window !== "undefined") {
      window.addEventListener("pagehide", this.#onPageHide);
      window.addEventListener("freeze", this.#onFreeze);
      window.addEventListener("offline", this.#onOffline);
      window.addEventListener("online", this.#onOnline);
    }
  }

  #detachEnvironment(): void {
    if (!this.#environmentAttached) return;
    this.#environmentAttached = false;
    if (typeof document !== "undefined")
      document.removeEventListener(
        "visibilitychange",
        this.#onVisibilityChange,
      );
    if (typeof window !== "undefined") {
      window.removeEventListener("pagehide", this.#onPageHide);
      window.removeEventListener("freeze", this.#onFreeze);
      window.removeEventListener("offline", this.#onOffline);
      window.removeEventListener("online", this.#onOnline);
    }
  }

  #assertLive(): void {
    if (this.#destroyed) throw new Error("coverRuntime: runtime is destroyed");
  }
}
