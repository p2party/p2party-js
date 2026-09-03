import {
  isCurrentRatchetGateLease,
  isRatchetGateOpen,
} from "../../handlers/ratchetGate";
import { requestPeersAfterEdgeTeardown } from "../../handlers/edgeTeardownFollowUp";
import { REBIND_AUTHENTICATION_DEADLINE_MS } from "../../utils/constants";
import { debugLog } from "../../utils/debug";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { DisconnectPeerTransport, IRTCPeerConnection } from "./interfaces";

/**
 * The timer primitives the deadline uses. Injected so a test drives the
 * deadline by hand instead of waiting out real seconds; production passes
 * nothing and gets the platform's own.
 */
export interface RebindDeadlineScheduler {
  readonly setTimeout: (
    callback: () => void,
    delayMs: number,
  ) => ReturnType<typeof setTimeout>;
  readonly clearTimeout: (handle: ReturnType<typeof setTimeout>) => void;
}

const systemScheduler: RebindDeadlineScheduler = {
  setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimeout: (handle) => {
    clearTimeout(handle);
  },
};

/**
 * Keep a pending deadline from holding a Node/Bun process open. Browsers have
 * no unref; a test scheduler's handle may be anything at all.
 */
const unrefTimer = (handle: unknown): void => {
  const timer = handle as { unref?: () => void } | null;
  if (timer && typeof timer.unref === "function") timer.unref();
};

/**
 * Release a pending re-bind deadline. Idempotent, and safe on a connection
 * that never armed one.
 */
export const clearRebindAuthenticationDeadline = (
  epc: Pick<IRTCPeerConnection, "rebindDeadline" | "rebindDeadlineClear">,
): void => {
  const handle = epc.rebindDeadline;
  const cancel = epc.rebindDeadlineClear;
  epc.rebindDeadline = undefined;
  epc.rebindDeadlineClear = undefined;
  if (handle === undefined) return;
  (cancel ?? systemScheduler.clearTimeout)(handle);
};

export interface ArmRebindAuthenticationDeadlineParams {
  epc: IRTCPeerConnection;
  roomId: string;
  peerId: string;
  api: Pick<BaseQueryApi, "dispatch" | "getState">;
  /** Tears this room/peer transport down through the transport-failure path. */
  disconnectPeer: DisconnectPeerTransport;
  deadlineMs?: number;
  schedule?: RebindDeadlineScheduler;
}

/**
 * Give one in-place re-bind a wall-clock deadline to re-authenticate in.
 *
 * A re-bind keeps the RTCPeerConnection — and with it the SCTP association
 * that was negotiated against the RETIRED remote certificate. Chromium will
 * happily open our own new outbound streams on it while never delivering the
 * peer's: on the process-freeze harness the woken responder re-binds its
 * surviving PC, its own message channel reaches the peer two seconds later,
 * and the peer's `main` — opened on its brand-new PC before the re-bind even
 * happened — never arrives at all. The re-bind is then a silent black hole:
 * ICE stays connected so no failure path replaces the transport, and the edge
 * only heals when the PEER's handshake step timeout (30 s) tears its own side
 * down and the normal re-dial rebuilds everything, ~37 s after the wake.
 *
 * So the re-bind gets a budget. When it expires with nothing authenticated,
 * this side does what the peer's timeout would eventually have done, sooner:
 * tear the edge down through the transport-failure path (which mints a fresh
 * local certificate on the rebuilt transport) and ask the room to re-introduce
 * the pair.
 *
 * Three guards make a late timer harmless, because the same connection object
 * outlives the re-bind that armed the deadline:
 *
 * - the connection still carries the gate lease this re-bind installed (a
 *   LATER re-bind of the same transport installed its own and re-armed);
 * - that lease is still the edge's current one (a replacement transport, from
 *   a re-dial or a "replace" decision, claims a fresh lease — this deadline
 *   then belongs to a transport nobody uses any more);
 * - the edge has not authenticated in the meantime (a live ratchet, or the
 *   gate open under this very lease).
 *
 * The teardown itself is not a guard: `webrtcDisconnectPeerQuery` clears the
 * deadline, so a torn-down connection never fires it at all.
 */
export const armRebindAuthenticationDeadline = ({
  epc,
  roomId,
  peerId,
  api,
  disconnectPeer,
  deadlineMs = REBIND_AUTHENTICATION_DEADLINE_MS,
  schedule = systemScheduler,
}: ArmRebindAuthenticationDeadlineParams): void => {
  clearRebindAuthenticationDeadline(epc);

  const lease = epc.ratchetGateLease;
  const onDeadline = (): void => {
    epc.rebindDeadline = undefined;
    epc.rebindDeadlineClear = undefined;
    if (epc.ratchetGateLease !== lease) return;
    if (!isCurrentRatchetGateLease(roomId, peerId, lease)) return;
    if (epc.ratchetState !== undefined) return;
    if (isRatchetGateOpen(roomId, peerId, lease)) return;

    debugLog(
      `In-place re-bind for ${peerId} in ${roomId} did not authenticate within ${String(deadlineMs)} ms; rebuilding the edge`,
    );
    void Promise.resolve()
      .then(() => disconnectPeer({ roomId, peerId }))
      .catch((error: unknown) => {
        // The edge is going away either way; the roster round below is what
        // rebuilds it, so a failed teardown must not skip the re-dial.
        console.error(
          `Failed to tear down the stalled re-bind of ${peerId} in ${roomId}:`,
          error,
        );
      })
      .then(() => {
        requestPeersAfterEdgeTeardown(api, roomId);
      });
  };

  const handle = schedule.setTimeout(onDeadline, deadlineMs);
  unrefTimer(handle);
  epc.rebindDeadline = handle;
  epc.rebindDeadlineClear = schedule.clearTimeout;
};
