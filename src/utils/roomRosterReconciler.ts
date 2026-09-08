import { isUUID } from "class-validator";
import {
  hasTerminalPeerHandshakeFailure,
  isTerminalHandshakeStatus,
} from "../handlers/handshakeFailure";
import type { HandshakeRetryStatus } from "../handlers/handshakeFailure";

/**
 * Bounded "is anyone still there?" retries for a room that has nobody in it.
 *
 * Every roster request this SDK sends is caused by an event: a room join, a
 * peer introduction from the server, an edge teardown that re-dials. That is
 * enough while events keep arriving, and nothing at all once they stop. A
 * socket can be connected and identity-verified, its room still active, and
 * its roster empty for good — no peer to hear from, no teardown left to fire,
 * so no event that would ask again. Both sides then sit in a healthy-looking
 * room, alone, until the user reloads the page.
 *
 * The property this restores is deliberately weak and deliberately bounded: a
 * verified socket in an active room with nobody authenticated on it asks the
 * server for its peer list again on a backoff, a capped number of times, and
 * stops the moment anything changes. It is not a keepalive and not a repair
 * loop — a peers request is idempotent at the server (it re-introduces this
 * client to the room's live members, which is exactly what a stranded room
 * needs) and the caller still owns whether one may be sent at all.
 *
 * Store-free on purpose: the caller injects the timeout scheduler and decides,
 * at each attempt, whether the room is still stranded. Nothing here reads a
 * clock, a store or a browser global, so the whole backoff is exercisable in
 * virtual time.
 */

/**
 * Runs one reconciliation attempt for a room. Returns whether the room is
 * still stranded and the backoff should continue; `false` retires it.
 */
export type RoomRosterReconcileTick = (roomId: string) => boolean;

export interface RoomRosterReconcilerScheduler<Handle> {
  readonly setTimeout: (callback: () => void, delayMs: number) => Handle;
  readonly clearTimeout: (handle: Handle) => void;
}

export interface RoomRosterReconcilerOptions<Handle> {
  readonly schedule: RoomRosterReconcilerScheduler<Handle>;
  /** Delay before attempt n; the last entry is the cap for every attempt after. */
  readonly delaysMs: readonly number[];
  /** Total attempts allowed for one uninterrupted strand. */
  readonly maxAttempts: number;
}

export interface RoomRosterReconciler {
  /**
   * Report that a room is stranded. Idempotent: a room already under a backoff
   * keeps its schedule and its attempt count, and only its tick is refreshed,
   * so repeated observations can never rewind the backoff or stack timers. A
   * room that already spent its attempts stays retired until `cancel`.
   */
  arm(roomId: string, tick: RoomRosterReconcileTick): void;
  /** Forget a room: releases its timer and resets its attempt budget. */
  cancel(roomId: string): void;
  /** Forget every room, for a lost socket or a purged store. */
  cancelAll(): void;
  /** Rooms this reconciler still tracks, retired ones included. */
  armedRooms(): readonly string[];
}

interface RoomEntry<Handle> {
  attempts: number;
  tick: RoomRosterReconcileTick;
  /** Null between attempts only while the room is retired or mid-tick. */
  timer: Handle | null;
}

export const createRoomRosterReconciler = <Handle>(
  options: RoomRosterReconcilerOptions<Handle>,
): RoomRosterReconciler => {
  const { schedule, delaysMs, maxAttempts } = options;
  if (delaysMs.length === 0)
    throw new Error("roomRosterReconciler: needs at least one backoff delay");
  for (const delay of delaysMs)
    if (!Number.isFinite(delay) || delay <= 0)
      throw new Error(
        "roomRosterReconciler: every backoff delay must be a positive duration",
      );
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0)
    throw new Error("roomRosterReconciler: needs a positive attempt cap");

  const rooms = new Map<string, RoomEntry<Handle>>();

  const delayFor = (attempt: number): number =>
    delaysMs[Math.min(attempt, delaysMs.length - 1)];

  const cancel = (roomId: string): void => {
    const entry = rooms.get(roomId);
    if (!entry) return;
    if (entry.timer !== null) schedule.clearTimeout(entry.timer);
    rooms.delete(roomId);
  };

  const scheduleAttempt = (roomId: string, entry: RoomEntry<Handle>): void => {
    entry.timer = schedule.setTimeout(() => {
      // Read the entry back: the tick below, and anything it dispatches, may
      // have cancelled or re-armed this room while we were inside the timer.
      const current = rooms.get(roomId);
      if (!current || current.timer !== entry.timer) return;
      current.timer = null;
      let stillStranded: boolean;
      try {
        stillStranded = current.tick(roomId);
      } catch (error) {
        // A reconciliation attempt is a best-effort repair. It must never
        // escape into the host page's timer queue as an uncaught exception.
        console.error("p2party: room roster reconciliation failed", error);
        cancel(roomId);
        return;
      }
      const live = rooms.get(roomId);
      if (!live || live !== current || live.timer !== null) return;
      if (!stillStranded) {
        cancel(roomId);
        return;
      }
      live.attempts += 1;
      // Cap spent: the entry is deliberately KEPT with no timer. Retiring by
      // deleting it would let the next observation of the same unchanged room
      // start the whole backoff again, which is not a cap at all.
      if (live.attempts >= maxAttempts) return;
      scheduleAttempt(roomId, live);
    }, delayFor(entry.attempts));
  };

  return {
    arm: (roomId, tick) => {
      const existing = rooms.get(roomId);
      if (existing) {
        // Already under a backoff, mid-attempt, or retired at the cap: adopt
        // the newest tick and change nothing else. Only `cancel` restarts one.
        existing.tick = tick;
        return;
      }
      const entry: RoomEntry<Handle> = { attempts: 0, tick, timer: null };
      rooms.set(roomId, entry);
      scheduleAttempt(roomId, entry);
    },
    cancel,
    cancelAll: () => {
      for (const roomId of [...rooms.keys()]) cancel(roomId);
    },
    armedRooms: () => [...rooms.keys()],
  };
};

/** The shape of a room this predicate needs; a superset of the reducer's. */
export interface ReconcilableRoom {
  readonly id: string;
  readonly signalingActive?: boolean;
  readonly peers: readonly {
    readonly peerId: string;
    readonly peerPublicKey?: string;
  }[];
  readonly handshakeStatusByPeer?: Readonly<
    Record<string, HandshakeRetryStatus | undefined>
  >;
}

export interface ReconcilableSocket {
  readonly isConnected: boolean;
  readonly isVerified: boolean;
}

/** Known peers all need a deliberate authentication retry, not another roster. */
export const hasOnlyTerminalPeerHandshakeFailures = (
  room: ReconcilableRoom,
): boolean => {
  const statuses = room.handshakeStatusByPeer ?? {};
  if (room.peers.length > 0)
    return room.peers.every((peer) =>
      hasTerminalPeerHandshakeFailure(
        statuses,
        peer.peerId,
        peer.peerPublicKey,
      ),
    );
  const known = Object.values(statuses);
  return known.length > 0 && known.every(isTerminalHandshakeStatus);
};

/**
 * Whether a room is worth asking about again.
 *
 * "Nobody to talk to" is not the same as "no peers": a roster full of edges
 * that never finished authenticating is just as empty in practice, and the
 * server re-introducing this client is what gives those edges a fresh start.
 * A room the user left (`signalingActive === false`, which `deleteRoom` sets),
 * a room with no signaling identity yet, and any socket that is not both
 * connected and verified are all excluded — a request on those either cannot
 * be sent or would be an unwanted rejoin.
 */
export const isRoomRosterStranded = (
  room: ReconcilableRoom,
  socket: ReconcilableSocket,
): boolean => {
  if (!socket.isConnected || !socket.isVerified) return false;
  if (room.signalingActive === false) return false;
  if (!isUUID(room.id)) return false;
  if (hasOnlyTerminalPeerHandshakeFailures(room)) return false;
  const statuses = room.handshakeStatusByPeer ?? {};
  if (
    room.peers.some((peer) => statuses[peer.peerId]?.status === "authenticated")
  )
    return false;
  // Terminal authentication failures survive roster deletion. Re-introducing
  // that same identity cannot fix its PIN/policy, and must not consume another
  // PIN attempt every time the empty-room backoff fires.
  return true;
};
