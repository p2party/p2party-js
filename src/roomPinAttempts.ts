import {
  deletePinAttemptState,
  getPinAttemptState,
  incrementPinAttemptState,
} from "./db/api";

import type { PinAttemptState } from "./db/types";

export const MAX_PIN_ATTEMPTS = 3;
export const PIN_BACKOFF_BASE_MS = 500;
export const PIN_BACKOFF_MAX_MS = 5 * 60_000;
export const ROOM_PIN_FAILURE_WINDOW_MS = 5 * 60_000;
export const MAX_ROOM_PIN_FAILURES_PER_WINDOW = 30;

// Two durable controls bound online PIN guessing in a room:
//
// - per identity: `(roomId, peer Ed25519 identity)` → exponential backoff
//   after MAX_PIN_ATTEMPTS failures (the 0.14.10 row, unchanged);
// - per room: one failure window that opens at the room's first failure and
//   lasts ROOM_PIN_FAILURE_WINDOW_MS. Once it holds
//   MAX_ROOM_PIN_FAILURES_PER_WINDOW failures, identities that never completed
//   a PIN handshake with this device in this room are refused until it ends.
//   Identities that did are never refused by it, so a peer rotating fresh
//   identities cannot lock established members out. A success does not close
//   the window.
//
// Both live in the same IndexedDB rows as the per-identity backoff, under room
// scopes no real room ID can take (room IDs are UUIDs; reserved prefixes are
// refused below), so the database worker needs no new method:
//   `${ROOM_WINDOW_SCOPE_PREFIX}${roomId}` / ROOM_WINDOW_ROW
//       { failures: count in the current window, retryAfter: window end }
//   `${KNOWN_PEER_SCOPE_PREFIX}${roomId}` / peer identity
//       present once that identity completed a PIN handshake in this room
//       { failures: successful handshakes, retryAfter: latest success }
const ROOM_WINDOW_SCOPE_PREFIX = "pin-room-window:";
const KNOWN_PEER_SCOPE_PREFIX = "pin-known-peers:";
const ROOM_WINDOW_ROW = "0".repeat(64);

/** The database worker's three PIN-attempt row operations. */
export interface PinAttemptStore {
  get(roomId: string, id: string): Promise<PinAttemptState | undefined>;
  increment(
    roomId: string,
    id: string,
    now: number,
    maxImmediateAttempts: number,
    baseMs: number,
    maxMs: number,
  ): Promise<PinAttemptState>;
  /** Without an id, deletes every row of that room scope. */
  delete(roomId: string, id?: string): Promise<void>;
}

export interface PinAttemptLimiter {
  /** Throws `... throttled until <ISO time>` when this attempt must wait. */
  assertAttemptAllowed(
    roomId: string,
    peerIdentityEd25519: string,
    now?: number,
  ): Promise<void>;
  /** A PIN handshake with this identity failed key confirmation. */
  recordFailure(
    roomId: string,
    peerIdentityEd25519: string,
    now?: number,
  ): Promise<void>;
  /** A PIN handshake with this identity completed. */
  recordSuccess(
    roomId: string,
    peerIdentityEd25519: string,
    now?: number,
  ): Promise<void>;
  /**
   * With an identity: drops that identity's backoff. Without: drops every PIN
   * row of the room — backoff, window and the record of authenticated peers.
   */
  clear(roomId: string, peerIdentityEd25519?: string): Promise<void>;
  /** Counts a failure in this tab's copy of the room window only. */
  recordInTabRoomFailure(roomId: string, now?: number): void;
}

export const pinBackoffMs = (failures: number): number => {
  if (failures < MAX_PIN_ATTEMPTS) return 0;
  return Math.min(
    PIN_BACKOFF_BASE_MS * 2 ** (failures - MAX_PIN_ATTEMPTS),
    PIN_BACKOFF_MAX_MS,
  );
};

const assertNotReservedRoomId = (roomId: string): void => {
  if (
    roomId.startsWith(ROOM_WINDOW_SCOPE_PREFIX) ||
    roomId.startsWith(KNOWN_PEER_SCOPE_PREFIX)
  )
    throw new Error("PIN attempt room ID uses a reserved prefix");
};

const roomWindowScope = (roomId: string): string =>
  `${ROOM_WINDOW_SCOPE_PREFIX}${roomId}`;

const knownPeerScope = (roomId: string): string =>
  `${KNOWN_PEER_SCOPE_PREFIX}${roomId}`;

const roomThrottledError = (until: number): Error =>
  new Error(
    `PIN attempts from identities new to this room are temporarily throttled until ${new Date(
      until,
    ).toISOString()}`,
  );

export const createPinAttemptLimiter = (
  store: PinAttemptStore,
): PinAttemptLimiter => {
  // In-tab copies. The window copy keeps counting when a persisted write
  // fails (storage full); the known-peer copy spares a read per handshake.
  const inTabWindows = new Map<string, { failures: number; end: number }>();
  const inTabKnownPeers = new Map<string, Set<string>>();
  // Restarting an ended persisted window is read → delete → increment; this
  // per-room chain keeps concurrent failures in this tab from deleting each
  // other's count.
  const windowWrites = new Map<string, Promise<void>>();

  const serializeWindowWrite = (
    roomId: string,
    write: () => Promise<void>,
  ): Promise<void> => {
    const run = (windowWrites.get(roomId) ?? Promise.resolve()).then(
      write,
      write,
    );
    const settled = run.then(
      () => undefined,
      () => undefined,
    );
    windowWrites.set(roomId, settled);
    void settled.then(() => {
      if (windowWrites.get(roomId) === settled) windowWrites.delete(roomId);
    });
    return run;
  };

  const inTabWindow = (roomId: string, now: number) => {
    const window = inTabWindows.get(roomId);
    if (window && window.end > now) return window;
    inTabWindows.delete(roomId);
    return undefined;
  };

  const recordInTabRoomFailure = (roomId: string, now = Date.now()): void => {
    const window = inTabWindow(roomId, now);
    if (window) window.failures += 1;
    else
      inTabWindows.set(roomId, {
        failures: 1,
        end: now + ROOM_PIN_FAILURE_WINDOW_MS,
      });
  };

  const fullWindowEnd = (
    window: { failures: number; end: number } | undefined,
    now: number,
  ): number | undefined =>
    window &&
    window.failures >= MAX_ROOM_PIN_FAILURES_PER_WINDOW &&
    window.end > now
      ? window.end
      : undefined;

  const persistedFullWindowEnd = async (
    roomId: string,
    now: number,
  ): Promise<number | undefined> => {
    const row = await store.get(roomWindowScope(roomId), ROOM_WINDOW_ROW);
    return fullWindowEnd(
      row && { failures: row.failures, end: row.retryAfter },
      now,
    );
  };

  const recordPersistedWindowFailure = (
    roomId: string,
    now: number,
  ): Promise<void> =>
    serializeWindowWrite(roomId, async () => {
      const scope = roomWindowScope(roomId);
      const row = await store.get(scope, ROOM_WINDOW_ROW);
      if (row && row.retryAfter > now) {
        // With one immediate attempt and base = cap = the time left, the
        // worker's backoff formula writes retryAfter = now + left: the window
        // end is kept and only the count grows.
        const left = row.retryAfter - now;
        await store.increment(scope, ROOM_WINDOW_ROW, now, 1, left, left);
        return;
      }
      if (row) await store.delete(scope, ROOM_WINDOW_ROW);
      await store.increment(
        scope,
        ROOM_WINDOW_ROW,
        now,
        1,
        ROOM_PIN_FAILURE_WINDOW_MS,
        ROOM_PIN_FAILURE_WINDOW_MS,
      );
    });

  const rememberKnownPeer = (
    roomId: string,
    peerIdentityEd25519: string,
  ): void => {
    const peers = inTabKnownPeers.get(roomId) ?? new Set<string>();
    peers.add(peerIdentityEd25519);
    inTabKnownPeers.set(roomId, peers);
  };

  const isKnownPeer = async (
    roomId: string,
    peerIdentityEd25519: string,
  ): Promise<boolean> => {
    if (inTabKnownPeers.get(roomId)?.has(peerIdentityEd25519)) return true;
    let row: PinAttemptState | undefined;
    try {
      row = await store.get(knownPeerScope(roomId), peerIdentityEd25519);
    } catch {
      // Only asked while the room window is full: an identity this device
      // cannot confirm it has authenticated is refused like a new one.
      return false;
    }
    if (row === undefined) return false;
    rememberKnownPeer(roomId, peerIdentityEd25519);
    return true;
  };

  return {
    async assertAttemptAllowed(roomId, peerIdentityEd25519, now = Date.now()) {
      assertNotReservedRoomId(roomId);
      // The in-tab copy is checked first so a full window still refuses new
      // identities when storage cannot be read.
      const windowEnd =
        fullWindowEnd(inTabWindow(roomId, now), now) ??
        (await persistedFullWindowEnd(roomId, now));
      if (
        windowEnd !== undefined &&
        !(await isKnownPeer(roomId, peerIdentityEd25519))
      )
        throw roomThrottledError(windowEnd);

      const state = await store.get(roomId, peerIdentityEd25519);
      if (state && state.retryAfter > now)
        throw new Error(
          `PIN retry for this peer identity is throttled until ${new Date(state.retryAfter).toISOString()}`,
        );
    },

    async recordFailure(roomId, peerIdentityEd25519, now = Date.now()) {
      assertNotReservedRoomId(roomId);
      recordInTabRoomFailure(roomId, now);
      await Promise.all([
        recordPersistedWindowFailure(roomId, now),
        store.increment(
          roomId,
          peerIdentityEd25519,
          now,
          MAX_PIN_ATTEMPTS,
          PIN_BACKOFF_BASE_MS,
          PIN_BACKOFF_MAX_MS,
        ),
      ]);
    },

    async recordSuccess(roomId, peerIdentityEd25519, now = Date.now()) {
      assertNotReservedRoomId(roomId);
      rememberKnownPeer(roomId, peerIdentityEd25519);
      await Promise.all([
        // No immediate-attempt limit is ever reached, so the worker stores
        // retryAfter = now: the latest success.
        store.increment(
          knownPeerScope(roomId),
          peerIdentityEd25519,
          now,
          Number.MAX_SAFE_INTEGER,
          1,
          1,
        ),
        store.delete(roomId, peerIdentityEd25519),
      ]);
    },

    async clear(roomId, peerIdentityEd25519) {
      assertNotReservedRoomId(roomId);
      if (peerIdentityEd25519 !== undefined) {
        await store.delete(roomId, peerIdentityEd25519);
        return;
      }
      inTabWindows.delete(roomId);
      inTabKnownPeers.delete(roomId);
      await Promise.all([
        store.delete(roomId),
        store.delete(knownPeerScope(roomId)),
        serializeWindowWrite(roomId, () =>
          store.delete(roomWindowScope(roomId), ROOM_WINDOW_ROW),
        ),
      ]);
    },

    recordInTabRoomFailure,
  };
};

const pinAttempts = createPinAttemptLimiter({
  get: getPinAttemptState,
  increment: incrementPinAttemptState,
  delete: deletePinAttemptState,
});

export const assertPinAttemptAllowed = (
  roomId: string,
  peerIdentityEd25519: string,
  now = Date.now(),
): Promise<void> =>
  pinAttempts.assertAttemptAllowed(roomId, peerIdentityEd25519, now);

export const recordPinFailure = (
  roomId: string,
  peerIdentityEd25519: string,
  now = Date.now(),
): Promise<void> => pinAttempts.recordFailure(roomId, peerIdentityEd25519, now);

export const recordPinSuccess = (
  roomId: string,
  peerIdentityEd25519: string,
  now = Date.now(),
): Promise<void> => pinAttempts.recordSuccess(roomId, peerIdentityEd25519, now);

export const clearPinAttempts = (
  roomId: string,
  peerIdentityEd25519?: string,
): Promise<void> => pinAttempts.clear(roomId, peerIdentityEd25519);

/**
 * Counts one failure in this tab's copy of the room window, without storage.
 * Production records failures with recordPinFailure.
 */
export const recordRoomPinAggregateFailure = (
  roomId: string,
  now = Date.now(),
): void => pinAttempts.recordInTabRoomFailure(roomId, now);
