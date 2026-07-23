import {
  deletePinAttemptState,
  getPinAttemptState,
  incrementPinAttemptState,
} from "./db/api";

export const MAX_PIN_ATTEMPTS = 3;
export const PIN_BACKOFF_BASE_MS = 500;
export const PIN_BACKOFF_MAX_MS = 5 * 60_000;
export const ROOM_PIN_FAILURE_WINDOW_MS = 5 * 60_000;
export const MAX_ROOM_PIN_FAILURES_PER_WINDOW = 30;

const roomFailureWindows = new Map<string, number[]>();

const currentRoomFailures = (roomId: string, now: number): number[] => {
  const cutoff = now - ROOM_PIN_FAILURE_WINDOW_MS;
  const current = (roomFailureWindows.get(roomId) ?? []).filter(
    (timestamp) => timestamp > cutoff,
  );
  if (current.length === 0) roomFailureWindows.delete(roomId);
  else roomFailureWindows.set(roomId, current);
  return current;
};

export const assertRoomPinAggregateAllowed = (
  roomId: string,
  now = Date.now(),
): void => {
  const failures = currentRoomFailures(roomId, now);
  if (failures.length < MAX_ROOM_PIN_FAILURES_PER_WINDOW) return;
  throw new Error(
    `PIN retries for this room are temporarily throttled until ${new Date(
      failures[0] + ROOM_PIN_FAILURE_WINDOW_MS,
    ).toISOString()}`,
  );
};

export const recordRoomPinAggregateFailure = (
  roomId: string,
  now = Date.now(),
): void => {
  const failures = currentRoomFailures(roomId, now);
  failures.push(now);
  roomFailureWindows.set(roomId, failures);
};

export const clearRoomPinAggregateFailures = (roomId: string): void => {
  roomFailureWindows.delete(roomId);
};

export const pinBackoffMs = (failures: number): number => {
  if (failures < MAX_PIN_ATTEMPTS) return 0;
  return Math.min(
    PIN_BACKOFF_BASE_MS * 2 ** (failures - MAX_PIN_ATTEMPTS),
    PIN_BACKOFF_MAX_MS,
  );
};

export const assertPinAttemptAllowed = async (
  roomId: string,
  peerIdentityEd25519: string,
  now = Date.now(),
): Promise<void> => {
  assertRoomPinAggregateAllowed(roomId, now);
  const state = await getPinAttemptState(roomId, peerIdentityEd25519);
  if (state && state.retryAfter > now)
    throw new Error(
      `PIN retry for this peer identity is throttled until ${new Date(state.retryAfter).toISOString()}`,
    );
};

export const recordPinFailure = async (
  roomId: string,
  peerIdentityEd25519: string,
  now = Date.now(),
): Promise<void> => {
  // Keep a softer in-tab room-wide window in addition to the durable
  // per-identity backoff. The former bounds identity rotation without letting
  // three failures from one peer lock every honest room member for five minutes.
  recordRoomPinAggregateFailure(roomId, now);
  await incrementPinAttemptState(
    roomId,
    peerIdentityEd25519,
    now,
    MAX_PIN_ATTEMPTS,
    PIN_BACKOFF_BASE_MS,
    PIN_BACKOFF_MAX_MS,
  );
};

export const clearPinAttempts = (
  roomId: string,
  peerIdentityEd25519?: string,
): Promise<void> => {
  if (peerIdentityEd25519 === undefined)
    clearRoomPinAggregateFailures(roomId);
  return deletePinAttemptState(roomId, peerIdentityEd25519);
};
