import { MAX_ACTIVE_SIGNALING_ROOMS, PROTOCOL_VERSION } from "./constants";
import { isUuidV4, randomUuidV4 } from "./correlationId";

import type { WebSocketMessageRoomIdRequest } from "./interfaces";

export { MAX_ACTIVE_SIGNALING_ROOMS };
export const MAX_PENDING_ROOM_REQUESTS = MAX_ACTIVE_SIGNALING_ROOMS;
export const MAX_ROOM_REQUEST_RETRY_WAITERS = MAX_ACTIVE_SIGNALING_ROOMS;
export const ROOM_RESPONSE_TIMEOUT_MS = 15_000;
export const SOCKET_PROOF_TIMEOUT_MS = 15_000;
export const TURN_REFRESH_LEAD_MS = 5 * 60_000;
export const MIN_TURN_REFRESH_DELAY_MS = 1_000;
export const TURN_REFRESH_RETRY_BASE_MS = 1_000;
export const MAX_TURN_REFRESH_RETRY_MS = 30_000;
export const MAX_TURN_REFRESH_ATTEMPTS = 8;

export interface AppliedRoomResponse {
  roomUrl: string;
  roomId: string;
  roomRequestId: string;
  requestGeneration: number;
  expiresAtUnixSeconds: number | null;
}

type SendRoomRequest = (
  request: WebSocketMessageRoomIdRequest,
) => void | Promise<unknown>;

interface PendingRoomRequest {
  readonly roomUrl: string;
  readonly roomRequestId: string;
  readonly requestGeneration: number;
  readonly promise: Promise<AppliedRoomResponse>;
  readonly resolve: (response: AppliedRoomResponse) => void;
  readonly reject: (error: Error) => void;
  readonly timeout: ReturnType<typeof setTimeout>;
  claimed: boolean;
}

interface SocketProofGate {
  readonly lifecycleEpoch: number;
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly timeout: ReturnType<typeof setTimeout>;
}

interface RoomRequestRetryWaiter {
  readonly lifecycleEpoch: number;
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly timeout: ReturnType<typeof setTimeout>;
}

interface RefreshTimer {
  timeout?: ReturnType<typeof setTimeout>;
  readonly token: symbol;
  readonly expiresAtUnixSeconds: number;
  readonly refresh: () => Promise<unknown>;
  readonly expire: () => void | Promise<void>;
  attempt: number;
}

interface RefreshReservationRecord {
  readonly token: symbol;
  readonly expiresAtUnixSeconds: number | null;
}

export interface RoomCredentialRefreshReservation {
  readonly roomUrl: string;
  readonly token: symbol;
}

const pendingRoomRequests = new Map<string, PendingRoomRequest>();
let socketProofGate: SocketProofGate | null = null;
const roomRequestRetryWaiters = new Map<string, RoomRequestRetryWaiter>();
const refreshTimers = new Map<string, RefreshTimer>();
const refreshReservations = new Map<string, RefreshReservationRecord>();
let nextRequestGeneration = 1;
let roomRequestLifecycleEpoch = 1;

const ROOM_URL_PATTERN = /^[0-9a-f]{64}$/;

const roomRequestError = (message: string): Error =>
  new Error(`roomRequest: ${message}`);

export const buildRoomRequest = (
  peerId: string,
  roomUrl: string,
): WebSocketMessageRoomIdRequest => {
  if (!isUuidV4(peerId)) throw roomRequestError("peerId must be a UUIDv4");
  if (!ROOM_URL_PATTERN.test(roomUrl))
    throw roomRequestError("roomUrl must be 32-byte lowercase hex");
  return {
    type: "room",
    fromPeerId: peerId,
    roomUrl,
    roomRequestId: randomUuidV4(),
    protocolVersion: PROTOCOL_VERSION,
  };
};

/**
 * Start one wire-bound room request, or join the exact in-flight request.
 *
 * A fresh UUID is carried on the wire and must be echoed by the server. Merely
 * keeping a local generation would not distinguish an old same-room response
 * that arrived during a later request.
 */
export const requestRoomResponse = (
  peerId: string,
  roomUrl: string,
  send: SendRoomRequest,
  options: {
    readonly timeoutMs?: number;
  } = {},
): Promise<AppliedRoomResponse> => {
  const existing = pendingRoomRequests.get(roomUrl);
  if (existing) return existing.promise;
  if (pendingRoomRequests.size >= MAX_PENDING_ROOM_REQUESTS)
    return Promise.reject(
      roomRequestError("pending room request bound is exhausted"),
    );

  const request = buildRoomRequest(peerId, roomUrl);
  const requestGeneration = nextRequestGeneration++;
  if (!Number.isSafeInteger(nextRequestGeneration)) nextRequestGeneration = 1;

  let resolvePromise!: (response: AppliedRoomResponse) => void;
  let rejectPromise!: (error: Error) => void;
  const promise = new Promise<AppliedRoomResponse>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const timeoutMs = options.timeoutMs ?? ROOM_RESPONSE_TIMEOUT_MS;
  const timeout = setTimeout(() => {
    const pending = pendingRoomRequests.get(roomUrl);
    if (
      pending?.roomRequestId !== request.roomRequestId ||
      pending.requestGeneration !== requestGeneration
    )
      return;
    pendingRoomRequests.delete(roomUrl);
    pending.reject(roomRequestError("room response timed out"));
  }, timeoutMs);
  const pending: PendingRoomRequest = {
    roomUrl,
    roomRequestId: request.roomRequestId,
    requestGeneration,
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
    timeout,
    claimed: false,
  };
  pendingRoomRequests.set(roomUrl, pending);

  try {
    void Promise.resolve(send(request)).catch((error: unknown) => {
      rejectRoomResponse(
        roomUrl,
        request.roomRequestId,
        error instanceof Error ? error : roomRequestError(String(error)),
      );
    });
  } catch (error) {
    rejectRoomResponse(
      roomUrl,
      request.roomRequestId,
      error instanceof Error ? error : roomRequestError(String(error)),
    );
  }
  return promise;
};

export interface PendingRoomResponseClaim {
  readonly roomUrl: string;
  readonly roomRequestId: string;
  readonly requestGeneration: number;
}

/** Claim only the exact echoed UUID of the current single-flight request. */
export const claimRoomResponse = (
  roomUrl: string,
  roomRequestId: string,
): PendingRoomResponseClaim | null => {
  const pending = pendingRoomRequests.get(roomUrl);
  if (!pending || pending.claimed || pending.roomRequestId !== roomRequestId)
    return null;
  pending.claimed = true;
  return {
    roomUrl,
    roomRequestId,
    requestGeneration: pending.requestGeneration,
  };
};

export const completeRoomResponse = (
  response: AppliedRoomResponse,
): boolean => {
  const pending = pendingRoomRequests.get(response.roomUrl);
  if (
    !pending ||
    !pending.claimed ||
    pending.roomRequestId !== response.roomRequestId ||
    pending.requestGeneration !== response.requestGeneration
  )
    return false;
  clearTimeout(pending.timeout);
  pendingRoomRequests.delete(response.roomUrl);
  pending.resolve(response);
  return true;
};

export const rejectRoomResponse = (
  roomUrl: string,
  roomRequestId: string,
  error: Error,
): boolean => {
  const pending = pendingRoomRequests.get(roomUrl);
  if (!pending || pending.roomRequestId !== roomRequestId) return false;
  clearTimeout(pending.timeout);
  pendingRoomRequests.delete(roomUrl);
  pending.reject(error);
  return true;
};

export const pendingRoomRequestId = (roomUrl: string): string | null =>
  pendingRoomRequests.get(roomUrl)?.roomRequestId ?? null;

/** True only while the exact claimed response still owns its pending slot. */
export const isRoomResponseClaimCurrent = (
  claim: PendingRoomResponseClaim,
): boolean => {
  const pending = pendingRoomRequests.get(claim.roomUrl);
  return (
    pending?.claimed === true &&
    pending.roomRequestId === claim.roomRequestId &&
    pending.requestGeneration === claim.requestGeneration
  );
};

export const waitForFreshSocketProof = (
  alreadyVerified: boolean,
  timeoutMs = SOCKET_PROOF_TIMEOUT_MS,
  lifecycleEpoch = roomRequestLifecycleEpoch,
): Promise<void> => {
  if (lifecycleEpoch !== roomRequestLifecycleEpoch)
    return Promise.reject(roomRequestError("socket proof lifecycle is stale"));
  if (alreadyVerified) return Promise.resolve();
  if (socketProofGate?.lifecycleEpoch === lifecycleEpoch)
    return socketProofGate.promise;
  let resolvePromise!: () => void;
  let rejectPromise!: (error: Error) => void;
  const promise = new Promise<void>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const gate: SocketProofGate = {
    lifecycleEpoch,
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
    timeout: setTimeout(() => {
      if (socketProofGate !== gate) return;
      socketProofGate = null;
      rejectPromise(roomRequestError("fresh socket proof timed out"));
    }, timeoutMs),
  };
  socketProofGate = gate;
  return promise;
};

export const markFreshSocketProof = (
  lifecycleEpoch = roomRequestLifecycleEpoch,
): void => {
  if (lifecycleEpoch !== roomRequestLifecycleEpoch) return;
  const gate = socketProofGate;
  if (!gate || gate.lifecycleEpoch !== lifecycleEpoch) return;
  socketProofGate = null;
  clearTimeout(gate.timeout);
  gate.resolve();
};

const rejectSocketProofWaiters = (error: Error): void => {
  const gate = socketProofGate;
  if (!gate) return;
  socketProofGate = null;
  clearTimeout(gate.timeout);
  gate.reject(error);
};

export const currentRoomRequestLifecycleEpoch = (): number =>
  roomRequestLifecycleEpoch;

export const isRoomRequestLifecycleCurrent = (
  lifecycleEpoch: number,
): boolean => lifecycleEpoch === roomRequestLifecycleEpoch;

export const waitForRoomRequestRetry = (
  roomUrl: string,
  lifecycleEpoch: number,
  delayMs: number,
): Promise<void> => {
  if (lifecycleEpoch !== roomRequestLifecycleEpoch)
    return Promise.reject(roomRequestError("room retry lifecycle is stale"));
  const existing = roomRequestRetryWaiters.get(roomUrl);
  if (existing) {
    if (existing.lifecycleEpoch === lifecycleEpoch) return existing.promise;
    clearTimeout(existing.timeout);
    existing.reject(roomRequestError("room retry lifecycle was replaced"));
    roomRequestRetryWaiters.delete(roomUrl);
  }
  if (roomRequestRetryWaiters.size >= MAX_ROOM_REQUEST_RETRY_WAITERS)
    return Promise.reject(
      roomRequestError("room retry waiter bound is exhausted"),
    );

  let resolvePromise!: () => void;
  let rejectPromise!: (error: Error) => void;
  const promise = new Promise<void>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const timeout = setTimeout(
    () => {
      const current = roomRequestRetryWaiters.get(roomUrl);
      if (
        current?.lifecycleEpoch !== lifecycleEpoch ||
        current.promise !== promise
      )
        return;
      roomRequestRetryWaiters.delete(roomUrl);
      if (lifecycleEpoch !== roomRequestLifecycleEpoch)
        rejectPromise(roomRequestError("room retry lifecycle is stale"));
      else resolvePromise();
    },
    Math.max(0, delayMs),
  );
  roomRequestRetryWaiters.set(roomUrl, {
    lifecycleEpoch,
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
    timeout,
  });
  return promise;
};

const rejectRoomRetryWaiter = (roomUrl: string, error: Error): void => {
  const waiter = roomRequestRetryWaiters.get(roomUrl);
  if (!waiter) return;
  clearTimeout(waiter.timeout);
  roomRequestRetryWaiters.delete(roomUrl);
  waiter.reject(error);
};

export const turnRefreshDelayMs = (
  expiresAtUnixSeconds: number,
  nowMs = Date.now(),
  minimumDelayMs = MIN_TURN_REFRESH_DELAY_MS,
): number => {
  const expiresAtMs = expiresAtUnixSeconds * 1_000;
  return Math.max(minimumDelayMs, expiresAtMs - TURN_REFRESH_LEAD_MS - nowMs);
};

export interface RoomCredentialRefreshOptions {
  /** Test seam; production uses Date.now(). */
  nowMs?: number;
  /** Dynamic test seam for time that can advance while refresh is awaited. */
  now?: () => number;
  /** Test seams; production uses the bounded constants above. */
  retryBaseMs?: number;
  maxRetryMs?: number;
  maxAttempts?: number;
  minimumInitialDelayMs?: number;
}

export const turnRefreshRetryDelayMs = (
  attempt: number,
  remainingMs: number,
  options: RoomCredentialRefreshOptions = {},
): number => {
  const maxAttempts = options.maxAttempts ?? MAX_TURN_REFRESH_ATTEMPTS;
  if (attempt > maxAttempts) return remainingMs;
  const retryBaseMs = options.retryBaseMs ?? TURN_REFRESH_RETRY_BASE_MS;
  const maxRetryMs = options.maxRetryMs ?? MAX_TURN_REFRESH_RETRY_MS;
  return Math.min(
    maxRetryMs,
    retryBaseMs * 2 ** Math.max(0, attempt - 1),
    remainingMs,
  );
};

export const scheduleRoomCredentialRefresh = (
  roomUrl: string,
  expiresAtUnixSeconds: number | null,
  refresh: () => Promise<unknown>,
  expire: () => void | Promise<void> = () => undefined,
  options: RoomCredentialRefreshOptions = {},
  ownerToken = Symbol(roomUrl),
): void => {
  if (refreshReservations.has(roomUrl))
    throw roomRequestError("room refresh slot is reserved");
  if (!canScheduleRoomCredentialRefresh(roomUrl, expiresAtUnixSeconds))
    throw roomRequestError("room refresh timer bound is exhausted");
  clearRoomCredentialRefresh(roomUrl);
  if (expiresAtUnixSeconds === null) return;

  const timer: RefreshTimer = {
    token: ownerToken,
    expiresAtUnixSeconds,
    refresh,
    expire,
    attempt: 0,
  };
  const now = options.now ?? Date.now;
  const expireCurrent = async (): Promise<void> => {
    if (refreshTimers.get(roomUrl) !== timer) return;
    refreshTimers.delete(roomUrl);
    try {
      await expire();
    } catch (error) {
      console.warn(
        "p2party: failed to remove expired TURN credentials",
        error instanceof Error ? error.message : String(error),
      );
    }
  };
  const run = async (): Promise<void> => {
    if (refreshTimers.get(roomUrl) !== timer) return;
    const remainingMs = expiresAtUnixSeconds * 1_000 - now();
    if (remainingMs <= 0) {
      await expireCurrent();
      return;
    }

    try {
      await refresh();
      // A successful correlated response replaces this timer. If a custom
      // callback resolves without doing so, retain only an expiry alarm.
      if (refreshTimers.get(roomUrl) !== timer) return;
      const remainingAfterRefreshMs = expiresAtUnixSeconds * 1_000 - now();
      if (remainingAfterRefreshMs <= 0) {
        await expireCurrent();
        return;
      }
      timer.timeout = setTimeout(() => void run(), remainingAfterRefreshMs);
    } catch (error) {
      if (refreshTimers.get(roomUrl) !== timer) return;
      const remainingAfterRefreshMs = expiresAtUnixSeconds * 1_000 - now();
      if (remainingAfterRefreshMs <= 0) {
        await expireCurrent();
        return;
      }
      timer.attempt += 1;
      const retryDelay = turnRefreshRetryDelayMs(
        timer.attempt,
        remainingAfterRefreshMs,
        options,
      );
      timer.timeout = setTimeout(() => void run(), retryDelay);
      console.warn(
        timer.attempt <= (options.maxAttempts ?? MAX_TURN_REFRESH_ATTEMPTS)
          ? "p2party: scheduled TURN refresh failed; retrying"
          : "p2party: TURN refresh retries exhausted; credentials will be removed at expiry",
        error instanceof Error ? error.message : String(error),
      );
    }
  };
  timer.timeout = setTimeout(
    () => void run(),
    turnRefreshDelayMs(
      expiresAtUnixSeconds,
      options.nowMs,
      options.minimumInitialDelayMs,
    ),
  );
  refreshTimers.set(roomUrl, timer);
};

/**
 * Preflight used immediately before publishing a room response.
 *
 * A replacement owns its existing slot; a STUN-only response needs no slot.
 * Callers recheck after asynchronous live-PC configuration, then publish and
 * schedule synchronously so the bound cannot change between those operations.
 */
export function canScheduleRoomCredentialRefresh(
  roomUrl: string,
  expiresAtUnixSeconds: number | null,
): boolean {
  if (expiresAtUnixSeconds === null || refreshTimers.has(roomUrl)) return true;
  let reservedNewSlots = 0;
  for (const [reservedRoomUrl, reservation] of refreshReservations) {
    if (
      reservation.expiresAtUnixSeconds !== null &&
      !refreshTimers.has(reservedRoomUrl)
    )
      reservedNewSlots += 1;
  }
  return (
    refreshTimers.size + reservedNewSlots < MAX_ACTIVE_SIGNALING_ROOMS ||
    refreshReservations.has(roomUrl)
  );
}

export const reserveRoomCredentialRefresh = (
  roomUrl: string,
  expiresAtUnixSeconds: number | null,
): RoomCredentialRefreshReservation => {
  if (refreshReservations.has(roomUrl))
    throw roomRequestError("room refresh slot is already reserved");
  if (!canScheduleRoomCredentialRefresh(roomUrl, expiresAtUnixSeconds))
    throw roomRequestError("room refresh timer bound is exhausted");
  const token = Symbol(roomUrl);
  refreshReservations.set(roomUrl, { token, expiresAtUnixSeconds });
  return { roomUrl, token };
};

export const isRoomCredentialRefreshReservationCurrent = (
  reservation: RoomCredentialRefreshReservation,
): boolean =>
  refreshReservations.get(reservation.roomUrl)?.token === reservation.token;

export const releaseRoomCredentialRefreshReservation = (
  reservation: RoomCredentialRefreshReservation,
): boolean => {
  if (!isRoomCredentialRefreshReservationCurrent(reservation)) return false;
  refreshReservations.delete(reservation.roomUrl);
  return true;
};

export const finalizeRoomCredentialRefresh = (
  reservation: RoomCredentialRefreshReservation,
  expiresAtUnixSeconds: number | null,
  refresh: () => Promise<unknown>,
  expire: () => void | Promise<void> = () => undefined,
  options: RoomCredentialRefreshOptions = {},
): void => {
  const current = refreshReservations.get(reservation.roomUrl);
  if (
    current?.token !== reservation.token ||
    current.expiresAtUnixSeconds !== expiresAtUnixSeconds
  )
    throw roomRequestError("room refresh reservation is stale");
  refreshReservations.delete(reservation.roomUrl);
  scheduleRoomCredentialRefresh(
    reservation.roomUrl,
    expiresAtUnixSeconds,
    refresh,
    expire,
    options,
    reservation.token,
  );
};

/**
 * Release whichever refresh object this exact response still owns.
 *
 * A stale handler must never clear a replacement reservation/timer installed
 * for the same room URL after delete/reactivate or socket reset.
 */
export const clearRoomCredentialRefreshIfOwned = (
  reservation: RoomCredentialRefreshReservation,
): boolean => {
  const currentReservation = refreshReservations.get(reservation.roomUrl);
  if (currentReservation?.token === reservation.token) {
    refreshReservations.delete(reservation.roomUrl);
    return true;
  }

  const timer = refreshTimers.get(reservation.roomUrl);
  if (timer?.token !== reservation.token) return false;
  if (timer.timeout) clearTimeout(timer.timeout);
  refreshTimers.delete(reservation.roomUrl);
  return true;
};

export const clearRoomCredentialRefresh = (roomUrl: string): void => {
  const timer = refreshTimers.get(roomUrl);
  if (timer?.timeout) clearTimeout(timer.timeout);
  refreshTimers.delete(roomUrl);
  refreshReservations.delete(roomUrl);
};

/** Cancel every coordinator handle owned by one retained room. */
export const cancelRoomRequestLifecycle = (
  roomUrl: string,
  reason = "room lifecycle was cancelled",
): void => {
  const error = roomRequestError(reason);
  clearRoomCredentialRefresh(roomUrl);
  const pending = pendingRoomRequests.get(roomUrl);
  if (pending) {
    clearTimeout(pending.timeout);
    pendingRoomRequests.delete(roomUrl);
    pending.reject(error);
  }
  rejectRoomRetryWaiter(roomUrl, error);
};

/**
 * Socket teardown invalidates responses and fails closed on managed TURN.
 *
 * With no authenticated path available to refresh, keeping a credential timer
 * but losing its refresh context risks stale use after background suspension.
 * Remove the managed bundle now; a later proof repopulates it before repair.
 */
export const resetRoomRequestLifecycle = (
  reason = "signaling socket disconnected",
): void => {
  const error = roomRequestError(reason);
  roomRequestLifecycleEpoch += 1;
  if (!Number.isSafeInteger(roomRequestLifecycleEpoch))
    roomRequestLifecycleEpoch = 1;
  for (const pending of pendingRoomRequests.values()) {
    clearTimeout(pending.timeout);
    pending.reject(error);
  }
  pendingRoomRequests.clear();
  for (const timer of refreshTimers.values()) {
    if (timer.timeout) clearTimeout(timer.timeout);
    void Promise.resolve(timer.expire()).catch((expireError: unknown) => {
      console.warn(
        "p2party: failed to clear TURN credentials on signaling teardown",
        expireError instanceof Error
          ? expireError.message
          : String(expireError),
      );
    });
  }
  refreshTimers.clear();
  refreshReservations.clear();
  for (const [roomUrl, waiter] of roomRequestRetryWaiters) {
    clearTimeout(waiter.timeout);
    roomRequestRetryWaiters.delete(roomUrl);
    waiter.reject(error);
  }
  rejectSocketProofWaiters(error);
};

/** Test-only observability without exposing mutable coordinator maps. */
export const roomRequestCoordinatorCounts = (): {
  pending: number;
  proofWaiters: number;
  retryWaiters: number;
  refreshTimers: number;
  refreshReservations: number;
} => ({
  pending: pendingRoomRequests.size,
  proofWaiters: socketProofGate ? 1 : 0,
  retryWaiters: roomRequestRetryWaiters.size,
  refreshTimers: refreshTimers.size,
  refreshReservations: refreshReservations.size,
});
