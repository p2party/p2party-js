import { isUUID } from "class-validator";

import {
  currentRoomRequestLifecycleEpoch,
  isRoomRequestLifecycleCurrent,
  requestRoomResponse,
  waitForRoomRequestRetry,
} from "../utils/roomRequestCoordinator";

import type { AppliedRoomResponse } from "../utils/roomRequestCoordinator";
import type { State } from "../store";
import type { WebSocketMessageRoomIdRequest } from "../utils/interfaces";

export interface RoomRequestApi {
  getState: () => unknown;
}

export type SendRoomRequest = (
  request: WebSocketMessageRoomIdRequest,
) => Promise<unknown>;

export const MAX_ROOM_REQUEST_ATTEMPTS = 4;
export const ROOM_REQUEST_RETRY_BASE_MS = 250;
export const MAX_ROOM_REQUEST_RETRY_MS = 2_000;

export interface RoomRequestRetryOptions {
  lifecycleEpoch?: number;
  maxAttempts?: number;
  retryBaseMs?: number;
  maxRetryMs?: number;
}

export interface ActiveRoomRequestOptions extends RoomRequestRetryOptions {
  concurrency?: number;
}

export const ACTIVE_ROOM_REQUEST_CONCURRENCY = 16;

/**
 * The one SDK path that emits a room request.
 *
 * It binds every request to a fresh wire nonce through the coordinator and
 * refuses to issue room traffic before the current socket proves identity.
 */
export const requestRoomFromSignaling = (
  api: RoomRequestApi,
  roomUrl: string,
  sendRoomRequest: SendRoomRequest,
): Promise<AppliedRoomResponse> => {
  const { keyPair, rooms, signalingServer } = api.getState() as State;
  const room = rooms.find((candidate) => candidate.url === roomUrl);
  if (
    !room ||
    room.signalingActive === false ||
    !signalingServer.isConnected ||
    !signalingServer.isVerified ||
    !isUUID(keyPair.peerId, 4)
  )
    return Promise.reject(
      new Error("roomRequest: signaling proof or active room is unavailable"),
    );

  return requestRoomResponse(keyPair.peerId, roomUrl, sendRoomRequest);
};

/** Retry one room independently while it remains in this socket lifecycle. */
export const requestRoomFromSignalingWithRetry = async (
  api: RoomRequestApi,
  roomUrl: string,
  sendRoomRequest: SendRoomRequest,
  options: RoomRequestRetryOptions = {},
): Promise<AppliedRoomResponse> => {
  const lifecycleEpoch =
    options.lifecycleEpoch ?? currentRoomRequestLifecycleEpoch();
  const maxAttempts = options.maxAttempts ?? MAX_ROOM_REQUEST_ATTEMPTS;
  const retryBaseMs = options.retryBaseMs ?? ROOM_REQUEST_RETRY_BASE_MS;
  const maxRetryMs = options.maxRetryMs ?? MAX_ROOM_REQUEST_RETRY_MS;
  let attempt = 0;

  while (true) {
    if (!isRoomRequestLifecycleCurrent(lifecycleEpoch))
      throw new Error("roomRequest: room retry lifecycle is stale");
    try {
      return await requestRoomFromSignaling(api, roomUrl, sendRoomRequest);
    } catch (error) {
      attempt += 1;
      if (
        attempt >= maxAttempts ||
        !isRoomRequestLifecycleCurrent(lifecycleEpoch)
      )
        throw error;
      const delayMs = Math.min(
        maxRetryMs,
        retryBaseMs * 2 ** Math.max(0, attempt - 1),
      );
      await waitForRoomRequestRetry(roomUrl, lifecycleEpoch, delayMs);
    }
  }
};

/** Refresh every retained active room after a fresh socket proof. */
export const requestAllActiveRooms = async (
  api: RoomRequestApi,
  sendRoomRequest: SendRoomRequest,
  options: ActiveRoomRequestOptions = {},
): Promise<void> => {
  const { rooms } = api.getState() as State;
  const roomUrls = rooms
    .filter((room) => room.signalingActive !== false)
    .map((room) => room.url)
    .sort();
  const requestedConcurrency =
    Number.isSafeInteger(options.concurrency) && (options.concurrency ?? 0) > 0
      ? (options.concurrency as number)
      : ACTIVE_ROOM_REQUEST_CONCURRENCY;
  const concurrency = Math.max(
    1,
    Math.min(roomUrls.length || 1, requestedConcurrency),
  );
  const failures: unknown[] = [];
  let nextRoomIndex = 0;
  const worker = async (): Promise<void> => {
    while (nextRoomIndex < roomUrls.length) {
      const roomUrl = roomUrls[nextRoomIndex++];
      try {
        await requestRoomFromSignalingWithRetry(
          api,
          roomUrl,
          sendRoomRequest,
          options,
        );
      } catch (error) {
        failures.push(error);
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  if (failures.length > 0)
    throw new AggregateError(
      failures,
      `${String(failures.length)} active room refresh(es) failed`,
    );
};
