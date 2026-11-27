import { deriveRoomLocator, ROOM_LOCATOR_PATTERN } from "./roomLocator";
import {
  MAX_ACTIVE_SIGNALING_ROOMS,
  SIGNALING_PROTOCOL_VERSION,
} from "./constants";
import { isUuidV4, randomUuidV4 } from "./correlationId";

import type {
  WebSocketMessageLeaveRoomRequest,
  WebSocketMessageRoomLeftResponse,
} from "./interfaces";

export const ROOM_LEAVE_ACK_TIMEOUT_MS = 2_000;
export const MAX_PENDING_ROOM_LEAVES = MAX_ACTIVE_SIGNALING_ROOMS;

export type RemoteRoomRevocationFailure =
  | "no-current-socket"
  | "send-failed"
  | "ack-timeout"
  | "socket-closed"
  | "socket-replaced"
  | "ingress-rejected";

/**
 * Local room state and transports are already terminal when this is surfaced.
 * It says only that authoritative unlinking at the rendezvous server was not
 * confirmed; callers may safely forget the local room while reporting that
 * narrower remote uncertainty.
 */
export class RemoteRoomRevocationUnconfirmedError extends Error {
  readonly roomUrl: string;
  readonly roomLeaveId: string;
  readonly reason: RemoteRoomRevocationFailure;

  constructor(
    roomUrl: string,
    roomLeaveId: string,
    reason: RemoteRoomRevocationFailure,
    detail?: string,
  ) {
    super(
      `Remote room revocation was not confirmed (${reason})${
        detail ? `: ${detail}` : ""
      }`,
    );
    this.name = "RemoteRoomRevocationUnconfirmedError";
    this.roomUrl = roomUrl;
    this.roomLeaveId = roomLeaveId;
    this.reason = reason;
  }
}

type SendRoomLeave = (
  request: WebSocketMessageLeaveRoomRequest,
) => void | Promise<unknown>;

interface PendingRoomLeave {
  readonly roomUrl: string;
  readonly roomLeaveId: string;
  readonly socketToken: object;
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (error: RemoteRoomRevocationUnconfirmedError) => void;
  readonly timeout: ReturnType<typeof setTimeout>;
}

const pendingByLeaveId = new Map<string, PendingRoomLeave>();
const pendingLeaveIdByRoomUrl = new Map<string, string>();

export const buildRoomLeaveRequest = (
  fromPeerId: string,
  roomUrl: string,
  roomLeaveId: string = randomUuidV4(),
): WebSocketMessageLeaveRoomRequest => {
  if (!isUuidV4(fromPeerId))
    throw new Error("roomLeave: fromPeerId must be a UUIDv4");
  if (!isUuidV4(roomLeaveId))
    throw new Error("roomLeave: roomLeaveId must be a UUIDv4");
  return {
    type: "leaveRoom",
    protocolVersion: SIGNALING_PROTOCOL_VERSION,
    fromPeerId,
    roomLocator: deriveRoomLocator(roomUrl),
    roomLeaveId,
  };
};

const settlePendingRoomLeave = (
  pending: PendingRoomLeave,
  error?: RemoteRoomRevocationUnconfirmedError,
): boolean => {
  if (pendingByLeaveId.get(pending.roomLeaveId) !== pending) return false;
  pendingByLeaveId.delete(pending.roomLeaveId);
  if (pendingLeaveIdByRoomUrl.get(pending.roomUrl) === pending.roomLeaveId)
    pendingLeaveIdByRoomUrl.delete(pending.roomUrl);
  clearTimeout(pending.timeout);
  if (error) pending.reject(error);
  else pending.resolve();
  return true;
};

export interface RequestRoomLeaveOptions {
  readonly timeoutMs?: number;
  readonly roomLeaveId?: string;
}

/**
 * Install correlation before sending, so even a synchronous in-memory server
 * acknowledgement cannot outrun the waiter.
 */
export const requestRoomLeaveAcknowledgement = (
  fromPeerId: string,
  roomUrl: string,
  socketToken: object,
  send: SendRoomLeave,
  options: RequestRoomLeaveOptions = {},
): Promise<void> => {
  const existingId = pendingLeaveIdByRoomUrl.get(roomUrl);
  if (existingId) {
    const existing = pendingByLeaveId.get(existingId);
    if (existing) {
      if (existing.socketToken === socketToken) return existing.promise;
      return Promise.reject(
        new RemoteRoomRevocationUnconfirmedError(
          roomUrl,
          options.roomLeaveId ?? randomUuidV4(),
          "socket-replaced",
          "another socket owns the pending leave",
        ),
      );
    }
    pendingLeaveIdByRoomUrl.delete(roomUrl);
  }
  if (pendingByLeaveId.size >= MAX_PENDING_ROOM_LEAVES)
    return Promise.reject(
      new RemoteRoomRevocationUnconfirmedError(
        roomUrl,
        options.roomLeaveId ?? randomUuidV4(),
        "send-failed",
        "pending leave bound is exhausted",
      ),
    );

  const request = buildRoomLeaveRequest(
    fromPeerId,
    roomUrl,
    options.roomLeaveId ?? randomUuidV4(),
  );
  let resolvePromise!: () => void;
  let rejectPromise!: (error: RemoteRoomRevocationUnconfirmedError) => void;
  const promise = new Promise<void>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const timeoutMs = options.timeoutMs ?? ROOM_LEAVE_ACK_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)
    return Promise.reject(
      new Error("roomLeave: timeout must be a positive integer"),
    );
  const pending = {
    roomUrl,
    roomLeaveId: request.roomLeaveId,
    socketToken,
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
    timeout: undefined as unknown as ReturnType<typeof setTimeout>,
  };
  pending.timeout = setTimeout(() => {
    settlePendingRoomLeave(
      pending,
      new RemoteRoomRevocationUnconfirmedError(
        roomUrl,
        request.roomLeaveId,
        "ack-timeout",
      ),
    );
  }, timeoutMs);
  pendingByLeaveId.set(request.roomLeaveId, pending);
  pendingLeaveIdByRoomUrl.set(roomUrl, request.roomLeaveId);

  try {
    void Promise.resolve(send(request)).catch((error: unknown) => {
      settlePendingRoomLeave(
        pending,
        new RemoteRoomRevocationUnconfirmedError(
          roomUrl,
          request.roomLeaveId,
          "send-failed",
          error instanceof Error ? error.message : String(error),
        ),
      );
    });
  } catch (error) {
    settlePendingRoomLeave(
      pending,
      new RemoteRoomRevocationUnconfirmedError(
        roomUrl,
        request.roomLeaveId,
        "send-failed",
        error instanceof Error ? error.message : String(error),
      ),
    );
  }
  return promise;
};

export const hasExactRoomLeftShape = (
  message: WebSocketMessageRoomLeftResponse,
): boolean => {
  if (
    typeof message !== "object" ||
    message === null ||
    Object.getPrototypeOf(message) !== Object.prototype
  )
    return false;
  const keys = Object.keys(message).sort();
  return (
    keys.length === 4 &&
    keys[0] === "protocolVersion" &&
    keys[1] === "roomLeaveId" &&
    keys[2] === "roomLocator" &&
    keys[3] === "type" &&
    message.type === "roomLeft" &&
    message.protocolVersion === SIGNALING_PROTOCOL_VERSION &&
    typeof message.roomLocator === "string" &&
    ROOM_LOCATOR_PATTERN.test(message.roomLocator) &&
    isUuidV4(message.roomLeaveId)
  );
};

/** Parse only the tiny exact ack shape used by the socket fast path. */
export const parseRoomLeftAcknowledgement = (
  data: unknown,
): WebSocketMessageRoomLeftResponse | null => {
  if (typeof data !== "string" || data.length === 0 || data.length > 256)
    return null;
  for (const key of ["type", "protocolVersion", "roomLocator", "roomLeaveId"])
    if ((data.match(new RegExp(`"${key}"\\s*:`, "g")) ?? []).length !== 1)
      return null;
  try {
    const parsed = JSON.parse(data) as WebSocketMessageRoomLeftResponse;
    return hasExactRoomLeftShape(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

/**
 * Settle only the exact socket+room+nonce waiter. The acknowledgement has no
 * reducer side effect, so a duplicate or late frame cannot resurrect a room.
 */
export const acknowledgeRoomLeft = (
  message: WebSocketMessageRoomLeftResponse,
  socketToken: object,
): boolean => {
  if (!hasExactRoomLeftShape(message)) return false;
  const pending = pendingByLeaveId.get(message.roomLeaveId);
  if (
    !pending ||
    pending.socketToken !== socketToken ||
    deriveRoomLocator(pending.roomUrl) !== message.roomLocator
  )
    return false;
  return settlePendingRoomLeave(pending);
};

export const cancelRoomLeavesForSocket = (
  socketToken: object,
  reason: Exclude<
    RemoteRoomRevocationFailure,
    "no-current-socket" | "send-failed" | "ack-timeout"
  >,
): number => {
  let cancelled = 0;
  for (const pending of [...pendingByLeaveId.values()]) {
    if (pending.socketToken !== socketToken) continue;
    if (
      settlePendingRoomLeave(
        pending,
        new RemoteRoomRevocationUnconfirmedError(
          pending.roomUrl,
          pending.roomLeaveId,
          reason,
        ),
      )
    )
      cancelled += 1;
  }
  return cancelled;
};

export const pendingRoomLeaveCount = (): number => pendingByLeaveId.size;
