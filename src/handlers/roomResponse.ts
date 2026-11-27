import { deriveRoomLocator, ROOM_LOCATOR_PATTERN } from "../utils/roomLocator";
import { isUUID } from "../utils/formatValidation";

import {
  applyRoomResponse,
  deriveEffectiveRTCConfig,
} from "../reducers/roomSlice";
import { isProtocolVersionCompatible } from "../utils/protocolVersion";
import { parseTurnCredentials } from "../utils/signalingAuth";

import type { ManagedRoom } from "../reducers/roomSlice";
import type {
  TurnCredentials,
  WebSocketMessageRoomIdResponse,
} from "../utils/interfaces";
import type { PendingRoomResponseClaim } from "../utils/roomRequestCoordinator";

const ROOM_RESPONSE_KEYS = new Set([
  "type",
  "roomId",
  "roomLocator",
  "roomRequestId",
  "protocolVersion",
  "turnCredentials",
]);
const REQUIRED_ROOM_RESPONSE_KEYS = [
  "type",
  "roomId",
  "roomLocator",
  "roomRequestId",
  "protocolVersion",
] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactRoomResponseShape = (value: Record<string, unknown>): boolean => {
  const keys = Object.keys(value);
  return (
    keys.every((key) => ROOM_RESPONSE_KEYS.has(key)) &&
    REQUIRED_ROOM_RESPONSE_KEYS.every((key) =>
      Object.prototype.hasOwnProperty.call(value, key),
    )
  );
};

export interface RoomResponseCorrelation {
  readonly roomLocator: string;
  readonly roomRequestId: string;
}

/**
 * Read only the correlation tuple. No pending request is consumed until this
 * tuple has been proven to be the exact current wire nonce.
 */
export const parseRoomResponseCorrelation = (
  value: unknown,
): RoomResponseCorrelation | null => {
  if (!isRecord(value)) return null;
  const { roomLocator, roomRequestId } = value;
  if (
    typeof roomLocator !== "string" ||
    !ROOM_LOCATOR_PATTERN.test(roomLocator) ||
    typeof roomRequestId !== "string" ||
    !isUUID(roomRequestId, 4)
  )
    return null;
  return { roomLocator, roomRequestId };
};

export type RoomResponsePlan =
  | {
      accepted: true;
      action: ReturnType<typeof applyRoomResponse>;
      roomId: string;
      roomUrl: string;
      roomRequestId: string;
      requestGeneration: number;
      expiresAtUnixSeconds: number | null;
      nextRtcConfig: RTCConfiguration;
    }
  | {
      accepted: false;
      reason:
        | "malformed-room-response"
        | "malformed-turn-credentials"
        | "unknown-room"
        | "room-id-reassignment"
        | "room-id-collision"
        | "stale-room-response";
    };

/**
 * Validate one wire-correlated response and derive its single Redux commit.
 *
 * Room identity and the signaling-owned TURN bundle change in one reducer
 * action. No observer can see a new room ID paired with old credentials.
 */
export const planRoomResponse = (
  value: unknown,
  rooms: readonly ManagedRoom[],
  claim: PendingRoomResponseClaim,
  nowMs = Date.now(),
): RoomResponsePlan => {
  if (!isRecord(value) || !hasExactRoomResponseShape(value))
    return { accepted: false, reason: "malformed-room-response" };

  const message = value as unknown as WebSocketMessageRoomIdResponse;
  if (
    message.type !== "roomId" ||
    !isProtocolVersionCompatible(message.protocolVersion) ||
    !isUUID(message.roomId, 4) ||
    !ROOM_LOCATOR_PATTERN.test(message.roomLocator) ||
    !isUUID(message.roomRequestId, 4) ||
    message.roomLocator !== deriveRoomLocator(claim.roomUrl) ||
    message.roomRequestId !== claim.roomRequestId
  )
    return { accepted: false, reason: "malformed-room-response" };

  const room = rooms.find((candidate) => candidate.url === claim.roomUrl);
  if (!room || room.signalingActive === false)
    return { accepted: false, reason: "unknown-room" };
  if (isUUID(room.id) && room.id !== message.roomId)
    return { accepted: false, reason: "room-id-reassignment" };
  if (
    rooms.some(
      (candidate) =>
        candidate.url !== claim.roomUrl && candidate.id === message.roomId,
    )
  )
    return { accepted: false, reason: "room-id-collision" };
  if (claim.requestGeneration <= (room.roomResponseGeneration ?? 0))
    return { accepted: false, reason: "stale-room-response" };

  const turn =
    message.turnCredentials === undefined
      ? null
      : parseTurnCredentials(message.turnCredentials, nowMs);
  if (message.turnCredentials !== undefined && turn === null)
    return { accepted: false, reason: "malformed-turn-credentials" };

  return {
    accepted: true,
    action: applyRoomResponse({
      roomId: message.roomId,
      roomUrl: claim.roomUrl,
      roomRequestId: message.roomRequestId,
      requestGeneration: claim.requestGeneration,
      turnCredentials: turn,
    }),
    roomId: message.roomId,
    roomUrl: claim.roomUrl,
    roomRequestId: message.roomRequestId,
    requestGeneration: claim.requestGeneration,
    expiresAtUnixSeconds: turn?.expiresAtUnixSeconds ?? null,
    nextRtcConfig: deriveEffectiveRTCConfig(
      room.callerRtcConfig ?? room.rtcConfig,
      turn,
    ),
  };
};

export type AcceptedRoomResponsePlan = Extract<
  RoomResponsePlan,
  { accepted: true }
>;

export interface AuthoritativeRoomResponseState {
  id: string;
  roomResponseGeneration: number;
  rtcConfig: RTCConfiguration;
  signalingTurnCredentials: TurnCredentials | null;
  signalingActive: boolean;
}

/** True only when an expiry reducer just removed this exact live generation. */
export const isExactExpiredTurnGeneration = (
  room: AuthoritativeRoomResponseState | undefined,
  plan: Pick<AcceptedRoomResponsePlan, "roomId" | "requestGeneration">,
): room is AuthoritativeRoomResponseState =>
  room !== undefined &&
  room.signalingActive &&
  room.id === plan.roomId &&
  room.roomResponseGeneration === plan.requestGeneration &&
  room.signalingTurnCredentials === null;

/**
 * Apply live browser configuration before publishing the Redux generation.
 *
 * If setConfiguration() rejects, the old state and old refresh timer remain
 * authoritative and retryable. Publishing first could orphan the new expiry
 * with no timer while live PCs still used the old credential.
 */
export const commitRoomResponsePlan = async (
  plan: AcceptedRoomResponsePlan,
  applyLiveConfiguration: (
    roomId: string,
    rtcConfig: RTCConfiguration,
    failurePolicy: "rollback" | "close",
  ) => Promise<void>,
  canPublish: () => boolean,
  publish: () => boolean,
  readRoom: (roomUrl: string) => AuthoritativeRoomResponseState | undefined,
  rollbackPublishedState: (
    previous: AuthoritativeRoomResponseState,
  ) => void = () => undefined,
): Promise<boolean> => {
  if (!canPublish()) return false;
  const authoritative = readRoom(plan.roomUrl);
  if (!authoritative) return false;
  await applyLiveConfiguration(plan.roomId, plan.nextRtcConfig, "rollback");
  if (!canPublish()) {
    const current = readRoom(plan.roomUrl);
    await applyLiveConfiguration(
      plan.roomId,
      current?.rtcConfig ?? authoritative.rtcConfig,
      "close",
    );
    return false;
  }
  let committed: boolean;
  try {
    committed = publish();
  } catch (error) {
    rollbackPublishedState(authoritative);
    const restored = readRoom(plan.roomUrl);
    await applyLiveConfiguration(
      plan.roomId,
      restored?.rtcConfig ?? authoritative.rtcConfig,
      "close",
    );
    throw error;
  }
  if (!committed) {
    rollbackPublishedState(authoritative);
    const restored = readRoom(plan.roomUrl);
    await applyLiveConfiguration(
      plan.roomId,
      restored?.rtcConfig ?? authoritative.rtcConfig,
      "close",
    );
  }
  return committed;
};
