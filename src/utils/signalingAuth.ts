import { isUUID } from "class-validator";

import { isProtocolVersionCompatible } from "./protocolVersion";

import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageSuccessfulChallenge,
} from "./interfaces";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasOnlyKeys = (
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean => {
  const keys = Object.keys(value);
  return keys.length === allowed.length &&
    keys.every((key) => allowed.includes(key));
};

/**
 * Exact protocol-v3 server challenge. Legacy reconnect credentials are
 * deliberately not accepted: every WebSocket must prove possession anew.
 */
export const isFreshV3Challenge = (
  value: unknown,
): value is WebSocketMessageChallengeRequest => {
  if (!isRecord(value)) return false;
  return (
    hasOnlyKeys(value, [
      "type",
      "peerId",
      "challenge",
      "protocolVersion",
      "message",
    ]) &&
    value.type === "peerId" &&
    typeof value.peerId === "string" &&
    isUUID(value.peerId) &&
    typeof value.challenge === "string" &&
    /^[0-9a-f]{64}$/.test(value.challenge) &&
    typeof value.protocolVersion === "number" &&
    isProtocolVersionCompatible(value.protocolVersion) &&
    typeof value.message === "string"
  );
};

/** Exact protocol-v3 proof-success response, with an all-or-none TURN pair. */
export const isV3ChallengeSuccess = (
  value: unknown,
): value is WebSocketMessageSuccessfulChallenge => {
  if (!isRecord(value)) return false;
  const hasTurnUsername = Object.hasOwn(value, "username");
  const hasTurnCredential = Object.hasOwn(value, "credential");
  const allowed = hasTurnUsername
    ? ["type", "challengeId", "protocolVersion", "username", "credential"]
    : ["type", "challengeId", "protocolVersion"];
  return (
    hasTurnUsername === hasTurnCredential &&
    hasOnlyKeys(value, allowed) &&
    value.type === "challenge" &&
    typeof value.challengeId === "string" &&
    isUUID(value.challengeId) &&
    typeof value.protocolVersion === "number" &&
    isProtocolVersionCompatible(value.protocolVersion) &&
    (!hasTurnUsername ||
      (typeof value.username === "string" &&
        value.username.length > 0 &&
        typeof value.credential === "string" &&
        value.credential.length > 0))
  );
};
