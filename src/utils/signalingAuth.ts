import { isUUID } from "./formatValidation";

import { isProtocolVersionCompatible } from "./protocolVersion";

import type {
  TurnCredentials,
  WebSocketMessageChallengeRequest,
  WebSocketMessageSuccessfulChallenge,
} from "./interfaces";

const MAX_TURN_URLS = 16;
const MAX_TURN_URL_CHARS = 2048;
const MAX_TURN_CREDENTIAL_CHARS = 256;
export const MIN_TURN_CREDENTIAL_REMAINING_SECONDS = 30;
export const MAX_TURN_CREDENTIAL_LIFETIME_SECONDS = 24 * 60 * 60;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasOnlyKeys = (
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean => {
  const keys = Object.keys(value);
  return (
    keys.length === allowed.length && keys.every((key) => allowed.includes(key))
  );
};

/** Stale bearer-shaped key fields never authenticate a replacement socket. */
export const hasCurrentSocketProof = (
  keyPair: {
    peerId: string;
    challenge: string;
    signature: string;
  },
  signalingServer: {
    isConnected: boolean;
    isVerified: boolean;
  },
): boolean =>
  signalingServer.isConnected &&
  signalingServer.isVerified &&
  isUUID(keyPair.peerId) &&
  /^[0-9a-f]{64}$/u.test(keyPair.challenge) &&
  /^[0-9a-f]{128}$/u.test(keyPair.signature);

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

/** Exact protocol-v3 proof-success response. TURN is issued only at room join. */
export const isV3ChallengeSuccess = (
  value: unknown,
): value is WebSocketMessageSuccessfulChallenge => {
  if (!isRecord(value)) return false;
  return (
    hasOnlyKeys(value, ["type", "challengeId", "protocolVersion"]) &&
    value.type === "challenge" &&
    typeof value.challengeId === "string" &&
    isUUID(value.challengeId) &&
    typeof value.protocolVersion === "number" &&
    isProtocolVersionCompatible(value.protocolVersion)
  );
};

/**
 * Decode the one nested TURN credential object used by room responses.
 *
 * The server controls the relay, but only bounded `turn:`/`turns:` URIs may
 * reach the browser ICE stack. Rejecting the complete object on one malformed
 * field keeps this a closed wire contract rather than a best-effort filter.
 */
export const parseTurnCredentials = (
  value: unknown,
  nowMs = Date.now(),
  expectedPublicKey?: string,
): TurnCredentials | null => {
  if (!isRecord(value)) return null;
  if (
    !hasOnlyKeys(value, [
      "urls",
      "username",
      "credential",
      "expiresAtUnixSeconds",
    ])
  )
    return null;
  const nowUnixSeconds = Math.floor(nowMs / 1_000);
  if (
    !Array.isArray(value.urls) ||
    value.urls.length === 0 ||
    value.urls.length > MAX_TURN_URLS ||
    !value.urls.every(
      (url): url is string =>
        typeof url === "string" &&
        url.length > 0 &&
        url.length <= MAX_TURN_URL_CHARS &&
        /^turns?:[^\s]+$/u.test(url),
    ) ||
    new Set(value.urls).size !== value.urls.length ||
    typeof value.username !== "string" ||
    value.username.length === 0 ||
    value.username.length > MAX_TURN_CREDENTIAL_CHARS ||
    typeof value.credential !== "string" ||
    value.credential.length === 0 ||
    value.credential.length > MAX_TURN_CREDENTIAL_CHARS ||
    typeof value.expiresAtUnixSeconds !== "number" ||
    !Number.isSafeInteger(value.expiresAtUnixSeconds) ||
    value.expiresAtUnixSeconds <
      nowUnixSeconds + MIN_TURN_CREDENTIAL_REMAINING_SECONDS ||
    value.expiresAtUnixSeconds >
      nowUnixSeconds + MAX_TURN_CREDENTIAL_LIFETIME_SECONDS
  )
    return null;

  const usernameBinding = /^([1-9][0-9]{0,10}):([0-9a-f]{64})$/u.exec(
    value.username,
  );
  if (
    usernameBinding === null ||
    Number(usernameBinding[1]) !== value.expiresAtUnixSeconds ||
    (expectedPublicKey !== undefined &&
      usernameBinding[2] !== expectedPublicKey)
  )
    return null;

  return {
    urls: [...value.urls],
    username: value.username,
    credential: value.credential,
    expiresAtUnixSeconds: value.expiresAtUnixSeconds,
  };
};
