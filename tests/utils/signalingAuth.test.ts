import { describe, expect, test } from "bun:test";

import {
  isFreshV3Challenge,
  hasCurrentSocketProof,
  isV3ChallengeSuccess,
} from "../../src/utils/signalingAuth";

const peerId = "00000000-0000-4000-8000-000000000123";
const challengeId = "00000000-0000-4000-8000-000000000456";

describe("protocol-v3 signaling authentication contract", () => {
  test("accepts only a fresh, exact v3 server challenge", () => {
    const valid = {
      type: "peerId",
      peerId,
      challenge: "ab".repeat(32),
      protocolVersion: 4,
      message: "sign this nonce",
    };
    expect(isFreshV3Challenge(valid)).toBe(true);
    expect(isFreshV3Challenge({ ...valid, protocolVersion: 2 })).toBe(false);
    expect(isFreshV3Challenge({ ...valid, challenge: "AB".repeat(32) })).toBe(
      false,
    );
    expect(
      isFreshV3Challenge({ ...valid, challengeId, signature: "00".repeat(64) }),
    ).toBe(false);
  });

  test("accepts only exact v3 success; TURN belongs to the room response", () => {
    const valid = {
      type: "challenge",
      challengeId,
      protocolVersion: 4,
    };
    expect(isV3ChallengeSuccess(valid)).toBe(true);
    expect(
      isV3ChallengeSuccess({
        ...valid,
        username: "turn-user",
        credential: "turn-secret",
      }),
    ).toBe(false);
    expect(
      isV3ChallengeSuccess({
        ...valid,
        urls: ["turns:turn.example:443"],
        username: "turn-user",
        credential: "turn-secret",
      }),
    ).toBe(false);
    expect(isV3ChallengeSuccess({ ...valid, protocolVersion: undefined })).toBe(
      false,
    );
  });

  test("stale proof-shaped key fields do not authenticate an unverified replacement socket", () => {
    const keyPair = {
      peerId,
      challenge: "ab".repeat(32),
      signature: "cd".repeat(64),
    };
    expect(
      hasCurrentSocketProof(keyPair, {
        isConnected: true,
        isVerified: false,
      }),
    ).toBe(false);
    expect(
      hasCurrentSocketProof(keyPair, {
        isConnected: true,
        isVerified: true,
      }),
    ).toBe(true);
    expect(
      hasCurrentSocketProof(keyPair, {
        isConnected: false,
        isVerified: true,
      }),
    ).toBe(false);
  });
});
