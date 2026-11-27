import { describe, expect, test } from "bun:test";

import {
  isFreshSignalingChallenge,
  hasCurrentSocketProof,
  isSignalingChallengeSuccess,
} from "../../src/utils/signalingAuth";

const peerId = "00000000-0000-4000-8000-000000000123";
const challengeId = "00000000-0000-4000-8000-000000000456";

describe("v5 signaling authentication contract", () => {
  test("accepts only a fresh, exact v5 server challenge", () => {
    const valid = {
      type: "authChallenge",
      challenge: "ab".repeat(32),
      protocolVersion: 5,
    };
    expect(isFreshSignalingChallenge(valid)).toBe(true);
    expect(isFreshSignalingChallenge({ ...valid, protocolVersion: 2 })).toBe(
      false,
    );
    expect(
      isFreshSignalingChallenge({ ...valid, challenge: "AB".repeat(32) }),
    ).toBe(false);
    expect(
      isFreshSignalingChallenge({
        ...valid,
        challengeId,
        signature: "00".repeat(64),
      }),
    ).toBe(false);
  });

  test("accepts only exact v5 success; TURN belongs to the room response", () => {
    const valid = {
      type: "challenge",
      challengeId,
      peerId,
      protocolVersion: 5,
    };
    expect(isSignalingChallengeSuccess(valid)).toBe(true);
    expect(
      isSignalingChallengeSuccess({
        ...valid,
        username: "turn-user",
        credential: "turn-secret",
      }),
    ).toBe(false);
    expect(
      isSignalingChallengeSuccess({
        ...valid,
        urls: ["turns:turn.example:443"],
        username: "turn-user",
        credential: "turn-secret",
      }),
    ).toBe(false);
    expect(
      isSignalingChallengeSuccess({ ...valid, protocolVersion: undefined }),
    ).toBe(false);
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
