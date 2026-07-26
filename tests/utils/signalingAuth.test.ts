import { describe, expect, test } from "bun:test";

import {
  isFreshV3Challenge,
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

  test("accepts exact v3 success with either both TURN fields or neither", () => {
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
    ).toBe(true);
    expect(isV3ChallengeSuccess({ ...valid, username: "turn-user" })).toBe(
      false,
    );
    expect(isV3ChallengeSuccess({ ...valid, protocolVersion: undefined })).toBe(
      false,
    );
  });
});
