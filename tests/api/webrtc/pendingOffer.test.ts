import { describe, expect, test } from "bun:test";

import {
  hasUnansweredFirstOffer,
  PENDING_OFFER_TIMEOUT_MS,
} from "../../../src/api/webrtc/pendingOffer";

const transport = (
  signalingState: RTCSignalingState,
  remoteDescription: RTCSessionDescription | null,
) => ({ signalingState, remoteDescription });

const ANSWER = { type: "answer", sdp: "v=0\r\n" } as RTCSessionDescription;

describe("hasUnansweredFirstOffer", () => {
  test("a local offer on a transport that never had a remote description is unanswered", () => {
    expect(hasUnansweredFirstOffer(transport("have-local-offer", null))).toBe(
      true,
    );
  });

  test("an ICE-restart offer on a negotiated transport is not a first offer", () => {
    expect(hasUnansweredFirstOffer(transport("have-local-offer", ANSWER))).toBe(
      false,
    );
  });

  test("a stable or closed transport holds no pending offer", () => {
    expect(hasUnansweredFirstOffer(transport("stable", null))).toBe(false);
    expect(
      hasUnansweredFirstOffer(transport("have-remote-offer", ANSWER)),
    ).toBe(false);
    expect(hasUnansweredFirstOffer(transport("closed", null))).toBe(false);
  });

  test("the watchdog outlives the signaling server's dark-socket drop", () => {
    // The server drops a socket that misses one 10 s ping plus its 5 s pong
    // window. A peer that was still on the roster when we offered into its
    // dark socket has left the roster by the time this fires.
    expect(PENDING_OFFER_TIMEOUT_MS).toBeGreaterThanOrEqual(15_000);
  });
});
