import { describe, expect, test } from "bun:test";

import {
  areBoundedDataChannelLabels,
  isBoundedDescription,
  isBoundedIceCandidate,
  MAX_DATA_CHANNEL_LABEL_CHARS,
  MAX_ICE_CANDIDATE_CHARS,
  MAX_SDP_CHARS,
  MAX_SIGNALING_LABELS,
} from "../../src/utils/signalingBounds";

describe("signaling input bounds", () => {
  test("bounds SDP before it reaches RTCPeerConnection", () => {
    expect(isBoundedDescription({ type: "offer", sdp: "v=0" })).toBe(true);
    expect(
      isBoundedDescription({ type: "offer", sdp: "x".repeat(MAX_SDP_CHARS + 1) }),
    ).toBe(false);
  });

  test("bounds candidate and auxiliary fields", () => {
    expect(isBoundedIceCandidate({ candidate: "candidate:1" })).toBe(true);
    expect(
      isBoundedIceCandidate({
        candidate: "x".repeat(MAX_ICE_CANDIDATE_CHARS + 1),
      }),
    ).toBe(false);
  });

  test("bounds label count and individual label size", () => {
    expect(areBoundedDataChannelLabels(["main"])).toBe(true);
    expect(
      areBoundedDataChannelLabels(
        Array.from({ length: MAX_SIGNALING_LABELS + 1 }, () => "main"),
      ),
    ).toBe(false);
    expect(
      areBoundedDataChannelLabels([
        "x".repeat(MAX_DATA_CHANNEL_LABEL_CHARS + 1),
      ]),
    ).toBe(false);
  });
});
