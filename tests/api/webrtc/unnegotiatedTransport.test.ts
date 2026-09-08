import { afterEach, describe, expect, test } from "bun:test";

import {
  MAX_UNNEGOTIATED_TRANSPORT_REBUILDS,
  clearUnnegotiatedTransportRebuilds,
  mayRebuildUnnegotiatedTransport,
  recordUnnegotiatedTransportRebuild,
  unnegotiatedTransportRebuilds,
} from "../../../src/api/webrtc/unnegotiatedTransport";
import { hasNoNegotiatedDescription } from "../../../src/api/webrtc/pendingOffer";

const ROOM = "00000000-0000-4000-8000-0000000000b1";
const PEER = "00000000-0000-4000-8000-0000000000b2";

afterEach(() => {
  clearUnnegotiatedTransportRebuilds(ROOM, PEER);
});

describe("un-negotiated responder transport", () => {
  test("a transport with no description either way is un-negotiated", () => {
    expect(
      hasNoNegotiatedDescription({
        signalingState: "stable",
        localDescription: null,
        remoteDescription: null,
      } as never),
    ).toBe(true);
  });

  test("a transport that offered, or that answered, is not un-negotiated", () => {
    expect(
      hasNoNegotiatedDescription({
        signalingState: "have-local-offer",
        localDescription: { type: "offer", sdp: "" },
        remoteDescription: null,
      } as never),
    ).toBe(false);
    expect(
      hasNoNegotiatedDescription({
        signalingState: "stable",
        localDescription: { type: "answer", sdp: "" },
        remoteDescription: { type: "offer", sdp: "" },
      } as never),
    ).toBe(false);
    // `stable` with a local description and no remote one is not a state the
    // negotiation machine produces, so the signalingState test alone would let
    // it through. It is exactly the shape a rollback race or a UA that reports
    // state and descriptions out of step can leave behind, and tearing such a
    // transport down would discard an offer that IS in flight. The predicate
    // asks about descriptions, so it must actually look at both of them.
    expect(
      hasNoNegotiatedDescription({
        signalingState: "stable",
        localDescription: { type: "offer", sdp: "" },
        remoteDescription: null,
      } as never),
    ).toBe(false);
  });

  test("rebuilds are counted per room/peer and capped", () => {
    expect(mayRebuildUnnegotiatedTransport(ROOM, PEER)).toBe(true);
    for (let i = 1; i <= MAX_UNNEGOTIATED_TRANSPORT_REBUILDS; i++)
      expect(recordUnnegotiatedTransportRebuild(ROOM, PEER)).toBe(i);
    expect(unnegotiatedTransportRebuilds(ROOM, PEER)).toBe(
      MAX_UNNEGOTIATED_TRANSPORT_REBUILDS,
    );
    // Against a pre-generation server the peer never rebuilds its own side, so
    // an uncapped watchdog would tear down and re-dial every 15 s forever.
    expect(mayRebuildUnnegotiatedTransport(ROOM, PEER)).toBe(false);
  });

  test("a negotiated transport clears the count", () => {
    recordUnnegotiatedTransportRebuild(ROOM, PEER);
    clearUnnegotiatedTransportRebuilds(ROOM, PEER);
    expect(unnegotiatedTransportRebuilds(ROOM, PEER)).toBe(0);
    expect(mayRebuildUnnegotiatedTransport(ROOM, PEER)).toBe(true);
  });

  test("counts do not leak between edges", () => {
    const other = "00000000-0000-4000-8000-0000000000b3";
    recordUnnegotiatedTransportRebuild(ROOM, PEER);
    expect(unnegotiatedTransportRebuilds(ROOM, other)).toBe(0);
    clearUnnegotiatedTransportRebuilds(ROOM, other);
  });
});
