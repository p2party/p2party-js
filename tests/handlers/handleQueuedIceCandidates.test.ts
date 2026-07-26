import { describe, expect, test } from "bun:test";

import {
  candidateIceUsernameFragment,
  candidateMatchesRemoteIceGeneration,
  remoteIceUsernameFragments,
} from "../../src/api/webrtc/iceGeneration";
import { handleQueuedIceCandidates } from "../../src/handlers/handleQueuedIceCandidates";

import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

const remoteDescription = {
  type: "answer",
  sdp:
    "v=0\r\n" +
    "a=ice-ufrag:active-session\r\n" +
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
    "a=ice-ufrag:active-media\r\n",
} as RTCSessionDescription;

describe("remote ICE generation validation", () => {
  test("extracts active SDP generations and candidate-string ufrag fallback", () => {
    expect([...remoteIceUsernameFragments(remoteDescription)]).toEqual([
      "active-session",
      "active-media",
    ]);
    expect(
      candidateIceUsernameFragment({
        candidate:
          "candidate:1 1 UDP 1 192.0.2.1 5000 typ host ufrag active-media",
      }),
    ).toBe("active-media");
    expect(
      candidateMatchesRemoteIceGeneration(
        { candidate: "candidate:1", usernameFragment: "active-session" },
        remoteDescription,
      ),
    ).toBe(true);
    expect(
      candidateMatchesRemoteIceGeneration(
        { candidate: "candidate:2", usernameFragment: "stale-generation" },
        remoteDescription,
      ),
    ).toBe(false);
    // Missing ufrag remains interoperable with older signaling payloads.
    expect(
      candidateMatchesRemoteIceGeneration(
        { candidate: "candidate:3", sdpMid: "0" },
        remoteDescription,
      ),
    ).toBe(true);
  });

  test("adds matching queued candidates and drops only stale generations", async () => {
    const added: RTCIceCandidateInit[] = [];
    const matching = {
      candidate: "candidate:matching",
      usernameFragment: "active-session",
    };
    const stale = {
      candidate: "candidate:stale",
      usernameFragment: "old-session",
    };
    const withoutUfrag = { candidate: "candidate:legacy", sdpMid: "0" };
    const epc = {
      signalingState: "stable",
      remoteDescription,
      iceCandidates: [matching, stale, withoutUfrag],
      addIceCandidate: async (candidate: RTCIceCandidateInit) => {
        added.push(candidate);
      },
    } as unknown as IRTCPeerConnection;

    await handleQueuedIceCandidates(epc);

    expect(added).toEqual([matching, withoutUfrag]);
    expect(epc.iceCandidates).toHaveLength(0);
  });

  test("one rejected candidate does not strand later candidates", async () => {
    const rejected = {
      candidate: "candidate:rejected",
      usernameFragment: "active-session",
    };
    const accepted = {
      candidate: "candidate:accepted",
      usernameFragment: "active-session",
    };
    const attempted: RTCIceCandidateInit[] = [];
    const epc = {
      signalingState: "stable",
      remoteDescription,
      iceCandidates: [rejected, accepted],
      addIceCandidate: async (candidate: RTCIceCandidateInit) => {
        attempted.push(candidate);
        if (candidate === rejected) throw new Error("candidate rejected");
      },
    } as unknown as IRTCPeerConnection;

    await handleQueuedIceCandidates(epc);

    expect(attempted).toEqual([rejected, accepted]);
    expect(epc.iceCandidates).toHaveLength(0);
  });
});
