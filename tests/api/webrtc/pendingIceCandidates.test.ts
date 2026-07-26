import { describe, expect, test } from "bun:test";

import {
  discardIceCandidatesForAttempt,
  discardPendingIceCandidates,
  enqueueConnectionIceCandidate,
  enqueuePendingIceCandidate,
  MAX_PENDING_ICE_PER_EDGE,
  MAX_PENDING_ICE_TOTAL,
  takePendingIceCandidates,
} from "../../../src/api/webrtc/pendingIceCandidates";

import type { IRTCIceCandidate } from "../../../src/api/webrtc/interfaces";

describe("pending ICE room isolation", () => {
  test("takes only the requested room/peer queue in arrival order", () => {
    const queue: IRTCIceCandidate[] = [];
    enqueuePendingIceCandidate(queue, "room-a", "peer", { candidate: "a-1" });
    enqueuePendingIceCandidate(queue, "room-b", "peer", { candidate: "b-1" });
    enqueuePendingIceCandidate(queue, "room-a", "peer", { candidate: "a-2" });

    expect(
      takePendingIceCandidates(queue, "room-a", "peer").map(
        (candidate) => candidate.candidate,
      ),
    ).toEqual(["a-1", "a-2"]);
    expect(queue).toHaveLength(1);
    expect(queue[0].roomId).toBe("room-b");
  });

  test("discarding one collision does not purge another room", () => {
    const queue: IRTCIceCandidate[] = [];
    enqueuePendingIceCandidate(queue, "room-a", "peer", { candidate: "a" });
    enqueuePendingIceCandidate(queue, "room-b", "peer", { candidate: "b" });

    discardPendingIceCandidates(queue, "room-a", "peer");

    expect(queue).toHaveLength(1);
    expect(queue[0].roomId).toBe("room-b");
  });

  test("abandoning an SDP attempt also clears its per-PC queue room-locally", () => {
    const connectionQueue: RTCIceCandidateInit[] = [
      { candidate: "queued-on-pc" },
    ];
    const pendingQueue: IRTCIceCandidate[] = [];
    enqueuePendingIceCandidate(pendingQueue, "room-a", "peer", {
      candidate: "room-a",
    });
    enqueuePendingIceCandidate(pendingQueue, "room-b", "peer", {
      candidate: "room-b",
    });

    discardIceCandidatesForAttempt(
      connectionQueue,
      pendingQueue,
      "room-a",
      "peer",
    );

    expect(connectionQueue).toHaveLength(0);
    expect(pendingQueue).toHaveLength(1);
    expect(pendingQueue[0].roomId).toBe("room-b");
  });

  test("bounds each room/peer queue and keeps the newest candidates", () => {
    const queue: IRTCIceCandidate[] = [];
    for (let i = 0; i < MAX_PENDING_ICE_PER_EDGE + 5; i++)
      enqueuePendingIceCandidate(queue, "room-a", "peer-a", {
        candidate: `candidate-${String(i)}`,
      });

    const selected = takePendingIceCandidates(queue, "room-a", "peer-a");
    expect(selected).toHaveLength(MAX_PENDING_ICE_PER_EDGE);
    expect(selected[0].candidate).toBe("candidate-5");
  });

  test("bounds the global pre-SDP queue across alias spam", () => {
    const queue: IRTCIceCandidate[] = [];
    for (let i = 0; i < MAX_PENDING_ICE_TOTAL + 5; i++)
      enqueuePendingIceCandidate(queue, `room-${String(i)}`, `peer-${String(i)}`, {
        candidate: `candidate-${String(i)}`,
      });

    expect(queue).toHaveLength(MAX_PENDING_ICE_TOTAL);
    expect(queue[0].candidate).toBe("candidate-5");
  });

  test("bounds candidates waiting on one existing connection", () => {
    const queue: RTCIceCandidateInit[] = [];
    for (let i = 0; i < MAX_PENDING_ICE_PER_EDGE + 2; i++)
      enqueueConnectionIceCandidate(queue, {
        candidate: `candidate-${String(i)}`,
      });

    expect(queue).toHaveLength(MAX_PENDING_ICE_PER_EDGE);
    expect(queue[0].candidate).toBe("candidate-2");
  });
});
