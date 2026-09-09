import { describe, expect, test } from "bun:test";

import { mergePeerRosterDelta } from "../../src/handlers/peerRosterDelta";
import { MAX_SIGNALING_ROOM_PEERS } from "../../src/utils/signalingBounds";

describe("incremental signaling peer roster", () => {
  test("interleaved one-peer deltas converge to both remote room members", () => {
    const self = {
      peerId: "00000000-0000-4000-8000-000000000001",
      publicKey: "11".repeat(32),
    };
    const first = {
      id: "00000000-0000-4000-8000-000000000002",
      publicKey: "22".repeat(32),
    };
    const second = {
      id: "00000000-0000-4000-8000-000000000003",
      publicKey: "33".repeat(32),
    };

    let peers = mergePeerRosterDelta([], [first], self);
    peers = mergePeerRosterDelta(peers, [second], self);
    peers = mergePeerRosterDelta(peers, [first], self);

    expect(peers).toEqual([
      { peerId: first.id, peerPublicKey: first.publicKey },
      { peerId: second.id, peerPublicKey: second.publicKey },
    ]);
  });

  test("filters self, malformed entries, and stable-id key conflicts", () => {
    const self = {
      peerId: "00000000-0000-4000-8000-000000000001",
      publicKey: "11".repeat(32),
    };
    const peer = {
      id: "00000000-0000-4000-8000-000000000002",
      publicKey: "22".repeat(32),
    };
    const current = [{ peerId: peer.id, peerPublicKey: peer.publicKey }];

    expect(
      mergePeerRosterDelta(
        current,
        [
          { id: self.peerId, publicKey: self.publicKey },
          { id: "not-a-uuid", publicKey: "33".repeat(32) },
          { id: peer.id, publicKey: "44".repeat(32) },
        ],
        self,
      ),
    ).toEqual(current);
  });

  test("fails closed when cumulative unique peers exceed the room cap", () => {
    const self = {
      peerId: "00000000-0000-4000-8000-000000000001",
      publicKey: "11".repeat(32),
    };
    const current = Array.from(
      { length: MAX_SIGNALING_ROOM_PEERS },
      (_, index) => ({
        peerId: `00000000-0000-4000-8000-${(index + 2)
          .toString(16)
          .padStart(12, "0")}`,
        peerPublicKey: (index + 2).toString(16).padStart(64, "0"),
      }),
    );
    const overflow = {
      id: "00000000-0000-4000-8000-000000000fff",
      publicKey: "ff".repeat(32),
    };

    expect(() => mergePeerRosterDelta(current, [overflow], self)).toThrow(
      "room edge cap",
    );
    expect(current).toHaveLength(MAX_SIGNALING_ROOM_PEERS);
  });

  test("rejects an oversized delta before per-peer processing", () => {
    const self = {
      peerId: "00000000-0000-4000-8000-000000000001",
      publicKey: "11".repeat(32),
    };
    const oversized = Array.from(
      { length: MAX_SIGNALING_ROOM_PEERS + 1 },
      (_, index) => ({
        id: `00000000-0000-4000-8000-${(index + 2)
          .toString(16)
          .padStart(12, "0")}`,
        publicKey: (index + 2).toString(16).padStart(64, "0"),
      }),
    );

    expect(() => mergePeerRosterDelta([], oversized, self)).toThrow(
      "room edge cap",
    );
  });
});
