import { describe, expect, test } from "bun:test";

import { mergePeerRosterDelta } from "../../src/handlers/peerRosterDelta";

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
});
