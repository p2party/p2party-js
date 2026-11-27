import { describe, expect, test } from "bun:test";

import {
  claimRatchetGeneration,
  assertCurrentRatchetGeneration,
  releaseRatchetGeneration,
  withEdgeCryptoMutationLock,
} from "../../src/handlers/ratchetPersist";

import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

const connection = (
  roomId: string,
  peerId: string,
  peerPublicKey: string,
): IRTCPeerConnection =>
  ({
    roomId,
    withPeerId: peerId,
    withPeerPublicKey: peerPublicKey,
  }) as unknown as IRTCPeerConnection;

describe("browser ratchet generation", () => {
  test("queued work cannot adopt or expose a key after its generation is replaced", async () => {
    const room = "room-generation";
    const identity = "22".repeat(32);
    const old = connection(room, "old", identity);
    const fresh = connection(room, "new", identity);
    claimRatchetGeneration(old, room);
    const queued = withEdgeCryptoMutationLock(old, async () =>
      assertCurrentRatchetGeneration(old, room),
    );
    claimRatchetGeneration(fresh, room);
    releaseRatchetGeneration(old, room);
    await expect(queued).rejects.toThrow("stale connection owner");
    assertCurrentRatchetGeneration(fresh, room);
    releaseRatchetGeneration(fresh, room);
    expect(() => assertCurrentRatchetGeneration(fresh, room)).toThrow();
  });
});
