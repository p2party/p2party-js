import { describe, expect, test } from "bun:test";

import {
  claimRatchetPersistence,
  persistAndActivateClaimedRatchetState,
} from "./ratchetPersist";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type { RatchetState } from "../cryptography/ratchet";

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

const state = (): RatchetState => ({
  rootKey: new Uint8Array(32),
  sendingChainKey: null,
  receivingChainKey: null,
  dhSelfPub: new Uint8Array(32),
  dhSelfSec: new Uint8Array(32),
  dhRemotePub: null,
  Ns: 0,
  Nr: 0,
  PN: 0,
  skipped: new Map(),
});

describe("initial ratchet persistence/activation", () => {
  test("gate activation failure rolls back the just-written seed", async () => {
    const epc = connection("room-establish-1", "peer-1", "11".repeat(32));
    claimRatchetPersistence(epc, epc.roomId);
    const events: string[] = [];

    await expect(
      persistAndActivateClaimedRatchetState(
        epc,
        state(),
        epc.roomId,
        () => {
          events.push("activate");
          throw new Error("gate already closed");
        },
        async () => {
          events.push("persist");
        },
        async () => {
          events.push("rollback");
        },
      ),
    ).rejects.toThrow("gate already closed");

    expect(events).toEqual(["persist", "activate", "rollback"]);
  });

  test("replacement during the write rolls back before the replacement writes", async () => {
    const roomId = "room-establish-2";
    const peerPublicKey = "22".repeat(32);
    const oldEpc = connection(roomId, "old-peer", peerPublicKey);
    const replacement = connection(roomId, "new-peer", peerPublicKey);
    claimRatchetPersistence(oldEpc, roomId);

    let releaseWrite!: () => void;
    const blocked = new Promise<void>((resolve) => {
      releaseWrite = resolve;
    });
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const events: string[] = [];

    const oldAttempt = persistAndActivateClaimedRatchetState(
      oldEpc,
      state(),
      roomId,
      () => events.push("old-activate"),
      async () => {
        events.push("old-persist");
        markStarted();
        await blocked;
      },
      async () => {
        events.push("old-rollback");
      },
    );
    await started;
    claimRatchetPersistence(replacement, roomId);
    releaseWrite();
    await expect(oldAttempt).rejects.toThrow("stale connection owner");

    await persistAndActivateClaimedRatchetState(
      replacement,
      state(),
      roomId,
      () => events.push("new-activate"),
      async () => {
        events.push("new-persist");
      },
      async () => {
        events.push("new-rollback");
      },
    );

    expect(events).toEqual([
      "old-persist",
      "old-rollback",
      "new-persist",
      "new-activate",
    ]);
  });
});
