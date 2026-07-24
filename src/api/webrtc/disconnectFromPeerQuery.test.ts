import { describe, expect, test } from "bun:test";

import webrtcDisconnectPeerQuery from "./disconnectFromPeerQuery";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { IRTCDataChannel, IRTCPeerConnection } from "./interfaces";

const connection = (
  roomId: string,
  peerId: string,
): { value: IRTCPeerConnection; closes: { count: number } } => {
  const closes = { count: 0 };
  const value = {
    roomId,
    withPeerId: peerId,
    connectionState: "connected",
    close: () => {
      closes.count++;
    },
  } as unknown as IRTCPeerConnection;
  return { value, closes };
};

const channel = (
  roomId: string,
  peerId: string,
): { value: IRTCDataChannel; closes: { count: number } } => {
  const closes = { count: 0 };
  const value = {
    roomIds: [roomId],
    withPeerId: peerId,
    readyState: "open",
    close: () => {
      closes.count++;
    },
  } as unknown as IRTCDataChannel;
  return { value, closes };
};

const api = {
  dispatch: (action: unknown) => action,
  getState: () => ({ rooms: [] }),
} as unknown as BaseQueryApi;

describe("disconnectFromPeer room isolation", () => {
  test("room-scoped teardown preserves the same peer's other room", async () => {
    const first = connection("room-a", "peer");
    const second = connection("room-b", "peer");
    const firstChannel = channel("room-a", "peer");
    const secondChannel = channel("room-b", "peer");
    const peerConnections = [first.value, second.value];
    const dataChannels = [firstChannel.value, secondChannel.value];

    await webrtcDisconnectPeerQuery(
      {
        peerId: "peer",
        roomId: "room-a",
        peerConnections,
        dataChannels,
        iceCandidates: [],
      },
      api,
      {},
    );

    expect(peerConnections).toEqual([second.value]);
    expect(dataChannels).toEqual([secondChannel.value]);
    expect(first.closes.count).toBe(1);
    expect(firstChannel.closes.count).toBe(1);
    expect(second.closes.count).toBe(0);
    expect(secondChannel.closes.count).toBe(0);
  });

  test("peer-wide teardown removes every room transport for that peer", async () => {
    const first = connection("room-a", "peer");
    const second = connection("room-b", "peer");
    const other = connection("room-a", "other");
    const peerConnections = [first.value, second.value, other.value];
    const dataChannels: IRTCDataChannel[] = [];

    await webrtcDisconnectPeerQuery(
      { peerId: "peer", peerConnections, dataChannels, iceCandidates: [] },
      api,
      {},
    );

    expect(peerConnections).toEqual([other.value]);
    expect(first.closes.count).toBe(1);
    expect(second.closes.count).toBe(1);
    expect(other.closes.count).toBe(0);
  });

  test("teardown erases live ratchet and cached message keys", async () => {
    const target = connection("room-a", "peer");
    const rootKey = new Uint8Array(32).fill(1);
    const sendingChainKey = new Uint8Array(32).fill(2);
    const receivingChainKey = new Uint8Array(32).fill(3);
    const dhSelfSec = new Uint8Array(32).fill(4);
    const skipped = new Uint8Array(32).fill(5);
    const cached = new Uint8Array(32).fill(6);
    target.value.ratchetState = {
      rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfPub: new Uint8Array(32),
      dhSelfSec,
      dhRemotePub: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      skipped: new Map([["skipped", skipped]]),
    };
    target.value.messageKeyCache = new Map([["cached", cached]]);
    target.value.messageKeyByMerkleRoot = new Map([["root", "cached"]]);
    let pqDestroyed = 0;
    target.value.pqHealingState = {
      destroy: () => {
        pqDestroyed += 1;
      },
    } as unknown as NonNullable<IRTCPeerConnection["pqHealingState"]>;
    target.value.serializeEdgeCryptoState = () => new Uint8Array(1);

    await webrtcDisconnectPeerQuery(
      {
        peerId: "peer",
        roomId: "room-a",
        peerConnections: [target.value],
        dataChannels: [],
        iceCandidates: [],
      },
      api,
      {},
    );

    for (const secret of [
      rootKey,
      sendingChainKey,
      receivingChainKey,
      dhSelfSec,
      skipped,
      cached,
    ])
      expect(secret.every((byte) => byte === 0)).toBe(true);
    expect(target.value.ratchetState).toBeUndefined();
    expect(target.value.messageKeyCache).toBeUndefined();
    expect(target.value.messageKeyByMerkleRoot).toBeUndefined();
    expect(pqDestroyed).toBe(1);
    expect(target.value.pqHealingState).toBeUndefined();
    expect(target.value.serializeEdgeCryptoState).toBeUndefined();
  });
});
