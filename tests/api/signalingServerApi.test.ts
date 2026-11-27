import { describe, expect, test } from "bun:test";

(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

const { canonicalSignalingServerUrl, selectSignalingServerUrl } =
  await import("../../src/utils/signalingServerBoundary");
const { sendAuthenticatedSignalingFrame, sendPeerConnectionRequest } =
  await import("../../src/utils/signalingFrame");

const SELF_PEER_ID = "00000000-0000-4000-8000-000000000123";
const OTHER_PEER_ID = "00000000-0000-4000-8000-000000000456";
const SELF_PUBLIC_KEY = "ab".repeat(32);
const OTHER_PUBLIC_KEY = "cd".repeat(32);

const state = (verified = true) => ({
  keyPair: {
    peerId: SELF_PEER_ID,
    publicKey: SELF_PUBLIC_KEY,
    secretKey: "ef".repeat(64),
    challengeId: "",
    challenge: "01".repeat(32),
    signature: "02".repeat(64),
  },
  signalingServer: {
    isConnected: true,
    isEstablishingConnection: false,
    isVerified: verified,
    serverUrl: "wss://signal.example/ws",
  },
});

const api = (verified = true) => {
  const actions: unknown[] = [];
  return {
    actions,
    value: {
      getState: () => state(verified),
      dispatch: (action: unknown) => {
        actions.push(action);
        return action;
      },
    },
  };
};

describe("signaling WebSocket boundary", () => {
  test("canonical URL construction preserves existing query parameters", () => {
    const result = new URL(
      canonicalSignalingServerUrl("wss://signal.example/ws?deployment=blue"),
    );
    expect(result.protocol).toBe("wss:");
    expect(result.searchParams.get("deployment")).toBe("blue");
    expect(result.searchParams.getAll("publickey")).toEqual([]);
    expect(() =>
      canonicalSignalingServerUrl("wss://signal.example/ws?publickey=old"),
    ).toThrow();
  });

  test("only ws and wss signaling schemes are accepted", () => {
    expect(() =>
      canonicalSignalingServerUrl("https://signal.example/ws"),
    ).toThrow("must use ws: or wss:");
    expect(() => canonicalSignalingServerUrl("not a URL")).toThrow();
  });

  test("first custom server is allowed, but retained rooms stay bound across disconnect", () => {
    expect(
      selectSignalingServerUrl({
        requestedServerUrl: "wss://custom.example/ws",
        currentServerUrl: "wss://default.example/ws",
        hasActiveRooms: false,
        isConnected: false,
        isEstablishingConnection: false,
      }),
    ).toBe("wss://custom.example/ws");

    expect(() =>
      selectSignalingServerUrl({
        requestedServerUrl: "wss://other.example/ws",
        currentServerUrl: "wss://custom.example/ws",
        hasActiveRooms: true,
        isConnected: false,
        isEstablishingConnection: false,
      }),
    ).toThrow("different active signaling server");
  });

  test("a stale fromPeerId cannot be sent on an authenticated replacement socket", () => {
    let sends = 0;
    const fakeApi = api();
    const result = sendAuthenticatedSignalingFrame(
      {
        readyState: 1,
        send: () => {
          sends += 1;
        },
      },
      {
        content: {
          type: "pong",
          fromPeerId: OTHER_PEER_ID,
        },
      },
      fakeApi.value as never,
      () => true,
    );
    expect(result).toEqual({ error: "Signaling frame identity is stale" });
    expect(sends).toBe(0);
  });

  test("peer initialization publishes no local state when proof, socket ownership, or send fails", () => {
    const params = {
      roomId: "00000000-0000-4000-8000-000000000789",
      peerId: OTHER_PEER_ID,
      peerPublicKey: OTHER_PUBLIC_KEY,
    };

    const unverified = api(false);
    let sends = 0;
    expect(
      sendPeerConnectionRequest(
        {
          readyState: 1,
          send: () => {
            sends += 1;
          },
        },
        params,
        unverified.value as never,
        () => true,
      ),
    ).toEqual({ error: "WebSocket identity is not authenticated" });
    expect(unverified.actions).toHaveLength(0);
    expect(sends).toBe(0);

    const stale = api();
    expect(
      sendPeerConnectionRequest(
        { readyState: 1, send: () => undefined },
        params,
        stale.value as never,
        () => false,
      ),
    ).toEqual({ error: "WebSocket is not open" });
    expect(stale.actions).toHaveLength(0);

    const throwing = api();
    expect(
      sendPeerConnectionRequest(
        {
          readyState: 1,
          send: () => {
            throw new Error("injected send failure");
          },
        },
        params,
        throwing.value as never,
        () => true,
      ),
    ).toEqual({ error: "injected send failure" });
    expect(throwing.actions).toHaveLength(0);
  });

  test("peer and channel publish only after an exact-socket send succeeds", () => {
    const fakeApi = api();
    let serialized = "";
    const result = sendPeerConnectionRequest(
      {
        readyState: 1,
        send: (data) => {
          serialized = String(data);
        },
      },
      {
        roomId: "00000000-0000-4000-8000-000000000789",
        peerId: OTHER_PEER_ID,
        peerPublicKey: OTHER_PUBLIC_KEY,
      },
      fakeApi.value as never,
      () => true,
    );
    expect(result).toEqual({ data: undefined });
    expect(JSON.parse(serialized)).toMatchObject({
      type: "connection",
      fromPeerId: SELF_PEER_ID,
      toPeerId: OTHER_PEER_ID,
    });
    expect(fakeApi.actions).toHaveLength(2);
  });
});
