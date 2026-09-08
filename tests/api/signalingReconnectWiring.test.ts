import { afterEach, describe, expect, test } from "bun:test";

// `src/reducers/keyPairSlice` reads localStorage at module scope, so the shim
// has to be in place before the api module is pulled in — same pattern as
// tests/api/signalingServerApi.test.ts.
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: () => null,
  setItem: () => undefined,
  removeItem: () => undefined,
  clear: () => undefined,
  key: () => null,
  length: 0,
} as Storage;

// src/api/signalingServerApi -> handleWebSocketMessage -> ... ->
// src/handlers/handleHandshake -> src/store -> src/api/signalingServerApi is a
// pre-existing runtime cycle. The app enters it through src/store (index.ts:4),
// which is the order that resolves; entering through the api module first hits
// "Cannot access 'signalingServerApi' before initialization" in store.ts:20.
await import("../../src/store");

const {
  noteSignalingSocketClose,
  signalingReconnect,
  signalingReconnectDelayWithJitter,
  setSignalingReconnectHost,
} = await import("../../src/api/signalingServerApi");

interface FakeRoom {
  readonly id: string;
  readonly signalingActive?: boolean;
}

const host = (
  rooms: FakeRoom[],
  signalingServer: {
    isConnected: boolean;
    isEstablishingConnection: boolean;
    serverUrl: string;
  },
): {
  dispatch: (action: unknown) => unknown;
  getState: () => unknown;
  dispatched: unknown[];
} => {
  const dispatched: unknown[] = [];
  return {
    dispatched,
    dispatch: (action: unknown) => {
      dispatched.push(action);
      return action;
    },
    getState: () => ({ rooms, signalingServer, keyPair: {} }),
  };
};

/** A host that wants a reconnect: one active room, a known URL, no live socket. */
const wantingHost = () =>
  host([{ id: "r1", signalingActive: true }], {
    isConnected: false,
    isEstablishingConnection: false,
    serverUrl: "ws://localhost:5811/ws",
  });

afterEach(() => {
  signalingReconnect.cancel();
  setSignalingReconnectHost(null);
});

describe("signaling reconnect wiring", () => {
  test("the module exposes one controller the socket paths share", () => {
    expect(typeof signalingReconnect.arm).toBe("function");
    expect(typeof signalingReconnect.schedule).toBe("function");
    expect(typeof signalingReconnect.succeeded).toBe("function");
    expect(typeof signalingReconnect.cancel).toBe("function");
  });

  test("with no host bound, nothing is ever scheduled", () => {
    setSignalingReconnectHost(null);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(false);
  });

  test("a room with signaling active and a known server wants a reconnect", () => {
    const h = host([{ id: "r1", signalingActive: true }], {
      isConnected: false,
      isEstablishingConnection: false,
      serverUrl: "ws://localhost:5811/ws",
    });
    setSignalingReconnectHost(h);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(true);
    expect(signalingReconnect.pending).toBe(true);
  });

  test("a client that left every room does not reconnect", () => {
    const h = host([{ id: "r1", signalingActive: false }], {
      isConnected: false,
      isEstablishingConnection: false,
      serverUrl: "ws://localhost:5811/ws",
    });
    setSignalingReconnectHost(h);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(false);
  });

  test("no server URL means no reconnect", () => {
    const h = host([{ id: "r1", signalingActive: true }], {
      isConnected: false,
      isEstablishingConnection: false,
      serverUrl: "",
    });
    setSignalingReconnectHost(h);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(false);
  });

  test("an attempt already in flight is not raced by the backoff", () => {
    const h = host([{ id: "r1", signalingActive: true }], {
      isConnected: false,
      isEstablishingConnection: true,
      serverUrl: "ws://localhost:5811/ws",
    });
    setSignalingReconnectHost(h);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(false);
  });

  test("a live connected socket is not reconnected over", () => {
    const h = host([{ id: "r1", signalingActive: true }], {
      isConnected: true,
      isEstablishingConnection: false,
      serverUrl: "ws://localhost:5811/ws",
    });
    setSignalingReconnectHost(h);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(false);
  });
});

describe("signaling reconnect close-code policy", () => {
  test("a server close the server means as final stops the ladder", () => {
    setSignalingReconnectHost(wantingHost());
    signalingReconnect.arm();
    noteSignalingSocketClose({ code: 1008, selfInitiated: false });
    expect(signalingReconnect.schedule("socket-closed")).toBe(false);
  });

  test("1003 and 1010 are refusals of this build, not of this moment", () => {
    for (const code of [1003, 1010]) {
      setSignalingReconnectHost(wantingHost());
      signalingReconnect.arm();
      noteSignalingSocketClose({ code, selfInitiated: false });
      expect(signalingReconnect.schedule("socket-closed")).toBe(false);
    }
  });

  test("the SDK's own protective 1008 is not a permanent refusal", () => {
    // `onOverflow` closes with 1008 when this tab's ingress backlog is
    // exceeded. That is local overload, which bounded backoff is the cure for.
    setSignalingReconnectHost(wantingHost());
    signalingReconnect.arm();
    noteSignalingSocketClose({ code: 1008, selfInitiated: true });
    expect(signalingReconnect.schedule("socket-closed")).toBe(true);
  });

  test("a codeless server close (1005) is retried — every server rejection is one", () => {
    // p2party-server ends verification failures, socket replacement, ping
    // timeout and handler errors with a bare ws.close(), which reaches the
    // browser as CloseEvent.code 1005. Treating 1005 as final would disable
    // the whole C4 fix.
    setSignalingReconnectHost(wantingHost());
    signalingReconnect.arm();
    noteSignalingSocketClose({ code: 1005, selfInitiated: false });
    expect(signalingReconnect.schedule("socket-closed")).toBe(true);
  });

  test("an abnormal close (1006), a normal one (1000) and a restart (1001) are retried", () => {
    for (const code of [1006, 1000, 1001, 1011, 1012, 1013, 4000]) {
      setSignalingReconnectHost(wantingHost());
      signalingReconnect.arm();
      noteSignalingSocketClose({ code, selfInitiated: false });
      expect(signalingReconnect.schedule("socket-closed")).toBe(true);
      signalingReconnect.cancel();
    }
  });

  test("binding a host clears a refusal, so a deliberate connect is never blocked", () => {
    const h = wantingHost();
    setSignalingReconnectHost(h);
    noteSignalingSocketClose({ code: 1008, selfInitiated: false });
    setSignalingReconnectHost(h);
    signalingReconnect.arm();
    expect(signalingReconnect.schedule("socket-closed")).toBe(true);
  });
});

describe("signaling reconnect jitter", () => {
  test("a ladder rung is a floor, never shortened, never more than +25%", () => {
    for (const rung of [1_000, 4_000, 30_000]) {
      for (let draw = 0; draw < 500; draw += 1) {
        const delayMs = signalingReconnectDelayWithJitter(rung);
        expect(delayMs).toBeGreaterThanOrEqual(rung);
        expect(delayMs).toBeLessThanOrEqual(rung * 1.25);
      }
    }
  });

  test("the spread is real: 500 draws off one rung are not one value", () => {
    const seen = new Set<number>();
    for (let draw = 0; draw < 500; draw += 1)
      seen.add(signalingReconnectDelayWithJitter(30_000));
    // A herd of clients woken by the same server restart must not re-handshake
    // in lockstep. Anything above a handful of distinct delays proves spread;
    // 500 uniform draws over 7,500 ms collide far too rarely to fall below 100.
    expect(seen.size).toBeGreaterThan(100);
  });
});
