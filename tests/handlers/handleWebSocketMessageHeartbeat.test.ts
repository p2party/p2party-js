import { beforeAll, describe, expect, test } from "bun:test";

// The message handler imports the signaling API, which imports the Redux
// store, whose identity slice reads localStorage at module initialization.
const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {
    for (const key of Object.keys(localStorageMemory))
      delete localStorageMemory[key];
  },
  key: () => null,
  length: 0,
} as Storage;

type Handler = typeof import("../../src/handlers/handleWebSocketMessage");

let handleWebSocketMessage: Handler["default"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root so every
  // createApi initializer has run before the handler module loads.
  await import("../../src/store");
  ({ default: handleWebSocketMessage } =
    await import("../../src/handlers/handleWebSocketMessage"));
});

const SELF_PEER_ID = "00000000-0000-4000-8000-0000000000d1";

const fixture = () => {
  const sent: unknown[] = [];
  const dispatched: unknown[] = [];
  let beats = 0;
  const ws = {
    readyState: 1,
    send: (data: unknown) => {
      sent.push(data);
    },
  } as unknown as WebSocket;
  const api = {
    getState: () => ({ keyPair: { peerId: SELF_PEER_ID } }),
    // The queued "ping" answers through the RTK sendMessage mutation, which
    // is a thunk here; the fake records it and resolves like a no-op send.
    dispatch: (action: unknown) => {
      dispatched.push(action);
      return Promise.resolve({ data: undefined });
    },
  };
  return {
    ws,
    api,
    sent,
    dispatched,
    beats: () => beats,
    onHeartbeat: () => {
      beats += 1;
    },
  };
};

describe("handleWebSocketMessage heartbeat notification", () => {
  test("a queued JSON ping is answered and reported as a heartbeat", async () => {
    const f = fixture();
    await handleWebSocketMessage(
      { data: '{"type":"ping"}' } as MessageEvent,
      f.ws,
      f.api as never,
      () => true,
      f.onHeartbeat,
    );
    expect(f.dispatched).toHaveLength(1);
    expect(f.beats()).toBe(1);
  });

  test("a queued raw PING is answered on the socket and reported as a heartbeat", async () => {
    const f = fixture();
    await handleWebSocketMessage(
      { data: "PING" } as MessageEvent,
      f.ws,
      f.api as never,
      () => true,
      f.onHeartbeat,
    );
    expect(f.sent).toEqual(["PONG"]);
    expect(f.dispatched).toHaveLength(0);
    expect(f.beats()).toBe(1);
  });

  test("a malformed heartbeat and a stale socket report nothing", async () => {
    const malformed = fixture();
    await handleWebSocketMessage(
      { data: '{"type":"ping","extra":1}' } as MessageEvent,
      malformed.ws,
      malformed.api as never,
      () => true,
      malformed.onHeartbeat,
    );
    expect(malformed.dispatched).toHaveLength(0);
    expect(malformed.beats()).toBe(0);

    const stale = fixture();
    await handleWebSocketMessage(
      { data: '{"type":"ping"}' } as MessageEvent,
      stale.ws,
      stale.api as never,
      () => false,
      stale.onHeartbeat,
    );
    expect(stale.dispatched).toHaveLength(0);
    expect(stale.sent).toHaveLength(0);
    expect(stale.beats()).toBe(0);
  });

  test("the heartbeat callback is optional", async () => {
    const f = fixture();
    await handleWebSocketMessage(
      { data: "PING" } as MessageEvent,
      f.ws,
      f.api as never,
      () => true,
    );
    expect(f.sent).toEqual(["PONG"]);
  });
});
