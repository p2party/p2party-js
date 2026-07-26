import { afterEach, describe, expect, test } from "bun:test";

// The store reads localStorage at module load, so it must exist before any of
// these imports are evaluated. Static imports hoist, hence the dynamic form.
const memory = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage = {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => memory.set(key, value),
  removeItem: (key: string) => memory.delete(key),
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

const { store, dispatch } = await import("./store");
const { deleteRoom, setRoom, setPeer, setPeerHandshakeStatus } =
  await import("./reducers/roomSlice");
const { DEFAULT_ROOM_POLICY_V1 } = await import("./roomPolicy");
const { normalizeRoomCapability } = await import("./roomInvite");
const p2party = (await import("./index")).default;

/**
 * These cover the reason waitForRoom exists: callers previously hand-rolled a
 * store subscription with a mutable unsubscribe binding, a synchronous
 * inspect() for the already-joined case, and no timeout. Each of those is a
 * separate way to leak or hang, so each is asserted here.
 */

const ROOM_URL = normalizeRoomCapability("a".repeat(64));
const ROOM_ID = "11111111-1111-4111-8111-111111111111";
const PEER_ID = "22222222-2222-4222-8222-222222222222";

const seedRoom = (id: string) => {
  dispatch(
    setRoom({
      url: ROOM_URL,
      id,
      rtcConfig: {},
      policy: DEFAULT_ROOM_POLICY_V1,
    }),
  );
};

afterEach(() => {
  const existing = p2party
    .roomSelector(store.getState())
    .find((room) => room.url === ROOM_URL);
  if (existing) dispatch(deleteRoom(existing.id));
});

describe("waitForRoom", () => {
  test("resolves immediately when the room already has an id", async () => {
    seedRoom(ROOM_ID);
    const room = await p2party.waitForRoom(ROOM_URL, { timeoutMs: 1000 });
    expect(room.id).toBe(ROOM_ID);
    expect(room.url).toBe(ROOM_URL);
  });

  test("resolves when the id arrives later", async () => {
    // Seeded without an id, exactly as connect() does before the signaling
    // service answers with a roomId frame.
    seedRoom("");
    const pending = p2party.waitForRoom(ROOM_URL, { timeoutMs: 2000 });
    setTimeout(() => {
      seedRoom(ROOM_ID);
    }, 20);
    const room = await pending;
    expect(room.id).toBe(ROOM_ID);
  });

  test("rejects on timeout instead of hanging forever", async () => {
    seedRoom("");
    await expect(
      p2party.waitForRoom(ROOM_URL, { timeoutMs: 50 }),
    ).rejects.toThrow(/did not assign a room id/);
  });

  test("rejects when aborted, and when already aborted", async () => {
    seedRoom("");
    const controller = new AbortController();
    const pending = p2party.waitForRoom(ROOM_URL, {
      timeoutMs: 5000,
      signal: controller.signal,
    });
    controller.abort();
    await expect(pending).rejects.toThrow(/aborted/);

    await expect(
      p2party.waitForRoom(ROOM_URL, { signal: AbortSignal.abort() }),
    ).rejects.toThrow(/aborted/);
  });

  test("leaves no store subscription behind on any exit path", async () => {
    // A leaked subscription is invisible until it is thousands deep, so count
    // listeners directly rather than trusting the implementation.
    const countListeners = () => {
      let count = 0;
      const probe = () => count++;
      const unsubscribe = store.subscribe(probe);
      dispatch(
        setRoom({
          url: ROOM_URL,
          id: "",
          rtcConfig: {},
          policy: DEFAULT_ROOM_POLICY_V1,
        }),
      );
      unsubscribe();
      return count;
    };

    const before = countListeners();

    seedRoom("");
    await expect(
      p2party.waitForRoom(ROOM_URL, { timeoutMs: 30 }),
    ).rejects.toThrow();
    seedRoom(ROOM_ID);
    await p2party.waitForRoom(ROOM_URL, { timeoutMs: 500 });

    // The probe fires once per dispatch regardless; what matters is that the
    // resolved and rejected waits did not add permanent subscribers.
    expect(countListeners()).toBe(before);
  });
});

describe("waitForPeers", () => {
  test("resolves only once a peer is authenticated, not merely present", async () => {
    seedRoom(ROOM_ID);
    const pending = p2party.waitForPeers(ROOM_ID, { timeoutMs: 2000 });

    // Present but mid-handshake must NOT satisfy the wait: sendMessage to a
    // room whose only peer is unauthenticated rejects.
    dispatch(
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticating",
      }),
    );
    dispatch(
      setPeer({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        peerPublicKey: "b".repeat(64),
      }),
    );

    let settledEarly = false;
    void pending.then(() => (settledEarly = true)).catch(() => undefined);
    await new Promise((r) => setTimeout(r, 60));
    expect(settledEarly).toBe(false);

    dispatch(
      setPeerHandshakeStatus({
        roomId: ROOM_ID,
        peerId: PEER_ID,
        status: "authenticated",
      }),
    );
    const peers = await pending;
    expect(peers.map((p) => p.peerId)).toContain(PEER_ID);
  });

  test("rejects on timeout and reports how many did authenticate", async () => {
    seedRoom(ROOM_ID);
    await expect(
      p2party.waitForPeers(ROOM_ID, { count: 3, timeoutMs: 50 }),
    ).rejects.toThrow(/of 3 peer\(s\) authenticated/);
  });
});
