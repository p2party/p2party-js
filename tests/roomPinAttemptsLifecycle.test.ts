// The two room-level clears, through the public API that triggers them:
// connect() with a PIN for a loaded room (a deliberate PIN re-entry) and
// purgeRoom(). The limiter writes to the real database worker over
// fake-indexeddb.
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";

import { workerPinAttemptStore } from "./pinAttemptStores";

// The store reads localStorage at module load, so it must exist before any of
// these imports are evaluated. Static imports hoist, hence the dynamic form.
const memory = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage ??= {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => memory.set(key, value),
  removeItem: (key: string) => memory.delete(key),
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

const { store, dispatch } = await import("../src/store");
const { deleteRoom, setRoom } = await import("../src/reducers/roomSlice");
const { signalingServerActions } =
  await import("../src/reducers/signalingServerSlice");
const { DEFAULT_ROOM_POLICY_V1 } = await import("../src/roomPolicy");
const { normalizeRoomCapability } = await import("../src/roomInvite");
const { deleteRoomPin } = await import("../src/roomPinVault");
const {
  MAX_ROOM_PIN_FAILURES_PER_WINDOW,
  assertPinAttemptAllowed,
  recordPinFailure,
  recordPinSuccess,
  usePinAttemptStoreForTests,
} = await import("../src/roomPinAttempts");
const p2party = (await import("../src/index")).default;

import type { RoomPolicyV1 } from "../src/roomPolicy";

const ROOM_URL = normalizeRoomCapability("b3".repeat(32));
const ROOM_ID = "33333333-3333-4333-8333-333333333333";
const SERVER_URL = "wss://signal.example/ws";
const PIN_POLICY: RoomPolicyV1 = { ...DEFAULT_ROOM_POLICY_V1, authMode: "pin" };
const KNOWN = "ab".repeat(32);
const NEVER_SEEN = "cd".repeat(32);

let identityCounter = 0;
const fillRoomWindow = async (): Promise<void> => {
  for (let i = 0; i < MAX_ROOM_PIN_FAILURES_PER_WINDOW; i++)
    await recordPinFailure(
      ROOM_ID,
      (0x2000 + identityCounter++).toString(16).padStart(64, "0"),
    );
};

const reload = (): void => {
  usePinAttemptStoreForTests(workerPinAttemptStore);
};

// A unit run has no database worker, so the room listener and the purge log
// every message-store call they make; none of those is under test here.
let quietErrors: ReturnType<typeof spyOn> | undefined;

beforeEach(() => {
  quietErrors = spyOn(console, "error").mockImplementation(() => undefined);
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
  reload();
  dispatch(
    setRoom({ url: ROOM_URL, id: ROOM_ID, rtcConfig: {}, policy: PIN_POLICY }),
  );
});

afterEach(async () => {
  usePinAttemptStoreForTests();
  deleteRoomPin(ROOM_URL);
  if (store.getState().rooms.some((room) => room.url === ROOM_URL))
    dispatch(deleteRoom(ROOM_URL));
  dispatch(signalingServerActions.disconnect());
  // Listener effects the test's dispatches started finish within a few turns.
  for (let turn = 0; turn < 5; turn++)
    await new Promise((resolve) => setTimeout(resolve, 0));
  quietErrors?.mockRestore();
});

describe("room-level PIN attempt clears", () => {
  test("PIN re-entry keeps authenticated peers exempt", async () => {
    await recordPinSuccess(ROOM_ID, KNOWN);
    await fillRoomWindow();
    await expect(assertPinAttemptAllowed(ROOM_ID, NEVER_SEEN)).rejects.toThrow(
      "identities new to this room",
    );

    // A socket is already being established for this server, so connect()
    // opens none of its own.
    dispatch(signalingServerActions.startConnecting(SERVER_URL));
    await p2party.connect(ROOM_URL, SERVER_URL, undefined, {
      policy: PIN_POLICY,
      pin: new Uint8Array([1, 2, 3, 4]),
    });

    // The re-entry reset the throttles...
    await expect(
      assertPinAttemptAllowed(ROOM_ID, NEVER_SEEN),
    ).resolves.toBeUndefined();
    // ...and, after a reload and a refilled window, the member who had
    // authenticated is still exempt while a new identity is refused.
    reload();
    await fillRoomWindow();
    await expect(
      assertPinAttemptAllowed(ROOM_ID, KNOWN),
    ).resolves.toBeUndefined();
    await expect(assertPinAttemptAllowed(ROOM_ID, NEVER_SEEN)).rejects.toThrow(
      "identities new to this room",
    );
  });

  test("room purge removes authenticated-peer rows", async () => {
    await recordPinSuccess(ROOM_ID, KNOWN);

    // Remote revocation and message deletion fail in a unit run (no socket,
    // no database worker); the PIN step runs regardless.
    await p2party.purgeRoom(ROOM_URL).catch(() => undefined);

    reload();
    await fillRoomWindow();
    await expect(assertPinAttemptAllowed(ROOM_ID, KNOWN)).rejects.toThrow(
      "identities new to this room",
    );
  });
});
