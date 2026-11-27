import { expect, test } from "bun:test";
import { leaveMembershipsForPurge } from "../../src/utils/purgeMemberships";
import { deriveRoomLocator } from "../../src/utils/roomLocator";

const server = "wss://fixture.invalid/ws";
const key = "11".repeat(32);
const room = (n: number) => String(n).padStart(64, "0");
const saved = (n: number) => ({
  roomId: "room-" + n,
  roomUrl: room(n),
  signalingServerUrl: server,
  membershipPublicKey: key,
});

test("purge starts a correlated leave for each known membership before key deletion", async () => {
  const events: string[] = [];
  let acknowledge: () => void = () => {};
  const waiting = new Promise<void>((resolve) => {
    acknowledge = resolve;
  });
  const result = leaveMembershipsForPurge(
    [{ id: "room-1", url: room(1) }],
    server,
    key,
    async () => [saved(1), saved(2)],
    async (url) => {
      events.push(url);
      await waiting;
    },
  ).then((value) => {
    events.push("delete key");
    return value;
  });
  await Promise.resolve();
  expect(events).toEqual([room(1), room(2)]);
  acknowledge();
  expect(await result).toEqual({
    unacknowledgedRoomIds: [],
    roomInventoryComplete: true,
  });
  expect(events.at(-1)).toBe("delete key");
});

test("purge reports unacknowledged rooms without disclosing another server's or identity's saved rooms", async () => {
  const seen: string[] = [];
  const outcome = await leaveMembershipsForPurge(
    [{ id: "", url: room(1) }],
    server,
    key,
    async () => [
      saved(2),
      { ...saved(3), signalingServerUrl: undefined },
      { ...saved(4), signalingServerUrl: "wss://other.invalid/ws" },
      { ...saved(5), membershipPublicKey: "other" },
    ],
    async (url) => {
      seen.push(url);
      if (url === room(1)) throw new Error("closed");
    },
  );
  expect(seen).toEqual([room(1), room(2)]);
  expect(outcome.unacknowledgedRoomIds).toEqual(
    [deriveRoomLocator(room(1)), "room-3", "room-4", "room-5"].sort(),
  );
});

test("one deadline bounds a stalled inventory or leave, and late inventory cannot send under a replacement key", async () => {
  let loaded: (value: ReturnType<typeof saved>[]) => void = () => {};
  const slow = new Promise<ReturnType<typeof saved>[]>((r) => {
    loaded = r;
  });
  const seen: string[] = [];
  const result = await leaveMembershipsForPurge(
    [
      { id: "one", url: room(1) },
      { id: "two", url: room(2) },
    ],
    server,
    key,
    () => slow,
    async (url) => {
      seen.push(url);
      if (url === room(1)) await new Promise<void>(() => {});
    },
    25,
  );
  expect(result).toEqual({
    unacknowledgedRoomIds: ["one"],
    roomInventoryComplete: false,
  });
  loaded([saved(3)]);
  await Promise.resolve();
  expect(seen).toEqual([room(1), room(2)]);
});

test("an acknowledgement cannot confirm a saved membership on another authority with the same room URL", async () => {
  const report = await leaveMembershipsForPurge(
    [{ id: "active", url: room(1) }],
    server,
    key,
    async () => [
      { ...saved(1), roomId: "archived", membershipPublicKey: "other" },
    ],
    async () => {},
  );
  expect(report.unacknowledgedRoomIds).toEqual(["archived"]);
});
