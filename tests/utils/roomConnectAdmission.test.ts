import { describe, expect, test } from "bun:test";

import { DEFAULT_ROOM_POLICY_V1 } from "../../src/roomPolicy";
import { resolveRoomConnectAdmission } from "../../src/utils/roomConnectAdmission";

const pinPolicy = {
  ...DEFAULT_ROOM_POLICY_V1,
  revision: 1,
  authMode: "pin" as const,
};

describe("room connection admission", () => {
  test("a persisted PIN policy cannot become no-PIN when Redux is empty", () => {
    expect(() =>
      resolveRoomConnectAdmission({
        persistedPolicy: pinPolicy,
        hasTransientPin: false,
      }),
    ).toThrow("requires a PIN");

    expect(
      resolveRoomConnectAdmission({
        persistedPolicy: pinPolicy,
        providedPin: new Uint8Array([1, 2, 3, 4]),
        hasTransientPin: false,
      }),
    ).toEqual(pinPolicy);
  });

  test("an inactive in-memory PIN policy still requires its erased PIN", () => {
    expect(() =>
      resolveRoomConnectAdmission({
        existingPolicy: pinPolicy,
        hasTransientPin: false,
      }),
    ).toThrow("requires a PIN");
  });

  test("persisted policy immutability is checked before activation", () => {
    expect(() =>
      resolveRoomConnectAdmission({
        persistedPolicy: pinPolicy,
        requestedPolicy: DEFAULT_ROOM_POLICY_V1,
        providedPin: new Uint8Array([1]),
        hasTransientPin: false,
      }),
    ).toThrow("immutable");
  });
});
