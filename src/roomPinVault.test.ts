import { describe, expect, test } from "bun:test";

import { TransientRoomPinVault } from "./roomPinVault";

describe("transient room PIN vault", () => {
  test("put and get both copy PIN bytes", () => {
    const vault = new TransientRoomPinVault();
    const input = new Uint8Array([1, 2, 3, 4]);
    vault.put("local-room-a", input);

    input.fill(9);
    const firstRead = vault.get("local-room-a");
    expect(firstRead).toEqual(new Uint8Array([1, 2, 3, 4]));

    firstRead?.fill(8);
    expect(vault.get("local-room-a")).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  test("replacement and delete wipe the vault-owned copies", () => {
    const wiped: Uint8Array[] = [];
    const vault = new TransientRoomPinVault((pin) => {
      pin.fill(0);
      wiped.push(pin);
    });

    vault.put("local-room-a", new Uint8Array([1, 2, 3]));
    vault.put("local-room-a", new Uint8Array([4, 5, 6]));
    expect(wiped).toHaveLength(1);
    expect(wiped[0]).toEqual(new Uint8Array(3));

    expect(vault.delete("local-room-a")).toBe(true);
    expect(vault.has("local-room-a")).toBe(false);
    expect(wiped).toHaveLength(2);
    expect(wiped[1]).toEqual(new Uint8Array(3));
    expect(vault.delete("local-room-a")).toBe(false);
  });

  test("clear wipes every stored PIN and empties the vault", () => {
    const wiped: Uint8Array[] = [];
    const vault = new TransientRoomPinVault((pin) => {
      pin.fill(0);
      wiped.push(pin);
    });
    vault.put("local-room-a", new Uint8Array([1, 2]));
    vault.put("local-room-b", new Uint8Array([3, 4, 5]));

    vault.clear();

    expect(wiped).toHaveLength(2);
    expect(wiped.every((pin) => pin.every((byte) => byte === 0))).toBe(true);
    expect(vault.has("local-room-a")).toBe(false);
    expect(vault.has("local-room-b")).toBe(false);
  });

  test("rejects ambiguous contexts and empty/non-byte PINs", () => {
    const vault = new TransientRoomPinVault();
    expect(() => vault.put("", new Uint8Array([1]))).toThrow(
      "room context must be a non-empty string",
    );
    expect(() => vault.put("room", new Uint8Array())).toThrow(
      "PIN must not be empty",
    );
    expect(() => vault.put("room", "1234" as unknown as Uint8Array)).toThrow(
      "PIN must be a Uint8Array",
    );
  });
});
