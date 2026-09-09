import { describe, expect, test } from "bun:test";

import {
  runIdentityPurgeSettlement,
  runRoomPurgeSettlement,
  runTerminalSettlement,
} from "../../src/utils/terminalSettlement";

describe("fail-closed terminal settlement", () => {
  test("storage cleanup failure cannot skip local deactivation or socket settlement", async () => {
    const order: string[] = [];
    const settling = runTerminalSettlement("room purge failed", [
      () => {
        order.push("deactivate");
      },
      () => {
        order.push("pin-attempt-cleanup");
        throw new Error("IndexedDB unavailable");
      },
      () => {
        order.push("disconnect");
      },
      () => {
        order.push("reconnect-survivors");
      },
    ]);

    await expect(settling).rejects.toBeInstanceOf(AggregateError);
    expect(order).toEqual([
      "deactivate",
      "pin-attempt-cleanup",
      "disconnect",
      "reconnect-survivors",
    ]);
  });

  test("each identity deletion failure occurs only after room teardown and still permits every delete", async () => {
    for (const failingDelete of ["x25519", "ed25519", "derivation"]) {
      const order: string[] = [];
      const settling = runIdentityPurgeSettlement({
        disconnectSignaling: () => {
          order.push("socket");
        },
        clearRoomPins: () => {
          order.push("pins");
        },
        resetIdentity: () => {
          order.push("reset-redux");
        },
        teardownRooms: () => {
          order.push("rooms-terminal");
        },
        deleteIdentityX25519: () => {
          order.push("x25519");
          if (failingDelete === "x25519") throw new Error("x25519 delete");
        },
        deleteIdentityEd25519: () => {
          order.push("ed25519");
          if (failingDelete === "ed25519") throw new Error("ed25519 delete");
        },
        deleteIdentityDerivation: () => {
          order.push("derivation");
          if (failingDelete === "derivation")
            throw new Error("derivation delete");
        },
      });

      await expect(settling).rejects.toBeInstanceOf(AggregateError);
      expect(order).toEqual([
        "socket",
        "pins",
        "reset-redux",
        "rooms-terminal",
        "x25519",
        "ed25519",
        // The provenance flag describes the key that was just purged; leaving
        // it behind would let a fresh random identity inherit the claim that
        // it can be exported as a recovery phrase.
        "derivation",
      ]);
    }
  });

  test("a deferred identity delete starts only after authenticated transports are terminal", async () => {
    let releaseDelete!: () => void;
    let markDeleteStarted!: () => void;
    const deleteStarted = new Promise<void>((resolve) => {
      markDeleteStarted = resolve;
    });
    const deleteDeferred = new Promise<void>((resolve) => {
      releaseDelete = resolve;
    });
    let transportsTerminal = false;

    const settling = runIdentityPurgeSettlement({
      disconnectSignaling: () => undefined,
      clearRoomPins: () => undefined,
      resetIdentity: () => undefined,
      teardownRooms: () => {
        transportsTerminal = true;
      },
      deleteIdentityX25519: async () => {
        markDeleteStarted();
        expect(transportsTerminal).toBe(true);
        await deleteDeferred;
      },
      deleteIdentityEd25519: () => {
        expect(transportsTerminal).toBe(true);
      },
      deleteIdentityDerivation: () => {
        expect(transportsTerminal).toBe(true);
      },
    });

    await deleteStarted;
    expect(transportsTerminal).toBe(true);
    releaseDelete();
    await settling;
  });

  test("room storage failure rejects the observed purge boundary after all terminal steps", async () => {
    const order: string[] = [];
    const settling = runRoomPurgeSettlement({
      closeLocalTransport: () => {
        order.push("transport");
      },
      startRemoteRevocation: async () => {
        order.push("leave");
      },
      deleteLocalData: () => {
        order.push("storage");
        throw new Error("injected room database failure");
      },
      clearPinAttempts: () => {
        order.push("pin-attempts");
      },
    });

    await expect(settling).rejects.toThrow("injected room database failure");
    expect(order).toEqual(["transport", "leave", "storage", "pin-attempts"]);
  });

  test("remote leave runs only after transport close and does not block local storage cleanup", async () => {
    let releaseLeave!: () => void;
    const leaveDeferred = new Promise<void>((resolve) => {
      releaseLeave = resolve;
    });
    const order: string[] = [];

    const settling = runRoomPurgeSettlement({
      closeLocalTransport: () => {
        order.push("transport");
      },
      startRemoteRevocation: async () => {
        order.push("leave-start");
        await leaveDeferred;
        order.push("leave-ack");
      },
      deleteLocalData: () => {
        order.push("storage");
      },
      clearPinAttempts: () => {
        order.push("pin-attempts");
      },
    });

    await Bun.sleep(0);
    expect(order).toEqual([
      "transport",
      "leave-start",
      "storage",
      "pin-attempts",
    ]);
    releaseLeave();
    await settling;
    expect(order).toEqual([
      "transport",
      "leave-start",
      "storage",
      "pin-attempts",
      "leave-ack",
    ]);
  });

  test("an unconfirmed remote leave preserves local settlement and rethrows the exact error", async () => {
    class Unconfirmed extends Error {}
    const remoteError = new Unconfirmed("server did not acknowledge");
    const order: string[] = [];
    const settling = runRoomPurgeSettlement({
      closeLocalTransport: () => {
        order.push("transport");
      },
      startRemoteRevocation: async () => {
        order.push("leave");
        throw remoteError;
      },
      deleteLocalData: () => {
        order.push("storage");
      },
      clearPinAttempts: () => {
        order.push("pin-attempts");
      },
    });

    await expect(settling).rejects.toBe(remoteError);
    expect(order).toEqual(["transport", "leave", "storage", "pin-attempts"]);
  });
});
