import { describe, expect, test } from "bun:test";

import { snapshotByteInput } from "../../src/cryptography/byteInput";

describe("snapshotByteInput", () => {
  test("rejects a Proxy that passes instanceof but lacks typed-array slots", () => {
    const hostile = new Proxy(new Uint8Array(0), {
      get(target, property) {
        if (property === "length") return 32;
        return Reflect.get(target, property, target) as unknown;
      },
    });

    expect(hostile).toBeInstanceOf(Uint8Array);
    expect(ArrayBuffer.isView(hostile)).toBe(false);
    expect(() =>
      snapshotByteInput(hostile, "test: key", { exactLength: 32 }),
    ).toThrow(TypeError);

    const trappingProxy = new Proxy(new Uint8Array(32), {
      getPrototypeOf(): never {
        throw new Error("hostile getPrototypeOf must not run");
      },
    });
    expect(() =>
      snapshotByteInput(trappingProxy, "test: key", { exactLength: 32 }),
    ).toThrow(TypeError);
  });

  test("ignores shadowed length, iterator, and species surfaces", () => {
    class HostileBytes extends Uint8Array {
      static get [Symbol.species](): Uint8ArrayConstructor {
        throw new Error("hostile species must not run");
      }
    }

    const input = new HostileBytes([1, 2, 3]);
    Object.defineProperty(input, "length", { value: 1_000 });
    Object.defineProperty(input, Symbol.iterator, {
      value: (): never => {
        throw new Error("hostile iterator must not run");
      },
    });
    Object.defineProperty(input, "constructor", {
      get: (): never => {
        throw new Error("hostile constructor must not run");
      },
    });

    const snapshot = snapshotByteInput(input, "test: input", {
      exactLength: 3,
      maximumLength: 3,
    });
    expect(snapshot).toEqual(Uint8Array.of(1, 2, 3));
    expect(Object.getPrototypeOf(snapshot)).toBe(Uint8Array.prototype);

    input.fill(0);
    expect(snapshot).toEqual(Uint8Array.of(1, 2, 3));
  });

  test("enforces exact and maximum length with stable RangeErrors", () => {
    expect(() =>
      snapshotByteInput(Uint8Array.of(1, 2), "test: key", {
        exactLength: 3,
      }),
    ).toThrow("test: key must be exactly 3 bytes");
    expect(() =>
      snapshotByteInput(Uint8Array.of(1, 2, 3), "test: payload", {
        maximumLength: 2,
      }),
    ).toThrow("test: payload exceeds the supported length");
  });

  test("owns a stable copy of SharedArrayBuffer-backed bytes", () => {
    const shared = new SharedArrayBuffer(3);
    const input = new Uint8Array(shared);
    input.set([1, 2, 3]);

    const snapshot = snapshotByteInput(input, "test: shared");
    input.fill(0);

    expect(snapshot).toEqual(Uint8Array.of(1, 2, 3));
  });
});
