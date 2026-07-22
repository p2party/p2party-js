import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { deriveGenerator, cpaceStart, cpaceShared } from "./cpace";

const rand = (n: number) => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

describe("cpace", () => {
  test("two honest parties with the same PIN reach the same K", async () => {
    const module = await loadTestModule();
    const enc = new TextEncoder();
    const pin = enc.encode("123456");
    const sid = rand(16);
    const ci = rand(64);

    const Ga = deriveGenerator(pin, sid, ci, module);
    const Gb = deriveGenerator(
      Uint8Array.from(pin),
      Uint8Array.from(sid),
      Uint8Array.from(ci),
      module,
    );
    // Same transcript -> same generator.
    expect(Buffer.from(Ga)).toEqual(Buffer.from(Gb));

    const a = cpaceStart(Ga, module);
    const b = cpaceStart(Gb, module);
    expect(a.Y.length).toBe(32);

    const Ka = cpaceShared(a.y, b.Y, module);
    const Kb = cpaceShared(b.y, a.Y, module);
    expect(Buffer.from(Ka)).toEqual(Buffer.from(Kb));
    // The agreed secret must be a real point, never the all-zero identity
    // encoding (scalarmult surfaces the identity as a throw, so reaching here
    // already implies non-identity; assert it explicitly for regression safety).
    expect(Ka.length).toBe(32);
    expect(Ka.some((byte) => byte !== 0)).toBe(true);
  });

  test("a wrong PIN yields a different generator and mismatched K", async () => {
    const module = await loadTestModule();
    const enc = new TextEncoder();
    const sid = rand(16);
    const ci = rand(64);

    const Ga = deriveGenerator(enc.encode("123456"), sid, ci, module);
    const Gb = deriveGenerator(enc.encode("000000"), Uint8Array.from(sid), Uint8Array.from(ci), module);
    expect(Buffer.from(Ga)).not.toEqual(Buffer.from(Gb));

    const a = cpaceStart(Ga, module);
    const b = cpaceStart(Gb, module);
    const Ka = cpaceShared(a.y, b.Y, module);
    const Kb = cpaceShared(b.y, a.Y, module);
    expect(Buffer.from(Ka)).not.toEqual(Buffer.from(Kb));
  });
});
