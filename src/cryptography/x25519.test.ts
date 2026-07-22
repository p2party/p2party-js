import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { x25519Keypair, x25519Dh } from "./x25519";

describe("x25519", () => {
  test("keypair produces 32-byte keys and DH agrees both ways", async () => {
    const module = await loadTestModule();

    const a = x25519Keypair(module);
    const b = x25519Keypair(module);

    expect(a.publicKey.length).toBe(32);
    expect(a.secretKey.length).toBe(32);

    const sa = x25519Dh(a.secretKey, b.publicKey, module);
    const sb = x25519Dh(b.secretKey, a.publicKey, module);

    expect(sa.length).toBe(32);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });
});
