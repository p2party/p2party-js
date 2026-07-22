import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { x25519Keypair, x25519Dh, newX25519KeyPair } from "./x25519";

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

  test("newX25519KeyPair(module) mints a valid, random 32/32 identity pair usable for DH", async () => {
    const module = await loadTestModule();

    const a = await newX25519KeyPair(module);
    const b = x25519Keypair(module);

    expect(a.publicKey.length).toBe(32);
    expect(a.secretKey.length).toBe(32);

    // two calls produce distinct random keys (not a fixed/zero key)
    const a2 = await newX25519KeyPair(module);
    expect(Buffer.from(a.secretKey)).not.toEqual(Buffer.from(a2.secretKey));

    // the minted identity key does real DH, agreeing with a peer both ways
    const sa = x25519Dh(a.secretKey, b.publicKey, module);
    const sb = x25519Dh(b.secretKey, a.publicKey, module);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });
});
