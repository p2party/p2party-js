import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import {
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchet,
  deserializeRatchet,
} from "./ratchet";
import { MAX_SKIP } from "../utils/constants";

const seed = () => {
  const s = new Uint8Array(32);
  crypto.getRandomValues(s);
  return s;
};

// Bob is the responder (initRatchet false, remote null); Alice is the initiator
// and consumes Bob's initial ratchet pub. Both share the identical root seed.
const pair = async () => {
  const module = await loadTestModule();
  const root = seed();
  const bob = initRatchet(root, false, null, module);
  const alice = initRatchet(Uint8Array.from(root), true, bob.dhSelfPub, module);
  return { module, alice, bob };
};

describe("ratchet", () => {
  test("encrypt -> decrypt round trip in both directions", async () => {
    const { module, alice, bob } = await pair();

    const a0 = ratchetEncrypt(alice, module);
    const bk = ratchetDecrypt(bob, a0.header, module);
    expect(Buffer.from(bk)).toEqual(Buffer.from(a0.messageKey));

    // Bob now has a sending chain (from his DH step). Reply exercises Alice's step.
    const b0 = ratchetEncrypt(bob, module);
    const ak = ratchetDecrypt(alice, b0.header, module);
    expect(Buffer.from(ak)).toEqual(Buffer.from(b0.messageKey));
  });

  test("DH-step fires on a new dhPub (dhRemotePub advances)", async () => {
    const { module, alice, bob } = await pair();
    const a0 = ratchetEncrypt(alice, module);
    ratchetDecrypt(bob, a0.header, module);
    const b0 = ratchetEncrypt(bob, module);
    const before = Uint8Array.from(alice.dhRemotePub!);
    ratchetDecrypt(alice, b0.header, module);
    expect(Buffer.from(alice.dhRemotePub!)).not.toEqual(Buffer.from(before));
    expect(Buffer.from(alice.dhRemotePub!)).toEqual(Buffer.from(b0.header.dhPub));
  });

  test("out-of-order delivery is served from skipped keys", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    const m1 = ratchetEncrypt(alice, module);
    const m2 = ratchetEncrypt(alice, module);

    const k2 = ratchetDecrypt(bob, m2.header, module); // skips 0,1
    const k0 = ratchetDecrypt(bob, m0.header, module); // from skipped
    const k1 = ratchetDecrypt(bob, m1.header, module); // from skipped

    expect(Buffer.from(k2)).toEqual(Buffer.from(m2.messageKey));
    expect(Buffer.from(k0)).toEqual(Buffer.from(m0.messageKey));
    expect(Buffer.from(k1)).toEqual(Buffer.from(m1.messageKey));
  });

  test("a jump beyond MAX_SKIP is rejected", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    ratchetDecrypt(bob, m0.header, module); // establish recv chain, Nr = 1

    const evil = { dhPub: m0.header.dhPub, N: MAX_SKIP + 100, PN: m0.header.PN };
    expect(() => ratchetDecrypt(bob, evil, module)).toThrow(/MAX_SKIP/);
  });

  test("serialize/deserialize preserves a pending skipped key", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    const m1 = ratchetEncrypt(alice, module);

    ratchetDecrypt(bob, m1.header, module); // m0 becomes skipped
    const snap = serializeRatchet(bob);
    expect(snap.skippedMessageKeys.length).toBe(1);

    const bob2 = deserializeRatchet(snap);
    const k0 = ratchetDecrypt(bob2, m0.header, module);
    expect(Buffer.from(k0)).toEqual(Buffer.from(m0.messageKey));
  });
});
