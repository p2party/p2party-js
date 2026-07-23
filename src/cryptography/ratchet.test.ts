import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import {
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchet,
  deserializeRatchet,
} from "./ratchet";
import type { RatchetSessionSecrets } from "./ratchet";
import { MAX_SKIP, MAX_SKIP_SESSION } from "../utils/constants";

// True iff the (dhPub, n) pair is present in a serialized skipped-key snapshot
// — used to probe eviction without depending on the internal Map key encoding.
const hasSkippedEntry = (
  secrets: RatchetSessionSecrets,
  dhPub: Uint8Array,
  n: number,
): boolean =>
  secrets.skippedMessageKeys.some(
    (e) => e.n === n && Buffer.from(e.dhPub).equals(Buffer.from(dhPub)),
  );

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

  test("global MAX_SKIP_SESSION cap evicts the oldest skipped keys across many DH steps", async () => {
    const { module, alice, bob } = await pair();

    // Each round: Alice fires `perRound + 1` messages on her current chain but
    // only the LAST is delivered to Bob, so decrypting it stashes `perRound`
    // skipped keys (well under the per-call MAX_SKIP=512 bound). Bob then
    // replies and Alice decrypts the reply, which DH-steps Alice onto a fresh
    // dhPub for the next round — so each round's skipped keys are stored under
    // a distinct dhPub, matching "a peer that repeatedly DH-steps".
    const perRound = 500;
    const rounds = 5; // 5 * 500 = 2500 > MAX_SKIP_SESSION (2000): forces eviction
    expect(perRound).toBeLessThan(MAX_SKIP);
    expect(rounds * perRound).toBeGreaterThan(MAX_SKIP_SESSION);

    let firstRoundDhPub: Uint8Array | null = null;
    let lastRoundDhPub: Uint8Array | null = null;
    let lastRoundFirstMessageKey: Uint8Array | null = null;

    for (let r = 0; r < rounds; r++) {
      const first = ratchetEncrypt(alice, module); // N=0 of this round's chain
      let last = first;
      for (let i = 0; i < perRound; i++) {
        last = ratchetEncrypt(alice, module);
      }
      ratchetDecrypt(bob, last.header, module);

      if (r === 0) firstRoundDhPub = Uint8Array.from(last.header.dhPub);
      if (r === rounds - 1) {
        lastRoundDhPub = Uint8Array.from(last.header.dhPub);
        lastRoundFirstMessageKey = first.messageKey;
      }

      const reply = ratchetEncrypt(bob, module);
      ratchetDecrypt(alice, reply.header, module);
    }

    // Bounded: never exceeds the global cap despite ~2500 logical skips.
    expect(bob.skipped.size).toBeLessThanOrEqual(MAX_SKIP_SESSION);

    const snap = serializeRatchet(bob);
    // Oldest round's entries are gone (evicted first)...
    expect(hasSkippedEntry(snap, firstRoundDhPub!, 0)).toBe(false);
    // ...while a still-needed key from the most recent round survives and
    // remains usable (and matches the original message key exactly).
    expect(hasSkippedEntry(snap, lastRoundDhPub!, 0)).toBe(true);
    const bob2 = deserializeRatchet(snap);
    const recovered = ratchetDecrypt(
      bob2,
      { dhPub: lastRoundDhPub!, N: 0, PN: perRound },
      module,
    );
    expect(Buffer.from(recovered)).toEqual(Buffer.from(lastRoundFirstMessageKey!));
  });

  test("global skipped-key eviction wipes the evicted key buffer", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    ratchetDecrypt(bob, m0.header, module); // establish recv chain, Nr = 1

    const m1 = ratchetEncrypt(alice, module);
    const m2 = ratchetEncrypt(alice, module);
    expect(m1.header.N).toBe(1);
    expect(m2.header.N).toBe(2);

    // Fill the cumulative cache to its cap with a sentinel as the oldest
    // insertion. Decrypting m2 derives/stashes m1, forcing exactly one
    // oldest-first eviction while this reference remains observable.
    const evictedKeyReference = new Uint8Array(32).fill(0xa5);
    bob.skipped.set("oldest-sentinel", evictedKeyReference);
    for (let i = 1; i < MAX_SKIP_SESSION; i++) {
      bob.skipped.set(`synthetic:${i}`, new Uint8Array(32).fill(i & 0xff));
    }

    const recovered = ratchetDecrypt(bob, m2.header, module);
    expect(Buffer.from(recovered)).toEqual(Buffer.from(m2.messageKey));
    expect(bob.skipped.has("oldest-sentinel")).toBe(false);
    expect(evictedKeyReference.every((byte) => byte === 0)).toBe(true);
  });

  test("a header with a negative or non-integer N/PN is rejected", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);

    expect(() =>
      ratchetDecrypt(bob, { ...m0.header, N: -1 }, module),
    ).toThrow(/invalid ratchet header/);
    expect(() =>
      ratchetDecrypt(bob, { ...m0.header, N: 1.5 }, module),
    ).toThrow(/invalid ratchet header/);
    expect(() =>
      ratchetDecrypt(bob, { ...m0.header, PN: -1 }, module),
    ).toThrow(/invalid ratchet header/);
    expect(() =>
      ratchetDecrypt(bob, { ...m0.header, PN: 1.5 }, module),
    ).toThrow(/invalid ratchet header/);
  });
});
