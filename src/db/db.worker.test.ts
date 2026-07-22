// Stage 3 / Task 4 — db.worker.ts wiring for the `ratchetSessions` store:
// fnGetRatchetSession / fnSetRatchetSession / fnDeleteRatchetSession, plus the
// onmessage cases that dispatch "getRatchetSession" / "setRatchetSession" /
// "deleteRatchetSession" to them.
//
// db.worker.ts has no exports (it's a worker entry point that wires up a
// global `onmessage`), so it is exercised here the same way the real caller
// (src/db/api.ts, via a Worker) exercises it: by importing the module (which
// installs `onmessage` as a side effect) and dispatching real
// `{ id, method, args }` messages through that handler, capturing whatever it
// posts back via `postMessage`. This covers the actual wiring end-to-end
// (onmessage -> fn* -> getDB / getWrapKey / wrap|unwrapRatchetSession), not a
// re-implemented test double.
//
// The key security assertion: after fnSetRatchetSession, the RAW row read
// directly from the `ratchetSessions` store (bypassing fnGetRatchetSession's
// unwrap step) must be ciphertext — the plaintext ratchet secrets must never
// touch disk.
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { beforeEach, describe, expect, test } from "bun:test";

import { getDB } from "./src/getDB";

import type { RatchetSession } from "./types";

beforeEach(() => {
  (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
    new IDBFactory();
});

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
const eq = (a: ArrayBuffer, b: ArrayBuffer) =>
  Buffer.from(new Uint8Array(a)).equals(Buffer.from(new Uint8Array(b)));

const sampleSession = (): RatchetSession => ({
  roomId: "room-1",
  peerPublicKey: "aa".repeat(32),
  peerId: "peer-abc-123",
  rootKey: rnd(32),
  sendingChainKey: rnd(32),
  receivingChainKey: null,
  dhSelfPub: rnd(32),
  dhSelfSec: rnd(32),
  dhRemotePub: rnd(32),
  Ns: 3,
  Nr: 1,
  PN: 2,
  skippedMessageKeys: [{ dhPub: rnd(32), n: 0, messageKey: rnd(32) }],
  updatedAt: 111,
});

interface WorkerResponse {
  id: number;
  result?: unknown;
  error?: unknown;
}

let nextId = 1;

// Dispatches a real message through db.worker.ts's actual `onmessage` handler
// and captures whatever it posts back, matched by id.
async function callWorker(
  method: string,
  args: unknown[],
): Promise<WorkerResponse> {
  await import("./db.worker"); // idempotent after the first call
  const id = nextId++;
  let captured: WorkerResponse | undefined;
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    (m: unknown) => {
      captured = m as WorkerResponse;
    };
  const handler = (
    globalThis as unknown as {
      onmessage: (e: MessageEvent) => Promise<void>;
    }
  ).onmessage;
  await handler({ data: { id, method, args } } as MessageEvent);
  if (!captured || captured.id !== id) {
    throw new Error(`worker did not respond to message id ${id}`);
  }
  return captured;
}

describe("db.worker ratchetSessions wiring", () => {
  test("setRatchetSession -> getRatchetSession round-trips the ORIGINAL session (secrets intact)", async () => {
    const s = sampleSession();
    const setResp = await callWorker("setRatchetSession", [s]);
    expect(setResp.error).toBeUndefined();

    const getResp = await callWorker("getRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(getResp.error).toBeUndefined();
    const got = getResp.result as RatchetSession;
    expect(got).toBeDefined();
    expect(eq(got.rootKey, s.rootKey)).toBe(true);
    expect(eq(got.dhSelfSec, s.dhSelfSec)).toBe(true);
    expect(
      got.sendingChainKey != null &&
        eq(got.sendingChainKey, s.sendingChainKey as ArrayBuffer),
    ).toBe(true);
    expect(got.receivingChainKey).toBe(null);
    expect(
      eq(
        got.skippedMessageKeys[0].messageKey,
        s.skippedMessageKeys[0].messageKey,
      ),
    ).toBe(true);
    expect(
      eq(got.skippedMessageKeys[0].dhPub, s.skippedMessageKeys[0].dhPub),
    ).toBe(true);
    expect(got.Ns).toBe(3);
    expect(got.Nr).toBe(1);
    expect(got.PN).toBe(2);
    expect(got.peerId).toBe("peer-abc-123");
    expect(got.roomId).toBe("room-1");
  });

  test("KEY SECURITY ASSERTION: the raw stored row in `ratchetSessions` is ciphertext, not plaintext", async () => {
    const s = sampleSession();
    await callWorker("setRatchetSession", [s]);

    // Read the RAW row directly from the store, bypassing fnGetRatchetSession's
    // unwrap step entirely — this is what would be visible to anything reading
    // the on-disk IndexedDB directly.
    const db = await getDB();
    const raw = (await db.get("ratchetSessions", [
      s.roomId,
      s.peerPublicKey,
    ])) as RatchetSession;
    db.close();

    expect(raw).toBeDefined();
    expect(eq(raw.rootKey, s.rootKey)).toBe(false);
    expect(eq(raw.dhSelfSec, s.dhSelfSec)).toBe(false);
    expect(
      raw.sendingChainKey != null &&
        eq(raw.sendingChainKey, s.sendingChainKey as ArrayBuffer),
    ).toBe(false);
    expect(
      eq(
        raw.skippedMessageKeys[0].messageKey,
        s.skippedMessageKeys[0].messageKey,
      ),
    ).toBe(false);
    // Public / counter fields pass through unwrapped — stored plaintext.
    expect(eq(raw.dhSelfPub, s.dhSelfPub)).toBe(true);
    expect(
      eq(raw.skippedMessageKeys[0].dhPub, s.skippedMessageKeys[0].dhPub),
    ).toBe(true);
    expect(raw.receivingChainKey).toBe(null);
    expect(raw.Ns).toBe(3);
    expect(raw.roomId).toBe("room-1");
    expect(raw.peerPublicKey).toBe("aa".repeat(32));
  });

  test("deleteRatchetSession removes the row", async () => {
    const s = sampleSession();
    await callWorker("setRatchetSession", [s]);

    const before = await callWorker("getRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(before.result).toBeDefined();

    const delResp = await callWorker("deleteRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(delResp.error).toBeUndefined();

    const after = await callWorker("getRatchetSession", [
      s.roomId,
      s.peerPublicKey,
    ]);
    expect(after.result).toBeUndefined();
  });

  test("getRatchetSession on a missing row returns undefined (not an error)", async () => {
    const resp = await callWorker("getRatchetSession", [
      "no-such-room",
      "bb".repeat(32),
    ]);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeUndefined();
  });
});

describe("db.worker identityX25519 wiring (WebCrypto-wrapped at rest)", () => {
  const sampleIdentity = () => ({
    pub: rnd(32),
    secret: rnd(32),
    crossSig: rnd(64),
  });

  test("setIdentityX25519 -> getIdentityX25519 round-trips pub/secret/crossSig", async () => {
    const idn = sampleIdentity();
    const setResp = await callWorker("setIdentityX25519", [idn]);
    expect(setResp.error).toBeUndefined();

    const getResp = await callWorker("getIdentityX25519", []);
    expect(getResp.error).toBeUndefined();
    const got = getResp.result as {
      pub: ArrayBuffer;
      secret: ArrayBuffer;
      crossSig: ArrayBuffer;
    };
    expect(got).toBeDefined();
    expect(eq(got.pub, idn.pub)).toBe(true);
    expect(eq(got.secret, idn.secret)).toBe(true);
    expect(eq(got.crossSig, idn.crossSig)).toBe(true);
  });

  test("KEY SECURITY ASSERTION: the raw stored identity secret is ciphertext; pub/crossSig are plaintext", async () => {
    const idn = sampleIdentity();
    await callWorker("setIdentityX25519", [idn]);

    // Read the raw record directly, bypassing the unwrap step.
    const db = await getDB();
    const raw = (await db.get("meta", "identityX25519")) as unknown as {
      pub: ArrayBuffer;
      wrappedSecret: ArrayBuffer;
      crossSig: ArrayBuffer;
    };
    db.close();

    expect(raw).toBeDefined();
    // secret is wrapped (iv||ct): different bytes AND longer than the 32B plaintext.
    expect(eq(raw.wrappedSecret, idn.secret)).toBe(false);
    expect(raw.wrappedSecret.byteLength).toBeGreaterThan(idn.secret.byteLength);
    // public fields are stored in the clear.
    expect(eq(raw.pub, idn.pub)).toBe(true);
    expect(eq(raw.crossSig, idn.crossSig)).toBe(true);
  });

  test("deleteIdentityX25519 removes the record; get then returns undefined", async () => {
    const idn = sampleIdentity();
    await callWorker("setIdentityX25519", [idn]);
    expect((await callWorker("getIdentityX25519", [])).result).toBeDefined();

    const delResp = await callWorker("deleteIdentityX25519", []);
    expect(delResp.error).toBeUndefined();

    const after = await callWorker("getIdentityX25519", []);
    expect(after.result).toBeUndefined();
  });

  test("getIdentityX25519 with no record returns undefined (not an error)", async () => {
    const resp = await callWorker("getIdentityX25519", []);
    expect(resp.error).toBeUndefined();
    expect(resp.result).toBeUndefined();
  });
});
