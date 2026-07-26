import { describe, expect, test } from "bun:test";

import { createChunkReceiptToken } from "../../src/utils/receiptToken";

describe("protocol-v3 chunk receipt tokens", () => {
  test("are deterministic, uniform 64-byte values", async () => {
    const root = new Uint8Array(64).fill(1);
    const leaf = new Uint8Array(64).fill(2);
    const first = await createChunkReceiptToken(root, 7, leaf);
    const second = await createChunkReceiptToken(root, 7, leaf);

    expect(first).toEqual(second);
    expect(first.length).toBe(64);
  });

  test("bind the root, chunk index, and leaf hash", async () => {
    const root = new Uint8Array(64).fill(1);
    const otherRoot = new Uint8Array(root);
    otherRoot[63] = 9;
    const leaf = new Uint8Array(64).fill(2);
    const otherLeaf = new Uint8Array(leaf);
    otherLeaf[63] = 8;

    const token = await createChunkReceiptToken(root, 7, leaf);
    expect(await createChunkReceiptToken(otherRoot, 7, leaf)).not.toEqual(
      token,
    );
    expect(await createChunkReceiptToken(root, 8, leaf)).not.toEqual(token);
    expect(await createChunkReceiptToken(root, 7, otherLeaf)).not.toEqual(
      token,
    );
  });

  test("partial-resume receipts distinguish duplicate equal leaves", async () => {
    const root = new Uint8Array(64).fill(3);
    const duplicateLeaf = new Uint8Array(64).fill(4);
    const heldIndex = 2;
    const missingIndex = 9;

    const replayed = await createChunkReceiptToken(
      root,
      heldIndex,
      duplicateLeaf,
    );
    const missing = await createChunkReceiptToken(
      root,
      missingIndex,
      duplicateLeaf,
    );

    expect(replayed).not.toEqual(missing);
    const senderLookup = new Map([
      [Buffer.from(replayed).toString("hex"), heldIndex],
      [Buffer.from(missing).toString("hex"), missingIndex],
    ]);
    expect(senderLookup.get(Buffer.from(replayed).toString("hex"))).toBe(
      heldIndex,
    );
  });

  test("rejects malformed inputs", async () => {
    await expect(
      createChunkReceiptToken(new Uint8Array(63), 0, new Uint8Array(64)),
    ).rejects.toThrow("Merkle root");
    await expect(
      createChunkReceiptToken(new Uint8Array(64), -1, new Uint8Array(64)),
    ).rejects.toThrow("index");
    await expect(
      createChunkReceiptToken(new Uint8Array(64), 0, new Uint8Array(63)),
    ).rejects.toThrow("leaf hash");
  });
});
