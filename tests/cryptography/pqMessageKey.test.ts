import { describe, expect, test } from "bun:test";
import { hkdfSync } from "node:crypto";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  combinePqMessageKey,
  PQ_MESSAGE_KEY_BINDING_BYTES,
  type PqMessageKeyContext,
} from "../../src/cryptography/pqMessageKey";
import {
  FRAME_TYPE_CHUNK,
  RATCHET_ROOT_SUITE_MLKEM512,
  RATCHET_ROOT_SUITE_MLKEM768,
} from "../../src/utils/constants";

import type { RatchetHeader } from "../../src/cryptography/ratchet";

const domain = new TextEncoder().encode("p2party/pq-message-key/v1\u0000");

const referenceInfo = (
  context: PqMessageKeyContext,
  header: RatchetHeader,
): Uint8Array => {
  const suite = new TextEncoder().encode(context.rootSuite);
  const info = new Uint8Array(
    domain.length + 2 + suite.length + 32 + 8 + 1 + 32 + 8 + 8,
  );
  const view = new DataView(info.buffer);
  let offset = 0;
  info.set(domain, offset);
  offset += domain.length;
  view.setUint16(offset, suite.length, false);
  offset += 2;
  info.set(suite, offset);
  offset += suite.length;
  info.set(context.binding, offset);
  offset += 32;
  view.setBigUint64(offset, context.epoch, false);
  offset += 8;
  info[offset++] = FRAME_TYPE_CHUNK;
  info.set(header.dhPub, offset);
  offset += 32;
  view.setBigUint64(offset, BigInt(header.N), false);
  offset += 8;
  view.setBigUint64(offset, BigInt(header.PN), false);
  return info;
};

const makeContext = (): PqMessageKeyContext => ({
  rootKey: Uint8Array.from({ length: 32 }, (_, index) => 0xa0 + index),
  binding: Uint8Array.from(
    { length: PQ_MESSAGE_KEY_BINDING_BYTES },
    (_, index) => index * 3,
  ),
  rootSuite: RATCHET_ROOT_SUITE_MLKEM768,
  epoch: 0x0102_0304_0506_0708n,
});

const header: RatchetHeader = {
  dhPub: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
  N: 23,
  PN: 17,
};

describe("protocol-v4 PQ message-key combiner", () => {
  test("matches HKDF-SHA512 reference bytes, consumes classical input, and preserves the live PQ root", async () => {
    const module = await loadTestModule();
    const context = makeContext();
    const rootBefore = Uint8Array.from(context.rootKey);
    const classical = Uint8Array.from(
      { length: 32 },
      (_, index) => 0x40 + index,
    );
    const referenceClassical = Uint8Array.from(classical);
    const expected = new Uint8Array(
      hkdfSync(
        "sha512",
        referenceClassical,
        context.rootKey,
        referenceInfo(context, header),
        32,
      ),
    );

    const combined = combinePqMessageKey(classical, context, header, module);

    expect(Buffer.from(combined)).toEqual(Buffer.from(expected));
    expect(classical.every((byte) => byte === 0)).toBe(true);
    expect(Buffer.from(context.rootKey)).toEqual(Buffer.from(rootBefore));
  });

  test("suite, binding, epoch, and every ratchet-header component change the key", async () => {
    const module = await loadTestModule();
    const baseContext = makeContext();
    const derive = (
      context: PqMessageKeyContext,
      candidateHeader: RatchetHeader,
    ): Uint8Array =>
      combinePqMessageKey(
        new Uint8Array(32).fill(0x55),
        context,
        candidateHeader,
        module,
      );
    const baseline = derive(baseContext, header);
    const changedBinding = Uint8Array.from(baseContext.binding);
    changedBinding[0] ^= 1;
    const changedDh = Uint8Array.from(header.dhPub);
    changedDh[0] ^= 1;
    const candidates = [
      derive(
        { ...baseContext, rootSuite: RATCHET_ROOT_SUITE_MLKEM512 },
        header,
      ),
      derive({ ...baseContext, binding: changedBinding }, header),
      derive({ ...baseContext, epoch: baseContext.epoch + 1n }, header),
      derive(baseContext, { ...header, dhPub: changedDh }),
      derive(baseContext, { ...header, N: header.N + 1 }),
      derive(baseContext, { ...header, PN: header.PN + 1 }),
    ];
    for (const candidate of candidates)
      expect(Buffer.from(candidate)).not.toEqual(Buffer.from(baseline));
  });

  test("validation failure still wipes the consumed classical key but never the context root", async () => {
    const module = await loadTestModule();
    const context = makeContext();
    const rootBefore = Uint8Array.from(context.rootKey);
    const classical = new Uint8Array(32).fill(0x77);

    expect(() =>
      combinePqMessageKey(
        classical,
        { ...context, binding: new Uint8Array(31) },
        header,
        module,
      ),
    ).toThrow("binding must be 32 bytes");
    expect(classical.every((byte) => byte === 0)).toBe(true);
    expect(Buffer.from(context.rootKey)).toEqual(Buffer.from(rootBefore));
  });
});
