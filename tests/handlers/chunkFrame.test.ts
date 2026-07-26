import { describe, expect, test } from "bun:test";

import {
  packChunkFrameHeader,
  parseChunkFrameHeader,
  CHUNK_FRAME_HEADER_LEN,
} from "../../src/handlers/chunkFrame";
import {
  FRAME_TYPE_CHUNK,
  RATCHET_DHPUB_LEN,
  RATCHET_NONCE_LEN,
} from "../../src/utils/constants";

describe("v4 chunk-frame codec", () => {
  test("pack -> parse round-trips the ratchet header, u64 epoch, nonce, and ciphertext byte-exact", () => {
    const dhPub = Uint8Array.from(
      { length: RATCHET_DHPUB_LEN },
      (_, i) => i + 1,
    );
    const nonce = Uint8Array.from(
      { length: RATCHET_NONCE_LEN },
      (_, i) => 100 + i,
    );
    const header = { dhPub, N: 5, PN: 3 };
    const pqEpoch = 0x0102_0304_0506_0708n;
    const ciphertext = new Uint8Array([9, 8, 7, 6, 5]);

    const hdr = packChunkFrameHeader(header, nonce, pqEpoch);
    expect(hdr.length).toBe(CHUNK_FRAME_HEADER_LEN); // 69
    expect(hdr[0]).toBe(FRAME_TYPE_CHUNK);
    expect([...hdr.slice(49, 57)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

    const frame = new Uint8Array(hdr.length + ciphertext.length);
    frame.set(hdr, 0);
    frame.set(ciphertext, hdr.length);

    const p = parseChunkFrameHeader(frame);
    expect([...p.header.dhPub]).toEqual([...dhPub]);
    expect(p.header.N).toBe(5);
    expect(p.header.PN).toBe(3);
    expect(p.pqEpoch).toBe(pqEpoch);
    expect([...p.nonce]).toEqual([...nonce]);
    expect([...p.ciphertext]).toEqual([...ciphertext]);
  });

  test("safe counters and the complete u64 epoch range round-trip; malformed values throw", () => {
    const dhPub = new Uint8Array(RATCHET_DHPUB_LEN);
    const nonce = new Uint8Array(RATCHET_NONCE_LEN);
    const big = Number.MAX_SAFE_INTEGER; // 2^53 - 1

    const hdr = packChunkFrameHeader(
      { dhPub, N: big, PN: big },
      nonce,
      (1n << 64n) - 1n,
    );
    const p = parseChunkFrameHeader(new Uint8Array([...hdr, 1, 2, 3]));
    expect(p.header.N).toBe(big);
    expect(p.header.PN).toBe(big);
    expect(p.pqEpoch).toBe((1n << 64n) - 1n);

    // wrong nonce length
    expect(() =>
      packChunkFrameHeader({ dhPub, N: 0, PN: 0 }, new Uint8Array(11)),
    ).toThrow();
    // counter out of safe integer range
    expect(() =>
      packChunkFrameHeader({ dhPub, N: big + 1, PN: 0 }, nonce),
    ).toThrow();
    expect(() =>
      packChunkFrameHeader({ dhPub, N: 0, PN: 0 }, nonce, -1n),
    ).toThrow("PQ epoch out of u64 range");
    expect(() =>
      packChunkFrameHeader({ dhPub, N: 0, PN: 0 }, nonce, 1n << 64n),
    ).toThrow("PQ epoch out of u64 range");
    // frame too short to hold a header
    expect(() => parseChunkFrameHeader(new Uint8Array(10))).toThrow();
    // wrong leading frame type
    const notChunk = new Uint8Array(CHUNK_FRAME_HEADER_LEN);
    notChunk[0] = 99;
    expect(() => parseChunkFrameHeader(notChunk)).toThrow();

    // The omitted low-level epoch remains bootstrap epoch zero for existing
    // callers; production passes an explicit authenticated context.
    expect(
      parseChunkFrameHeader(packChunkFrameHeader({ dhPub, N: 0, PN: 0 }, nonce))
        .pqEpoch,
    ).toBe(0n);
  });
});
