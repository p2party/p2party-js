import { describe, expect, test } from "bun:test";

import {
  packChunkFrameHeader,
  parseChunkFrameHeader,
  CHUNK_FRAME_HEADER_LEN,
} from "./chunkFrame";
import {
  FRAME_TYPE_CHUNK,
  RATCHET_DHPUB_LEN,
  RATCHET_NONCE_LEN,
} from "../utils/constants";

describe("v3 chunk-frame codec", () => {
  test("pack -> parse round-trips the ratchet header, nonce, and ciphertext byte-exact", () => {
    const dhPub = Uint8Array.from({ length: RATCHET_DHPUB_LEN }, (_, i) => i + 1);
    const nonce = Uint8Array.from({ length: RATCHET_NONCE_LEN }, (_, i) => 100 + i);
    const header = { dhPub, N: 5, PN: 3 };
    const ciphertext = new Uint8Array([9, 8, 7, 6, 5]);

    const hdr = packChunkFrameHeader(header, nonce);
    expect(hdr.length).toBe(CHUNK_FRAME_HEADER_LEN); // 62
    expect(hdr[0]).toBe(FRAME_TYPE_CHUNK);

    const frame = new Uint8Array(hdr.length + ciphertext.length);
    frame.set(hdr, 0);
    frame.set(ciphertext, hdr.length);

    const p = parseChunkFrameHeader(frame);
    expect([...p.header.dhPub]).toEqual([...dhPub]);
    expect(p.header.N).toBe(5);
    expect(p.header.PN).toBe(3);
    expect([...p.nonce]).toEqual([...nonce]);
    expect([...p.ciphertext]).toEqual([...ciphertext]);
  });

  test("large counters near 2^53 round-trip; bad length / wrong type / out-of-range throw", () => {
    const dhPub = new Uint8Array(RATCHET_DHPUB_LEN);
    const nonce = new Uint8Array(RATCHET_NONCE_LEN);
    const big = Number.MAX_SAFE_INTEGER; // 2^53 - 1

    const hdr = packChunkFrameHeader({ dhPub, N: big, PN: big }, nonce);
    const p = parseChunkFrameHeader(new Uint8Array([...hdr, 1, 2, 3]));
    expect(p.header.N).toBe(big);
    expect(p.header.PN).toBe(big);

    // wrong nonce length
    expect(() =>
      packChunkFrameHeader({ dhPub, N: 0, PN: 0 }, new Uint8Array(11)),
    ).toThrow();
    // counter out of safe integer range
    expect(() =>
      packChunkFrameHeader({ dhPub, N: big + 1, PN: 0 }, nonce),
    ).toThrow();
    // frame too short to hold a header
    expect(() => parseChunkFrameHeader(new Uint8Array(10))).toThrow();
    // wrong leading frame type
    const notChunk = new Uint8Array(CHUNK_FRAME_HEADER_LEN);
    notChunk[0] = 99;
    expect(() => parseChunkFrameHeader(notChunk)).toThrow();
  });
});
