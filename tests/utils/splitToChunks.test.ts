import { describe, expect, test } from "bun:test";

import {
  estimateOutboundStagingBytes,
  planMessageChunkCount,
} from "../../src/utils/splitToChunks";
import {
  CHUNK_LEN,
  MAX_MESSAGE_SIZE,
  METADATA_LEN,
  PROOF_LEN,
} from "../../src/utils/constants";

describe("outbound staging plan", () => {
  test("charges padded cells, proofs/metadata, and a sender self-copy", () => {
    const totalSize = 100;
    const totalChunks = 3;
    const estimate = estimateOutboundStagingBytes(
      totalSize,
      totalChunks,
      CHUNK_LEN,
    );

    expect(estimate).toBeGreaterThan(
      totalSize + totalChunks * (CHUNK_LEN + METADATA_LEN + PROOF_LEN),
    );
    expect(estimate).toBeGreaterThan(totalSize * 1000);
  });

  test("cover padding can make storage much larger than raw content", () => {
    const totalSize = 1;
    const totalChunks = planMessageChunkCount(totalSize, 10);
    expect(
      estimateOutboundStagingBytes(totalSize, totalChunks, CHUNK_LEN),
    ).toBeGreaterThan(CHUNK_LEN * 10);
  });

  test("rejects deterministic 100%-full cells used by exact duplicate sends", () => {
    expect(() => planMessageChunkCount(CHUNK_LEN, 1, CHUNK_LEN, 1)).toThrow(
      "0.99",
    );
    // At 99%, every leaf retains RNG-filled bytes. That fresh root namespace
    // separates wire labels/receiver storage; it is transfer identity, not a
    // claim that cover traffic is enabled.
    expect(planMessageChunkCount(CHUNK_LEN, 1, CHUNK_LEN, 0.99)).toBe(2);
  });

  test("rejects payloads above the 10 GiB protocol ceiling before staging", () => {
    expect(planMessageChunkCount(MAX_MESSAGE_SIZE)).toBeGreaterThan(0);
    expect(() => planMessageChunkCount(MAX_MESSAGE_SIZE + 1)).toThrow(
      "protocol limit",
    );
  });
});
