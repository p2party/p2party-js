import { describe, expect, test } from "bun:test";

import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { MAX_MESSAGE_SIZE } from "../../src/utils/constants";
import { assertMetadataV1 } from "../../src/utils/metadata";

import type { Metadata } from "../../src/utils/metadata";

const validMetadata = (
  overrides: Partial<Metadata> = {},
): Metadata => ({
  schemaVersion: 1,
  messageType: 1,
  hash: new Uint8Array(crypto_hash_sha512_BYTES),
  totalSize: 1,
  date: new Date(0),
  name: "message",
  chunkStartIndex: 0,
  chunkEndIndex: 1,
  chunkIndex: 0,
  ...overrides,
});

describe("protocol metadata validation", () => {
  test("accepts the v1 boundary profile through the 10 GiB ceiling", () => {
    expect(() =>
      assertMetadataV1(validMetadata({ totalSize: MAX_MESSAGE_SIZE })),
    ).not.toThrow();
  });

  test("rejects unsupported schema and message-type values", () => {
    expect(() =>
      assertMetadataV1(validMetadata({ schemaVersion: 2 })),
    ).toThrow("schema");
    expect(() =>
      assertMetadataV1(validMetadata({ messageType: 0 })),
    ).toThrow("message type");
    expect(() =>
      assertMetadataV1(validMetadata({ messageType: 65 })),
    ).toThrow("message type");
  });

  test("rejects oversized or precision-losing authenticated integers", () => {
    expect(() =>
      assertMetadataV1(
        validMetadata({ totalSize: MAX_MESSAGE_SIZE + 1 }),
      ),
    ).toThrow("total size");
    expect(() =>
      assertMetadataV1(
        validMetadata({ chunkIndex: Number.MAX_SAFE_INTEGER + 1 }),
      ),
    ).toThrow("chunkIndex");
    expect(() =>
      assertMetadataV1(validMetadata({ date: new Date(Number.NaN) })),
    ).toThrow("timestamp");
  });
});
