import { beforeAll, describe, expect, test } from "bun:test";

import {
  CoverCellError,
  COVER_CELL_HEADER_BYTES,
  COVER_CELL_TOKEN_BYTES,
  openCoverCell,
  sealCoverCell,
  type CoverCellContent,
  type OpenCoverCellOptions,
  type SealCoverCellOptions,
} from "../../src/cryptography/coverCell";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  FRAME_TYPE_COVER,
  RATCHET_ROOT_SUITE_MLKEM512,
  RATCHET_ROOT_SUITE_MLKEM768,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

const ROOT = (): Uint8Array => new Uint8Array(32).fill(0x51);
const BINDING = (fill = 0x42): Uint8Array => new Uint8Array(32).fill(fill);

const sealDefaults = (
  overrides: Partial<SealCoverCellOptions> = {},
): SealCoverCellOptions => ({
  module,
  rootSuite: RATCHET_ROOT_SUITE_MLKEM768,
  rootKey: ROOT(),
  binding: BINDING(),
  direction: "initiator-to-responder",
  keyEpoch: 3n,
  counter: 7n,
  content: { subtype: "dummy" },
  ...overrides,
});

const openDefaults = (
  frame: Uint8Array,
  overrides: Partial<OpenCoverCellOptions> = {},
): OpenCoverCellOptions => ({
  module,
  rootSuite: RATCHET_ROOT_SUITE_MLKEM768,
  rootKey: ROOT(),
  binding: BINDING(),
  direction: "initiator-to-responder",
  keyEpoch: 3n,
  frame,
  ...overrides,
});

const expectCode = (
  action: () => unknown,
  code: CoverCellError["code"],
): void => {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(CoverCellError);
    expect((error as CoverCellError).code).toBe(code);
    return;
  }
  throw new Error(`expected CoverCellError ${code}`);
};

describe("authenticated cover cells", () => {
  test("dummy, CANCEL, and receipt subtypes round-trip inside one uniform 65,490-byte cell", () => {
    const merkleRoot = new Uint8Array(COVER_CELL_TOKEN_BYTES).fill(0xaa);
    const token = new Uint8Array(COVER_CELL_TOKEN_BYTES).fill(0xbb);
    const contents: CoverCellContent[] = [
      { subtype: "dummy" },
      { subtype: "cancel", merkleRoot },
      { subtype: "receipt", merkleRoot, token },
    ];
    for (const [index, content] of contents.entries()) {
      const frame = sealCoverCell(
        sealDefaults({ content, counter: BigInt(index) }),
      );
      expect(frame).toHaveLength(WIRE_CHUNK_FRAME_LEN);
      expect(frame[0]).toBe(FRAME_TYPE_COVER);
      const opened = openCoverCell(openDefaults(frame));
      expect(opened.counter).toBe(BigInt(index));
      expect(opened.content.subtype).toBe(content.subtype);
      if (opened.content.subtype === "cancel")
        expect(Buffer.from(opened.content.merkleRoot)).toEqual(
          Buffer.from(merkleRoot),
        );
      if (opened.content.subtype === "receipt") {
        expect(Buffer.from(opened.content.merkleRoot)).toEqual(
          Buffer.from(merkleRoot),
        );
        expect(Buffer.from(opened.content.token)).toEqual(Buffer.from(token));
      }
    }
  });

  test("two dummy cells share only their public header shape", () => {
    const first = sealCoverCell(sealDefaults());
    const second = sealCoverCell(sealDefaults());
    expect(Buffer.from(first.subarray(0, 57))).toEqual(
      Buffer.from(second.subarray(0, 57)),
    );
    // Fresh nonce → distinct ciphertext for identical content.
    expect(Buffer.from(first.subarray(COVER_CELL_HEADER_BYTES))).not.toEqual(
      Buffer.from(second.subarray(COVER_CELL_HEADER_BYTES)),
    );
  });

  test("wrong direction, binding, epoch, root, and suite fail closed", () => {
    const frame = sealCoverCell(sealDefaults());
    expectCode(
      () =>
        openCoverCell(
          openDefaults(frame, { direction: "responder-to-initiator" }),
        ),
      "authentication-failed",
    );
    expectCode(
      () => openCoverCell(openDefaults(frame, { binding: BINDING(0x43) })),
      "binding-mismatch",
    );
    expectCode(
      () => openCoverCell(openDefaults(frame, { keyEpoch: 4n })),
      "epoch-mismatch",
    );
    expectCode(
      () =>
        openCoverCell(
          openDefaults(frame, { rootKey: new Uint8Array(32).fill(0x52) }),
        ),
      "authentication-failed",
    );
    expectCode(
      () =>
        openCoverCell(
          openDefaults(frame, { rootSuite: RATCHET_ROOT_SUITE_MLKEM512 }),
        ),
      "authentication-failed",
    );
  });

  test("any tampered byte fails authentication and reveals no subtype", () => {
    const frame = sealCoverCell(
      sealDefaults({
        content: {
          subtype: "cancel",
          merkleRoot: new Uint8Array(COVER_CELL_TOKEN_BYTES).fill(0xaa),
        },
      }),
    );
    for (const offset of [
      1, // binding → binding-mismatch before any crypto
      COVER_CELL_HEADER_BYTES, // first ciphertext byte
      WIRE_CHUNK_FRAME_LEN - 1, // AEAD tag
    ]) {
      const tampered = Uint8Array.from(frame);
      tampered[offset] ^= 1;
      expect(() => openCoverCell(openDefaults(tampered))).toThrow(
        CoverCellError,
      );
    }
    // A tampered counter byte breaks the AAD.
    const counterTampered = Uint8Array.from(frame);
    counterTampered[40] ^= 1;
    expectCode(
      () => openCoverCell(openDefaults(counterTampered)),
      "authentication-failed",
    );
    // A tampered reserved byte is rejected before decryption.
    const reservedTampered = Uint8Array.from(frame);
    reservedTampered[41] ^= 1;
    expectCode(
      () => openCoverCell(openDefaults(reservedTampered)),
      "invalid-cell",
    );
  });

  test("a replayed or stale counter is rejected when ordering is enforced", () => {
    const frame = sealCoverCell(sealDefaults({ counter: 7n }));
    expect(
      openCoverCell(openDefaults(frame, { counterAbove: 6n })).counter,
    ).toBe(7n);
    expectCode(
      () => openCoverCell(openDefaults(frame, { counterAbove: 7n })),
      "replayed-counter",
    );
    expectCode(
      () => openCoverCell(openDefaults(frame, { counterAbove: 8n })),
      "replayed-counter",
    );
  });

  test("malformed cells and payloads fail closed at seal time", () => {
    expectCode(
      () =>
        sealCoverCell(
          sealDefaults({
            content: {
              subtype: "cancel",
              merkleRoot: new Uint8Array(32),
            },
          }),
        ),
      "invalid-cell",
    );
    expectCode(
      () =>
        openCoverCell(
          openDefaults(new Uint8Array(WIRE_CHUNK_FRAME_LEN - 1)),
        ),
      "invalid-cell",
    );
    const wrongType = sealCoverCell(sealDefaults());
    wrongType[0] = 2; // FRAME_TYPE_CHUNK
    expectCode(() => openCoverCell(openDefaults(wrongType)), "invalid-cell");
  });
});
