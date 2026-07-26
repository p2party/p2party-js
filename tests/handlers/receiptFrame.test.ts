import { describe, expect, test } from "bun:test";

import {
  decodeReceiptFrame,
  encodeReceiptFrame,
  sendReceiptFrame,
  sendReceiptFramesPaced,
} from "../../src/handlers/receiptFrame";
import {
  FRAME_TYPE_RECEIPT,
  MAX_BUFFERED_AMOUNT,
  WIRE_RECEIPT_FRAME_LEN,
} from "../../src/utils/constants";

describe("protocol-v3 receipt wire frames", () => {
  test("encodes and decodes only tag(1) + token(64)", () => {
    const token = new Uint8Array(64).fill(0x42);
    const frame = encodeReceiptFrame(token);
    expect(frame).toHaveLength(WIRE_RECEIPT_FRAME_LEN);
    expect(frame[0]).toBe(FRAME_TYPE_RECEIPT);
    expect([...decodeReceiptFrame(frame)!]).toEqual([...token]);

    expect(decodeReceiptFrame(token)).toBeUndefined();
    expect(
      decodeReceiptFrame(new Uint8Array([FRAME_TYPE_RECEIPT, ...token, 0])),
    ).toBeUndefined();
    expect(() => encodeReceiptFrame(new Uint8Array(63))).toThrow(
      "exactly 64 bytes",
    );
  });

  test("all production send helpers emit exact tagged frames", async () => {
    const sent: ArrayBuffer[] = [];
    const channel = {
      readyState: "open" as RTCDataChannelState,
      bufferedAmount: 0,
      send: (data: ArrayBuffer) => {
        sent.push(data);
      },
    };
    const first = new Uint8Array(64).fill(1);
    const second = new Uint8Array(64).fill(2);

    expect(sendReceiptFrame(channel, first)).toBe(true);
    expect(await sendReceiptFramesPaced(channel, [second])).toBe(true);
    expect(sent).toHaveLength(2);
    for (const buffer of sent) {
      const frame = new Uint8Array(buffer);
      expect(frame).toHaveLength(WIRE_RECEIPT_FRAME_LEN);
      expect(frame[0]).toBe(FRAME_TYPE_RECEIPT);
    }
  });

  test("reconnect replay respects backpressure before sending", async () => {
    const sent: ArrayBuffer[] = [];
    const channel = {
      readyState: "open" as RTCDataChannelState,
      bufferedAmount: MAX_BUFFERED_AMOUNT,
      send: (data: ArrayBuffer) => {
        sent.push(data);
      },
    };
    setTimeout(() => {
      channel.bufferedAmount = 0;
    }, 5);

    expect(await sendReceiptFramesPaced(channel, [new Uint8Array(64)])).toBe(
      true,
    );
    expect(sent).toHaveLength(1);
  });
});
