import {
  CHANNEL_OPEN_POLL_MS,
  FRAME_TYPE_RECEIPT,
  MAX_BUFFERED_AMOUNT,
  RECEIPT_TOKEN_LEN,
  WIRE_RECEIPT_FRAME_LEN,
} from "../utils/constants";

interface ReceiptSendChannel {
  readonly readyState: string;
  readonly bufferedAmount: number;
  send(data: ArrayBuffer): void;
}

/** Encode a chunk token or terminal message hash as one canonical wire frame. */
export const encodeReceiptFrame = (token: Uint8Array): Uint8Array => {
  if (token.length !== RECEIPT_TOKEN_LEN)
    throw new Error("Receipt token must be exactly 64 bytes");

  const frame = new Uint8Array(WIRE_RECEIPT_FRAME_LEN);
  frame[0] = FRAME_TYPE_RECEIPT;
  frame.set(token, 1);
  return frame;
};

/** Return the zero-copy token only for the exact tagged receipt geometry. */
export const decodeReceiptFrame = (
  frame: Uint8Array,
): Uint8Array | undefined =>
  frame.length === WIRE_RECEIPT_FRAME_LEN && frame[0] === FRAME_TYPE_RECEIPT
    ? frame.subarray(1)
    : undefined;

export const sendReceiptFrame = (
  channel: Pick<ReceiptSendChannel, "readyState" | "send">,
  token: Uint8Array,
): boolean => {
  if (channel.readyState !== "open") return false;
  channel.send(encodeReceiptFrame(token).buffer as ArrayBuffer);
  return true;
};

export const RECEIPT_REPLAY_BATCH_SIZE = 32;
export const RECEIPT_REPLAY_PAUSE_MS = 10;

/**
 * Replay a reconnect have-set without filling SCTP or monopolising the event
 * loop. The caller may then send the terminal receipt on the same channel.
 */
export const sendReceiptFramesPaced = async (
  channel: ReceiptSendChannel,
  tokens: Iterable<Uint8Array>,
): Promise<boolean> => {
  let inBatch = 0;
  for (const token of tokens) {
    while (
      channel.readyState === "open" &&
      channel.bufferedAmount >= MAX_BUFFERED_AMOUNT
    ) {
      await new Promise((resolve) => setTimeout(resolve, CHANNEL_OPEN_POLL_MS));
    }
    if (channel.readyState !== "open") return false;

    channel.send(encodeReceiptFrame(token).buffer as ArrayBuffer);
    inBatch++;
    if (inBatch === RECEIPT_REPLAY_BATCH_SIZE) {
      inBatch = 0;
      await new Promise((resolve) =>
        setTimeout(resolve, RECEIPT_REPLAY_PAUSE_MS),
      );
    }
  }
  return channel.readyState === "open";
};
