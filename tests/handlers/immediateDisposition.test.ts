import { describe, expect, test } from "bun:test";
import {
  IMMEDIATE_RESUME_PROTOCOL,
  acceptImmediateDisposition,
  bindImmediateDisposition,
  hasImmediateRemoteCancel,
  immediateCloseMeansPause,
  sendImmediateCancel,
  sendImmediateResumeCapability,
} from "../../src/handlers/immediateDisposition";
import type { IRTCDataChannel } from "../../src/api/webrtc/interfaces";

const root = new Uint8Array(64).fill(37);
function endpoint(incoming: boolean, protocol = IMMEDIATE_RESUME_PROTOCOL) {
  let authenticated = true;
  const sent: Uint8Array[] = [];
  const channel = {
    protocol,
    readyState: "open",
    bufferedAmount: 0,
    send: (bytes: ArrayBuffer) => sent.push(new Uint8Array(bytes)),
  } as unknown as IRTCDataChannel;
  bindImmediateDisposition(channel, root, incoming, () => authenticated);
  return {
    channel,
    sent,
    authenticate: (value: boolean) => {
      authenticated = value;
    },
  };
}

describe("immediate transfer pause and explicit cancellation", () => {
  test("the opener waits for the receiver capability; legacy close remains cancel", () => {
    const sender = endpoint(false);
    const receiver = endpoint(true);
    expect(immediateCloseMeansPause(sender.channel)).toBe(false);
    expect(immediateCloseMeansPause(receiver.channel)).toBe(true);
    sendImmediateResumeCapability(receiver.channel);
    expect(acceptImmediateDisposition(sender.channel, receiver.sent[0])).toBe(
      "capability",
    );
    expect(immediateCloseMeansPause(sender.channel)).toBe(true);
    expect(hasImmediateRemoteCancel(sender.channel)).toBe(false);
  });

  test("raw legacy channels neither advertise nor consume the new protocol", async () => {
    const old = endpoint(true, "raw");
    const current = endpoint(true);
    sendImmediateResumeCapability(old.channel);
    await sendImmediateCancel(old.channel);
    await sendImmediateCancel(current.channel);
    expect(old.sent).toHaveLength(0);
    expect(
      acceptImmediateDisposition(old.channel, current.sent[0]),
    ).toBeUndefined();
    expect(immediateCloseMeansPause(old.channel)).toBe(false);
  });

  test("explicit CANCEL is idempotent and scoped to the concrete channel", async () => {
    const sender = endpoint(false);
    const receiver = endpoint(true);
    const anotherRecipient = endpoint(false);
    await sendImmediateCancel(receiver.channel);
    await sendImmediateCancel(receiver.channel);
    expect(receiver.sent).toHaveLength(1);
    expect(acceptImmediateDisposition(sender.channel, receiver.sent[0])).toBe(
      "cancel",
    );
    expect(
      acceptImmediateDisposition(sender.channel, receiver.sent[0]),
    ).toBeUndefined();
    expect(hasImmediateRemoteCancel(sender.channel)).toBe(true);
    expect(hasImmediateRemoteCancel(anotherRecipient.channel)).toBe(false);
  });

  test("pre-authentication and replaced transport gates cannot send or accept controls", async () => {
    const sender = endpoint(false);
    const receiver = endpoint(true);
    await sendImmediateCancel(receiver.channel);
    sender.authenticate(false);
    expect(
      acceptImmediateDisposition(sender.channel, receiver.sent[0]),
    ).toBeUndefined();
    await sendImmediateCancel(sender.channel);
    sendImmediateResumeCapability(sender.channel);
    expect(sender.sent).toHaveLength(0);
    expect(hasImmediateRemoteCancel(sender.channel)).toBe(false);
  });

  test("cross-root, unknown subtype, wrong tag and noncanonical geometry are ignored", async () => {
    const sender = endpoint(false);
    const receiver = endpoint(true);
    await sendImmediateCancel(receiver.channel);
    for (const index of [0, 1, 2, 65]) {
      const forged = receiver.sent[0].slice();
      forged[index] ^= 255;
      expect(
        acceptImmediateDisposition(sender.channel, forged),
      ).toBeUndefined();
    }
    expect(
      acceptImmediateDisposition(sender.channel, receiver.sent[0].subarray(1)),
    ).toBeUndefined();
    expect(
      acceptImmediateDisposition(sender.channel, new Uint8Array(67)),
    ).toBeUndefined();
    expect(hasImmediateRemoteCancel(sender.channel)).toBe(false);
  });

  test("a send failure cannot prevent local cancellation cleanup", async () => {
    const receiver = endpoint(true);
    receiver.channel.send = () => {
      throw new Error("transport closed");
    };
    await expect(
      sendImmediateCancel(receiver.channel),
    ).resolves.toBeUndefined();
  });

  test("CANCEL drains before its caller is allowed to close the channel", async () => {
    const receiver = endpoint(true);
    Object.defineProperty(receiver.channel, "bufferedAmount", {
      configurable: true,
      value: 66,
    });
    let finished = false;
    const pending = sendImmediateCancel(receiver.channel).then(() => {
      finished = true;
    });
    await Promise.resolve();
    expect(receiver.sent).toHaveLength(1);
    expect(finished).toBe(false);
    Object.defineProperty(receiver.channel, "bufferedAmount", { value: 0 });
    await pending;
    expect(finished).toBe(true);
  });
});
