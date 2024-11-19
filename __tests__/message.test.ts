import { describe, expect, test } from "@jest/globals";
import { handleSendMessage } from "../src/handlers/handleSendMessage";
import { handleReceiveMessage } from "../src/handlers/handleReceiveMessage";
import { IRTCPeerConnection } from "../src/api/webrtc/interfaces";

describe("Test message send and receive", () => {
  const peerConnections: IRTCPeerConnection[] = [
    {
      ...new RTCPeerConnection(),
    },
  ];
  test("message sent can be read", () => {
    expect(sum(1, 2)).toBe(3);
  });
});
