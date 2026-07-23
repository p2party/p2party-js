import { describe, expect, test } from "bun:test";

import { repairIceTransportAfterCandidateFailure } from "./iceRepair";

const target = (
  connectionState: RTCPeerConnectionState,
  restartIce: () => void,
): Pick<
  RTCPeerConnection,
  "connectionState" | "signalingState" | "restartIce"
> => ({
  connectionState,
  signalingState: "stable",
  restartIce,
});

describe("ICE candidate failure repair", () => {
  test("restarts an active PC without invoking disconnect", async () => {
    let restarts = 0;
    let disconnects = 0;

    const result = await repairIceTransportAfterCandidateFailure(
      target("connected", () => {
        restarts++;
      }),
      () => {
        disconnects++;
      },
    );

    expect(result).toBe("restarted");
    expect(restarts).toBe(1);
    expect(disconnects).toBe(0);
  });

  test("disconnects a closed PC without trying to restart it", async () => {
    let restarts = 0;
    let disconnects = 0;

    const result = await repairIceTransportAfterCandidateFailure(
      target("closed", () => {
        restarts++;
      }),
      () => {
        disconnects++;
      },
    );

    expect(result).toBe("disconnected");
    expect(restarts).toBe(0);
    expect(disconnects).toBe(1);
  });

  test("a concurrent-close restart failure falls back to disconnect once", async () => {
    let restarts = 0;
    let disconnects = 0;

    const result = await repairIceTransportAfterCandidateFailure(
      target("connected", () => {
        restarts++;
        throw new Error("PC closed");
      }),
      () => {
        disconnects++;
      },
    );

    expect(result).toBe("disconnected");
    expect(restarts).toBe(1);
    expect(disconnects).toBe(1);
  });
});
