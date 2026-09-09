import { describe, expect, test } from "bun:test";

import { repairIceTransportAfterCandidateFailure } from "../../../src/api/webrtc/iceRepair";

const target = (
  connectionState: RTCPeerConnectionState,
  restartIce: () => void,
  ensureFreshIceConfiguration?: () => Promise<boolean | void>,
): Pick<
  RTCPeerConnection,
  "connectionState" | "signalingState" | "restartIce"
> & { ensureFreshIceConfiguration?: () => Promise<boolean | void> } => ({
  connectionState,
  signalingState: "stable",
  restartIce,
  ensureFreshIceConfiguration,
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

  test("applies fresh room configuration before restart", async () => {
    const events: string[] = [];
    const result = await repairIceTransportAfterCandidateFailure(
      target(
        "connected",
        () => {
          events.push("restart");
        },
        async () => {
          events.push("configure");
        },
      ),
      () => {
        events.push("disconnect");
      },
    );

    expect(result).toBe("restarted");
    expect(events).toEqual(["configure", "restart"]);
  });

  test("does not restart twice when credential rotation already restarted the room", async () => {
    const events: string[] = [];
    const result = await repairIceTransportAfterCandidateFailure(
      target(
        "connected",
        () => {
          events.push("duplicate-restart");
        },
        async () => {
          events.push("configure-and-restart");
          return true;
        },
      ),
      () => {
        events.push("disconnect");
      },
    );

    expect(result).toBe("restarted");
    expect(events).toEqual(["configure-and-restart"]);
  });

  test("a failed proof/configuration gate never restarts ICE", async () => {
    let restarts = 0;
    let disconnects = 0;
    const repair = repairIceTransportAfterCandidateFailure(
      target(
        "connected",
        () => {
          restarts++;
        },
        () => Promise.reject(new Error("proof failed")),
      ),
      () => {
        disconnects++;
      },
    );

    await expect(repair).rejects.toThrow("proof failed");
    expect(restarts).toBe(0);
    expect(disconnects).toBe(0);
  });
});
