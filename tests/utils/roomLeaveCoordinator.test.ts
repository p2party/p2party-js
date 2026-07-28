import { describe, expect, test } from "bun:test";

import {
  acknowledgeRoomLeft,
  buildRoomLeaveRequest,
  cancelRoomLeavesForSocket,
  parseRoomLeftAcknowledgement,
  pendingRoomLeaveCount,
  RemoteRoomRevocationUnconfirmedError,
  requestRoomLeaveAcknowledgement,
} from "../../src/utils/roomLeaveCoordinator";
import { SignalingIngressQueue } from "../../src/utils/signalingIngressQueue";

const PEER_ID = "00000000-0000-4000-8000-000000000001";
const ROOM_URL = "ab".repeat(32);
const OTHER_ROOM_URL = "cd".repeat(32);
const LEAVE_ID = "00000000-0000-4000-8000-000000000004";
const OTHER_LEAVE_ID = "00000000-0000-4000-8000-000000000005";

const ack = (roomUrl = ROOM_URL, roomLeaveId = LEAVE_ID) =>
  ({
    type: "roomLeft",
    protocolVersion: 4,
    roomUrl,
    roomLeaveId,
  }) as const;

describe("correlated room leave acknowledgement", () => {
  test("uses the stable room capability before any server room id exists", async () => {
    const socket = {};
    const request = buildRoomLeaveRequest(PEER_ID, ROOM_URL, LEAVE_ID);
    expect(request).toEqual({
      type: "leaveRoom",
      protocolVersion: 4,
      fromPeerId: PEER_ID,
      roomUrl: ROOM_URL,
      roomLeaveId: LEAVE_ID,
    });

    const leaving = requestRoomLeaveAcknowledgement(
      PEER_ID,
      ROOM_URL,
      socket,
      (sent) => {
        expect(sent).toEqual(request);
        expect(acknowledgeRoomLeft(ack(), socket)).toBe(true);
      },
      { roomLeaveId: LEAVE_ID, timeoutMs: 50 },
    );
    await leaving;
    expect(pendingRoomLeaveCount()).toBe(0);
  });

  test("requires the exact socket, room, and nonce and settles only once", async () => {
    const socket = {};
    const replacementSocket = {};
    const leaving = requestRoomLeaveAcknowledgement(
      PEER_ID,
      ROOM_URL,
      socket,
      () => undefined,
      { roomLeaveId: LEAVE_ID, timeoutMs: 100 },
    );

    expect(acknowledgeRoomLeft(ack(), replacementSocket)).toBe(false);
    expect(acknowledgeRoomLeft(ack(OTHER_ROOM_URL, LEAVE_ID), socket)).toBe(
      false,
    );
    expect(acknowledgeRoomLeft(ack(ROOM_URL, OTHER_LEAVE_ID), socket)).toBe(
      false,
    );
    expect(acknowledgeRoomLeft(ack(), socket)).toBe(true);
    expect(acknowledgeRoomLeft(ack(), socket)).toBe(false);
    await leaving;
    expect(pendingRoomLeaveCount()).toBe(0);
  });

  test("socket cancellation rejects promptly and a late ack has no effect", async () => {
    const socket = {};
    const leaving = requestRoomLeaveAcknowledgement(
      PEER_ID,
      ROOM_URL,
      socket,
      () => undefined,
      { roomLeaveId: LEAVE_ID, timeoutMs: 1_000 },
    );

    expect(cancelRoomLeavesForSocket(socket, "socket-replaced")).toBe(1);
    await expect(leaving).rejects.toMatchObject({
      name: "RemoteRoomRevocationUnconfirmedError",
      reason: "socket-replaced",
      roomUrl: ROOM_URL,
      roomLeaveId: LEAVE_ID,
    });
    expect(acknowledgeRoomLeft(ack(), socket)).toBe(false);
    expect(pendingRoomLeaveCount()).toBe(0);
  });

  test("a missing acknowledgement reports explicit unconfirmed revocation", async () => {
    const socket = {};
    const leaving = requestRoomLeaveAcknowledgement(
      PEER_ID,
      ROOM_URL,
      socket,
      () => undefined,
      { roomLeaveId: LEAVE_ID, timeoutMs: 5 },
    );

    await expect(leaving).rejects.toBeInstanceOf(
      RemoteRoomRevocationUnconfirmedError,
    );
    await expect(
      requestRoomLeaveAcknowledgement(
        PEER_ID,
        ROOM_URL,
        socket,
        () => {
          throw new Error("send failed");
        },
        { roomLeaveId: OTHER_LEAVE_ID, timeoutMs: 100 },
      ),
    ).rejects.toMatchObject({ reason: "send-failed" });
    expect(pendingRoomLeaveCount()).toBe(0);
  });

  test("malformed or extended acknowledgements fail closed", async () => {
    const socket = {};
    expect(() =>
      buildRoomLeaveRequest(PEER_ID, ROOM_URL.toUpperCase(), LEAVE_ID),
    ).toThrow("roomUrl must be 32-byte lowercase hex");
    const leaving = requestRoomLeaveAcknowledgement(
      PEER_ID,
      ROOM_URL,
      socket,
      () => undefined,
      { roomLeaveId: LEAVE_ID, timeoutMs: 100 },
    );

    expect(
      acknowledgeRoomLeft({ ...ack(), protocolVersion: 3 } as never, socket),
    ).toBe(false);
    expect(
      acknowledgeRoomLeft({ ...ack(), extra: true } as never, socket),
    ).toBe(false);
    expect(
      acknowledgeRoomLeft(
        { ...ack(), roomUrl: ROOM_URL.toUpperCase() },
        socket,
      ),
    ).toBe(false);
    expect(acknowledgeRoomLeft(ack(), socket)).toBe(true);
    await leaving;
  });

  test("the exact ack fast path settles while an earlier protocol frame is deferred", async () => {
    let releaseProtocol!: () => void;
    let protocolStarted!: () => void;
    const protocolGate = new Promise<void>((resolve) => {
      releaseProtocol = resolve;
    });
    const started = new Promise<void>((resolve) => {
      protocolStarted = resolve;
    });
    const queue = new SignalingIngressQueue({
      onOverflow: () => undefined,
    });
    queue.enqueue(async () => {
      protocolStarted();
      await protocolGate;
    });

    const socket = {};
    const leaving = requestRoomLeaveAcknowledgement(
      PEER_ID,
      ROOM_URL,
      socket,
      () => undefined,
      { roomLeaveId: LEAVE_ID, timeoutMs: 100 },
    );
    await started;
    const parsed = parseRoomLeftAcknowledgement(JSON.stringify(ack()));
    expect(parsed).not.toBeNull();
    expect(acknowledgeRoomLeft(parsed!, socket)).toBe(true);
    await leaving;

    releaseProtocol();
    await Bun.sleep(0);
  });
});
