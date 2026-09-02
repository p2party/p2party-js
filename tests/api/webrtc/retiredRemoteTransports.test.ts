import { afterEach, describe, expect, test } from "bun:test";

import {
  MAX_RETIRED_REMOTE_TRANSPORTS_PER_EDGE,
  RETIRED_REMOTE_TRANSPORT_TTL_MS,
  forgetRetiredRemoteTransport,
  forgetRetiredRemoteTransports,
  isRetiredRemoteTransport,
  retireRemoteTransport,
} from "../../../src/api/webrtc/retiredRemoteTransports";

const ROOM_ID = "00000000-0000-4000-8000-0000000000aa";
const OTHER_ROOM_ID = "00000000-0000-4000-8000-0000000000bb";
const PEER_ID = "00000000-0000-4000-8000-000000000002";
const OTHER_PEER_ID = "00000000-0000-4000-8000-000000000003";

const fingerprintSdp = (hexByte: string): string =>
  "v=0\r\n" +
  `a=fingerprint:sha-256 ${Array<string>(32).fill(hexByte).join(":")}\r\n` +
  "a=setup:actpass\r\n";

const fingerprintBytes = (byte: number): Uint8Array =>
  new Uint8Array(32).fill(byte);

afterEach(() => {
  forgetRetiredRemoteTransports(ROOM_ID, PEER_ID);
  forgetRetiredRemoteTransports(ROOM_ID, OTHER_PEER_ID);
  forgetRetiredRemoteTransports(OTHER_ROOM_ID, PEER_ID);
});

describe("retiredRemoteTransports", () => {
  test("an SDP retired for an edge is recognized, another fingerprint is not", () => {
    expect(retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"))).toBe(
      true,
    );

    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(true);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb")),
    ).toBe(false);
  });

  test("raw fingerprint bytes retire the same transport as its SDP", () => {
    expect(
      retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintBytes(0xaa)),
    ).toBe(true);

    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(true);
  });

  test("an SDP without a usable sha-256 fingerprint retires and matches nothing", () => {
    expect(retireRemoteTransport(ROOM_ID, PEER_ID, "v=0\r\n")).toBe(false);
    expect(retireRemoteTransport(ROOM_ID, PEER_ID, undefined)).toBe(false);
    expect(isRetiredRemoteTransport(ROOM_ID, PEER_ID, "v=0\r\n")).toBe(false);
    expect(isRetiredRemoteTransport(ROOM_ID, PEER_ID, undefined)).toBe(false);
  });

  test("the per-edge cap evicts the oldest retired fingerprint", () => {
    expect(MAX_RETIRED_REMOTE_TRANSPORTS_PER_EDGE).toBe(4);
    const bytes = ["a1", "a2", "a3", "a4"];
    for (const byte of bytes)
      retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp(byte));
    for (const byte of bytes)
      expect(
        isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp(byte)),
      ).toBe(true);

    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("a5"));

    // The oldest entry is gone; every later one, and the new one, remain.
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("a1")),
    ).toBe(false);
    for (const byte of ["a2", "a3", "a4", "a5"])
      expect(
        isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp(byte)),
      ).toBe(true);
  });

  test("re-retiring a fingerprint refreshes it without consuming a slot", () => {
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("a1"), 0);
    for (const byte of ["a2", "a3", "a4"])
      retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp(byte), 0);
    // Re-retiring the oldest makes it the newest, so the NEXT entry evicts a2.
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("a1"), 1);
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("a5"), 2);

    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("a2"), 2),
    ).toBe(false);
    for (const byte of ["a1", "a3", "a4", "a5"])
      expect(
        isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp(byte), 2),
      ).toBe(true);
  });

  test("a retired fingerprint expires after its TTL", () => {
    expect(RETIRED_REMOTE_TRANSPORT_TTL_MS).toBe(120_000);
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"), 1_000);

    expect(
      isRetiredRemoteTransport(
        ROOM_ID,
        PEER_ID,
        fingerprintSdp("aa"),
        1_000 + RETIRED_REMOTE_TRANSPORT_TTL_MS - 1,
      ),
    ).toBe(true);
    expect(
      isRetiredRemoteTransport(
        ROOM_ID,
        PEER_ID,
        fingerprintSdp("aa"),
        1_000 + RETIRED_REMOTE_TRANSPORT_TTL_MS,
      ),
    ).toBe(false);
    // Expiry is permanent: the entry was pruned, not merely hidden.
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"), 1_000),
    ).toBe(false);
  });

  test("retirement is per (roomId, peerId) edge", () => {
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"));

    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(true);
    expect(
      isRetiredRemoteTransport(ROOM_ID, OTHER_PEER_ID, fingerprintSdp("aa")),
    ).toBe(false);
    expect(
      isRetiredRemoteTransport(OTHER_ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(false);
  });

  test("edge keys of different room/peer splits do not collide", () => {
    // "ab" + "c" and "a" + "bc" must be different edges.
    retireRemoteTransport("ab", "c", fingerprintSdp("aa"));

    expect(isRetiredRemoteTransport("ab", "c", fingerprintSdp("aa"))).toBe(
      true,
    );
    expect(isRetiredRemoteTransport("a", "bc", fingerprintSdp("aa"))).toBe(
      false,
    );

    forgetRetiredRemoteTransports("ab", "c");
  });

  test("forgetting one transport leaves the edge's other retirements alone", () => {
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"));
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb"));

    forgetRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"));

    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(false);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb")),
    ).toBe(true);
    // Forgetting an unknown or unparsable transport is a no-op.
    forgetRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("cc"));
    forgetRetiredRemoteTransport(ROOM_ID, PEER_ID, "v=0\r\n");
    forgetRetiredRemoteTransport(OTHER_ROOM_ID, PEER_ID, fingerprintSdp("bb"));
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb")),
    ).toBe(true);
  });

  test("forgetting an edge drops every fingerprint retired for it", () => {
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa"));
    retireRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb"));
    retireRemoteTransport(ROOM_ID, OTHER_PEER_ID, fingerprintSdp("aa"));

    forgetRetiredRemoteTransports(ROOM_ID, PEER_ID);

    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("aa")),
    ).toBe(false);
    expect(
      isRetiredRemoteTransport(ROOM_ID, PEER_ID, fingerprintSdp("bb")),
    ).toBe(false);
    // The peer's other edge is untouched.
    expect(
      isRetiredRemoteTransport(ROOM_ID, OTHER_PEER_ID, fingerprintSdp("aa")),
    ).toBe(true);
  });
});
