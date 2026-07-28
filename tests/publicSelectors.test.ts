import { describe, expect, test } from "bun:test";

import type { KeyPair, Room, SignalingState, State } from "../src/index";

type PublicSdk = typeof import("../src/index").default;

/**
 * Compile-time external-consumer regression: every exported selector accepts
 * the exported State projection, including its intentionally non-normalized
 * public Room[] surface.
 */
const readPublicSelectors = (sdk: PublicSdk, state: State): void => {
  const rooms: Room[] = sdk.roomSelector(state);
  const keyPair: KeyPair = sdk.keyPairSelector(state);
  const signalingServer: SignalingState = sdk.signalingServerSelector(state);
  const currentRoomUrl: string = sdk.commonStateSelector(state).currentRoomUrl;
  void rooms;
  void keyPair;
  void signalingServer;
  void currentRoomUrl;
};

describe("public selector types", () => {
  test("keep the external-consumer regression in the typechecked suite", () => {
    expect(readPublicSelectors).toBeFunction();
  });
});
