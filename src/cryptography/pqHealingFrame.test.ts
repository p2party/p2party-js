import { beforeAll, describe, expect, test } from "bun:test";

import {
  encodePqHealingAck,
  PqHealingMachine,
  PQ_HEALING_BINDING_BYTES,
  PQ_HEALING_ROOT_BYTES,
} from "./pqHealing";
import {
  openPqControlFrame,
  PqControlFrameError,
  PQ_CONTROL_FRAME_HEADER_BYTES,
  PQ_CONTROL_FRAME_PLAINTEXT_BYTES,
  sealPqControlFrame,
} from "./pqHealingFrame";
import {
  createMlKemBackend,
  ML_KEM_512_SUITE,
  ML_KEM_768_SUITE,
} from "./mlkem";
import {
  FRAME_TYPE_PQ_CONTROL,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";
import { loadTestModule } from "./testModule";

import type { LibCrypto } from "./libcrypto";

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const expectFrameCode = (
  action: () => unknown,
  code: PqControlFrameError["code"],
): void => {
  try {
    action();
    throw new Error("expected PqControlFrameError");
  } catch (error) {
    expect(error).toBeInstanceOf(PqControlFrameError);
    expect((error as PqControlFrameError).code).toBe(code);
  }
};

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

const binding = (): Uint8Array =>
  new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x42);
const root = (): Uint8Array => new Uint8Array(PQ_HEALING_ROOT_BYTES).fill(0x19);

describe("protocol-v4 PQ control frames", () => {
  test("OFFER, ADVANCE, and ACK round-trip as indistinguishable fixed-size cells", async () => {
    const offerer = new PqHealingMachine({
      module,
      backend: createMlKemBackend(module, ML_KEM_512_SUITE),
      suite: ML_KEM_512_SUITE,
      binding: binding(),
      rootKey: root(),
      nextOfferer: "local",
    });
    const responder = new PqHealingMachine({
      module,
      backend: createMlKemBackend(module, ML_KEM_512_SUITE),
      suite: ML_KEM_512_SUITE,
      binding: binding(),
      rootKey: root(),
      nextOfferer: "remote",
    });

    const epochZeroRoot = offerer.copyRootKey();
    const offer = await offerer.prepareOffer();
    const offerFrame = sealPqControlFrame({
      module,
      suite: ML_KEM_512_SUITE,
      rootKey: epochZeroRoot,
      binding: binding(),
      direction: "initiator-to-responder",
      keyEpoch: 0n,
      record: offer,
    });
    offerer.markOfferDispatched();
    responder.acceptAuthenticatedOffer(offer);

    const advance = await responder.prepareAdvance();
    const advanceFrame = sealPqControlFrame({
      module,
      suite: ML_KEM_512_SUITE,
      rootKey: epochZeroRoot,
      binding: binding(),
      direction: "responder-to-initiator",
      keyEpoch: 0n,
      record: advance,
    });
    responder.commitPreparedAdvance();

    await offerer.acceptAuthenticatedAdvance(advance);
    const acknowledgement = offerer.commitAcceptedAdvance();
    const epochOneRoot = offerer.copyRootKey();
    const ack = encodePqHealingAck(
      acknowledgement,
      ML_KEM_512_SUITE,
      binding(),
    );
    const ackFrame = sealPqControlFrame({
      module,
      suite: ML_KEM_512_SUITE,
      rootKey: epochOneRoot,
      binding: binding(),
      direction: "initiator-to-responder",
      keyEpoch: 1n,
      record: ack,
    });

    expect(PQ_CONTROL_FRAME_HEADER_BYTES).toBe(69);
    expect(PQ_CONTROL_FRAME_PLAINTEXT_BYTES).toBe(65_405);
    for (const frame of [offerFrame, advanceFrame, ackFrame]) {
      expect(frame).toHaveLength(WIRE_CHUNK_FRAME_LEN);
      expect(frame[0]).toBe(FRAME_TYPE_PQ_CONTROL);
    }
    expect(offerFrame.length).toBe(advanceFrame.length);
    expect(advanceFrame.length).toBe(ackFrame.length);

    expectBytesEqual(
      openPqControlFrame({
        module,
        suite: ML_KEM_512_SUITE,
        rootKey: epochZeroRoot,
        binding: binding(),
        direction: "initiator-to-responder",
        keyEpoch: 0n,
        frame: offerFrame,
      }),
      offer,
    );
    expectBytesEqual(
      openPqControlFrame({
        module,
        suite: ML_KEM_512_SUITE,
        rootKey: epochZeroRoot,
        binding: binding(),
        direction: "responder-to-initiator",
        keyEpoch: 0n,
        frame: advanceFrame,
      }),
      advance,
    );
    expectBytesEqual(
      openPqControlFrame({
        module,
        suite: ML_KEM_512_SUITE,
        rootKey: epochOneRoot,
        binding: binding(),
        direction: "initiator-to-responder",
        keyEpoch: 1n,
        frame: ackFrame,
      }),
      ack,
    );

    epochZeroRoot.fill(0);
    epochOneRoot.fill(0);
    offerer.destroy();
    responder.destroy();
  });

  test("rejects wrong direction/root and every tampered public-header or ciphertext class", async () => {
    const machine = new PqHealingMachine({
      module,
      backend: createMlKemBackend(module, ML_KEM_512_SUITE),
      suite: ML_KEM_512_SUITE,
      binding: binding(),
      rootKey: root(),
      nextOfferer: "local",
    });
    const offer = await machine.prepareOffer();
    const epochRoot = machine.copyRootKey();
    const frame = sealPqControlFrame({
      module,
      suite: ML_KEM_512_SUITE,
      rootKey: epochRoot,
      binding: binding(),
      direction: "initiator-to-responder",
      keyEpoch: 0n,
      record: offer,
    });
    const open = (
      candidate: Uint8Array,
      overrides: Partial<{
        rootKey: Uint8Array;
        binding: Uint8Array;
        direction: "initiator-to-responder" | "responder-to-initiator";
        keyEpoch: bigint;
      }> = {},
    ): Uint8Array =>
      openPqControlFrame({
        module,
        suite: ML_KEM_512_SUITE,
        rootKey: overrides.rootKey ?? epochRoot,
        binding: overrides.binding ?? binding(),
        direction: overrides.direction ?? "initiator-to-responder",
        keyEpoch: overrides.keyEpoch ?? 0n,
        frame: candidate,
      });

    expectFrameCode(
      () => open(frame, { direction: "responder-to-initiator" }),
      "authentication-failed",
    );
    expectFrameCode(
      () => open(frame, { rootKey: new Uint8Array(32).fill(0x20) }),
      "authentication-failed",
    );
    expectFrameCode(() => open(frame, { keyEpoch: 1n }), "epoch-mismatch");
    expectFrameCode(
      () =>
        open(frame, {
          binding: new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x43),
        }),
      "binding-mismatch",
    );
    expectFrameCode(
      () => open(frame.subarray(0, frame.length - 1)),
      "invalid-frame",
    );

    const badType = Uint8Array.from(frame);
    badType[0] ^= 1;
    expectFrameCode(() => open(badType), "invalid-frame");

    const badBinding = Uint8Array.from(frame);
    badBinding[1] ^= 1;
    expectFrameCode(() => open(badBinding), "binding-mismatch");

    const badReserved = Uint8Array.from(frame);
    badReserved[48] ^= 1;
    expectFrameCode(() => open(badReserved), "invalid-frame");

    for (const offset of [
      40,
      68,
      PQ_CONTROL_FRAME_HEADER_BYTES,
      frame.length - 1,
    ]) {
      const tampered = Uint8Array.from(frame);
      tampered[offset] ^= 1;
      expectFrameCode(() => open(tampered), "authentication-failed");
    }

    expectFrameCode(
      () =>
        openPqControlFrame({
          module,
          suite: ML_KEM_768_SUITE,
          rootKey: epochRoot,
          binding: binding(),
          direction: "initiator-to-responder",
          keyEpoch: 0n,
          frame,
        }),
      "authentication-failed",
    );

    epochRoot.fill(0);
    machine.destroy();
  });

  test("seal rejects cross-edge records, wrong record epochs, and invalid directions", async () => {
    const machine = new PqHealingMachine({
      module,
      backend: createMlKemBackend(module, ML_KEM_512_SUITE),
      suite: ML_KEM_512_SUITE,
      binding: binding(),
      rootKey: root(),
      nextOfferer: "local",
    });
    const offer = await machine.prepareOffer();
    const common = {
      module,
      suite: ML_KEM_512_SUITE,
      rootKey: machine.copyRootKey(),
      binding: binding(),
      direction: "initiator-to-responder" as const,
      keyEpoch: 0n,
      record: offer,
    };

    expectFrameCode(
      () => sealPqControlFrame({ ...common, keyEpoch: 1n }),
      "epoch-mismatch",
    );
    expectFrameCode(
      () =>
        sealPqControlFrame({
          ...common,
          binding: new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x43),
        }),
      "binding-mismatch",
    );
    expectFrameCode(
      () =>
        sealPqControlFrame({
          ...common,
          direction: "sideways" as never,
        }),
      "invalid-direction",
    );

    common.rootKey.fill(0);
    machine.destroy();
  });
});
