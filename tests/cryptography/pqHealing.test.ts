import { beforeAll, describe, expect, test } from "bun:test";

import {
  adoptPqHealing,
  clonePqHealing,
  decodePqHealingAck,
  encodePqHealingAck,
  getPqHealingRecordLengths,
  inspectPqHealingRecord,
  PqHealingError,
  PqHealingMachine,
  PQ_HEALING_ACK_BYTES,
  PQ_HEALING_BINDING_BYTES,
  PQ_HEALING_ROOT_BYTES,
  restorePqHealing,
  snapshotPqHealing,
  wipePqHealingSnapshot,
  type PqHealingAdvanceAcknowledgement,
  type PqHealingPhase,
} from "../../src/cryptography/pqHealing";
import {
  ML_KEM_512_SUITE,
  ML_KEM_768_SUITE,
  type MlKemBackend,
  type MlKemDecapsulation,
  type MlKemEncapsulation,
  type MlKemKeyPair,
} from "../../src/cryptography/mlkem";
import { loadTestModule } from "../../src/cryptography/testModule";

import type { LibCrypto } from "../../src/cryptography/libcrypto";

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const expectBytesDifferent = (
  actual: Uint8Array,
  expected: Uint8Array,
): void => {
  expect(Buffer.from(actual)).not.toEqual(Buffer.from(expected));
};

const makeDestroyable = <T extends { readonly sharedSecret: Uint8Array }>(
  value: Omit<T, "destroy" | "destroyed">,
): T & { readonly destroyed: boolean; destroy(): void } => {
  let destroyed = false;
  return {
    ...value,
    get destroyed(): boolean {
      return destroyed;
    },
    destroy(): void {
      if (destroyed) return;
      value.sharedSecret.fill(0);
      destroyed = true;
    },
  } as T & { readonly destroyed: boolean; destroy(): void };
};

class FakeMlKem512Backend implements MlKemBackend<512> {
  readonly suite = ML_KEM_512_SUITE;
  readonly generatedSecretKeys: Uint8Array[] = [];
  readonly encapsulatedSecrets: Uint8Array[] = [];
  readonly decapsulatedSecrets: Uint8Array[] = [];
  keyGenerationCount = 0;
  encapsulationCount = 0;
  decapsulationCount = 0;

  async generateKeyPair(): Promise<MlKemKeyPair> {
    await Promise.resolve();
    this.keyGenerationCount += 1;
    const marker = (0x30 + this.keyGenerationCount) & 0xff;
    const publicKey = new Uint8Array(this.suite.publicKeyBytes).fill(marker);
    const secretKey = new Uint8Array(this.suite.secretKeyBytes).fill(
      marker ^ 0xff,
    );
    this.generatedSecretKeys.push(secretKey);
    let destroyed = false;
    return {
      publicKey,
      secretKey,
      get destroyed(): boolean {
        return destroyed;
      },
      destroy(): void {
        if (destroyed) return;
        secretKey.fill(0);
        destroyed = true;
      },
    };
  }

  async encapsulate(publicKey: Uint8Array): Promise<MlKemEncapsulation> {
    await Promise.resolve();
    this.encapsulationCount += 1;
    const marker = publicKey[0];
    const ciphertext = new Uint8Array(this.suite.ciphertextBytes).fill(
      marker ^ 0xa5,
    );
    ciphertext[0] = marker;
    const sharedSecret = Uint8Array.from(
      { length: this.suite.sharedSecretBytes },
      (_, index) => (marker + index * 7) & 0xff,
    );
    this.encapsulatedSecrets.push(sharedSecret);
    return makeDestroyable<MlKemEncapsulation>({
      ciphertext,
      sharedSecret,
    });
  }

  async decapsulate(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Promise<MlKemDecapsulation> {
    await Promise.resolve();
    this.decapsulationCount += 1;
    const marker = secretKey[0] ^ 0xff;
    if (ciphertext[0] !== marker)
      throw new Error("fake ML-KEM ciphertext/key mismatch");
    const sharedSecret = Uint8Array.from(
      { length: this.suite.sharedSecretBytes },
      (_, index) => (marker + index * 7) & 0xff,
    );
    this.decapsulatedSecrets.push(sharedSecret);
    return makeDestroyable<MlKemDecapsulation>({ sharedSecret });
  }
}

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

const binding = (): Uint8Array =>
  new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x42);

const root = (): Uint8Array => new Uint8Array(PQ_HEALING_ROOT_BYTES).fill(0x19);

const makeMachine = (
  backend: FakeMlKem512Backend,
  nextOfferer: "local" | "remote",
  edgeBinding = binding(),
): PqHealingMachine<512> =>
  new PqHealingMachine({
    module,
    backend,
    suite: ML_KEM_512_SUITE,
    binding: edgeBinding,
    rootKey: root(),
    nextOfferer,
  });

const restoreMachine = (
  snapshot: unknown,
  backend: FakeMlKem512Backend,
  edgeBinding = binding(),
): PqHealingMachine<512> =>
  restorePqHealing(snapshot, {
    module,
    backend,
    suite: ML_KEM_512_SUITE,
    binding: edgeBinding,
  });

const expectSnapshotRoundTrip = (
  machine: PqHealingMachine<512>,
  backend: FakeMlKem512Backend,
  expectedPhase: PqHealingPhase,
): void => {
  const snapshot = snapshotPqHealing(machine);
  const restored = restoreMachine(snapshot, backend);
  const restoredSnapshot = snapshotPqHealing(restored);
  expect(restored.phase).toBe(expectedPhase);
  expect(restoredSnapshot).toEqual(snapshot);
  wipePqHealingSnapshot(restoredSnapshot);
  restored.destroy();
  wipePqHealingSnapshot(snapshot);
};

const completeExchange = async (
  offerer: PqHealingMachine<512>,
  responder: PqHealingMachine<512>,
): Promise<{
  readonly offer: Uint8Array;
  readonly advance: Uint8Array;
  readonly acknowledgement: PqHealingAdvanceAcknowledgement;
}> => {
  const offer = await offerer.prepareOffer();
  offerer.markOfferDispatched();
  responder.acceptAuthenticatedOffer(offer);

  const advance = await responder.prepareAdvance();
  const committedAdvance = responder.commitPreparedAdvance();
  expectBytesEqual(committedAdvance, advance);

  await offerer.acceptAuthenticatedAdvance(advance);
  const acknowledgement = offerer.commitAcceptedAdvance();
  offerer.markAdvanceAcknowledgementDispatched(acknowledgement);
  responder.acceptAuthenticatedAdvanceAcknowledgement(acknowledgement);
  return { offer, advance, acknowledgement };
};

const expectCode = async (
  action: () => unknown | Promise<unknown>,
  code: PqHealingError["code"],
): Promise<void> => {
  try {
    await action();
    throw new Error("expected PqHealingError");
  } catch (error) {
    expect(error).toBeInstanceOf(PqHealingError);
    expect((error as PqHealingError).code).toBe(code);
  }
};

describe("sparse PQ healing", () => {
  test("canonical full-record exchange commits matching roots and swaps turn", async () => {
    const offererBackend = new FakeMlKem512Backend();
    const responderBackend = new FakeMlKem512Backend();
    const offerer = makeMachine(offererBackend, "local");
    const responder = makeMachine(responderBackend, "remote");
    const lengths = getPqHealingRecordLengths(ML_KEM_512_SUITE);

    const offer = await offerer.prepareOffer();
    expect(offer).toHaveLength(lengths.offer);
    expect(offer[6]).toBe(2); // byte-matches room-policy ML-KEM-512
    const inspectedOffer = inspectPqHealingRecord(offer, ML_KEM_512_SUITE);
    expect(inspectedOffer.type).toBe("offer");
    expect(inspectedOffer.senderCounter).toBe(0n);
    expect(inspectedOffer.fromEpoch).toBe(0n);
    expect(inspectedOffer.toEpoch).toBe(1n);

    offerer.markOfferDispatched();
    responder.acceptAuthenticatedOffer(offer);
    const responderOldRoot = responder.copyRootKey();
    const advance = await responder.prepareAdvance();
    expect(advance).toHaveLength(lengths.advance);
    expectBytesEqual(responder.copyRootKey(), responderOldRoot);

    const inspectedAdvance = inspectPqHealingRecord(advance, ML_KEM_512_SUITE);
    expect(inspectedAdvance.type).toBe("advance");
    if (inspectedAdvance.type !== "advance")
      throw new Error("expected ADVANCE");
    expectBytesEqual(inspectedAdvance.offerBytes, offer);
    expect(inspectedAdvance.senderCounter).toBe(0n);

    responder.commitPreparedAdvance();
    expect(responder.phase).toBe("outbound-advance-awaiting-ack");
    expect(responder.trafficBlocked).toBe(true);
    expectBytesDifferent(responder.copyRootKey(), responderOldRoot);

    const offererOldRoot = offerer.copyRootKey();
    await offerer.acceptAuthenticatedAdvance(advance);
    expectBytesEqual(offerer.copyRootKey(), offererOldRoot);
    const acknowledgement = offerer.commitAcceptedAdvance();
    expect(offerer.phase).toBe("inbound-advance-awaiting-ack-dispatch");
    expect(acknowledgement).toEqual({
      epoch: 1n,
      advanceCounter: 0n,
    });
    expectBytesEqual(offerer.copyRootKey(), responder.copyRootKey());

    offerer.markAdvanceAcknowledgementDispatched(acknowledgement);
    responder.acceptAuthenticatedAdvanceAcknowledgement(acknowledgement);
    for (const machine of [offerer, responder]) {
      expect(machine.phase).toBe("idle");
      expect(machine.trafficBlocked).toBe(false);
      expect(machine.epoch).toBe(1n);
      expect(machine.localCounter).toBe(1n);
      expect(machine.remoteCounter).toBe(1n);
    }
    expect(offerer.nextOfferer).toBe("remote");
    expect(responder.nextOfferer).toBe("local");

    expect(
      responderBackend.encapsulatedSecrets.every((secret) =>
        secret.every((byte) => byte === 0),
      ),
    ).toBe(true);
    expect(
      offererBackend.decapsulatedSecrets.every((secret) =>
        secret.every((byte) => byte === 0),
      ),
    ).toBe(true);
    expect(
      offererBackend.generatedSecretKeys.every((secret) =>
        secret.every((byte) => byte === 0),
      ),
    ).toBe(true);
  });

  test("two exchanges ping-pong without negotiation or counter reset", async () => {
    const firstBackend = new FakeMlKem512Backend();
    const secondBackend = new FakeMlKem512Backend();
    const first = makeMachine(firstBackend, "local");
    const second = makeMachine(secondBackend, "remote");

    await completeExchange(first, second);
    await completeExchange(second, first);

    expect(first.epoch).toBe(2n);
    expect(second.epoch).toBe(2n);
    expect(first.localCounter).toBe(2n);
    expect(first.remoteCounter).toBe(2n);
    expect(second.localCounter).toBe(2n);
    expect(second.remoteCounter).toBe(2n);
    expect(first.nextOfferer).toBe("local");
    expect(second.nextOfferer).toBe("remote");
    expectBytesEqual(first.copyRootKey(), second.copyRootKey());
  });

  test("rejects room-suite mismatch before any KEM fallback", async () => {
    const backend = new FakeMlKem512Backend();
    await expectCode(
      () =>
        new PqHealingMachine({
          module,
          backend,
          suite: ML_KEM_768_SUITE as never,
          binding: binding(),
          rootKey: root(),
          nextOfferer: "local",
        }),
      "suite-mismatch",
    );
    expect(backend.keyGenerationCount).toBe(0);

    const offerer = makeMachine(new FakeMlKem512Backend(), "local");
    const offer = await offerer.prepareOffer();
    const wrongSuiteBackend = {
      ...backend,
      suite: ML_KEM_768_SUITE,
    } as unknown as MlKemBackend<768>;
    const wrongSuitePeer = new PqHealingMachine({
      module,
      backend: wrongSuiteBackend,
      suite: ML_KEM_768_SUITE,
      binding: binding(),
      rootKey: root(),
      nextOfferer: "remote",
    });
    await expectCode(
      () => wrongSuitePeer.acceptAuthenticatedOffer(offer),
      "suite-mismatch",
    );
    expect(backend.encapsulationCount).toBe(0);
  });

  test("rejects cross-edge records before encapsulation", async () => {
    const offerer = makeMachine(new FakeMlKem512Backend(), "local");
    const responderBackend = new FakeMlKem512Backend();
    const responder = makeMachine(
      responderBackend,
      "remote",
      new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x43),
    );
    const offer = await offerer.prepareOffer();

    await expectCode(
      () => responder.acceptAuthenticatedOffer(offer),
      "binding-mismatch",
    );
    expect(responderBackend.encapsulationCount).toBe(0);
  });

  test("classifies exact OFFER replays and same-slot forks", async () => {
    const offerer = makeMachine(new FakeMlKem512Backend(), "local");
    const responder = makeMachine(new FakeMlKem512Backend(), "remote");
    const offer = await offerer.prepareOffer();
    responder.acceptAuthenticatedOffer(offer);

    await expectCode(() => responder.acceptAuthenticatedOffer(offer), "replay");

    const fork = Uint8Array.from(offer);
    fork[fork.length - 1] ^= 1;
    await expectCode(() => responder.acceptAuthenticatedOffer(fork), "fork");
  });

  test("classifies exact ADVANCE replays and same-slot forks", async () => {
    const offerer = makeMachine(new FakeMlKem512Backend(), "local");
    const responder = makeMachine(new FakeMlKem512Backend(), "remote");
    const offer = await offerer.prepareOffer();
    offerer.markOfferDispatched();
    responder.acceptAuthenticatedOffer(offer);
    const advance = await responder.prepareAdvance();
    responder.commitPreparedAdvance();

    await offerer.acceptAuthenticatedAdvance(advance);
    await expectCode(
      () => offerer.acceptAuthenticatedAdvance(advance),
      "replay",
    );

    const fork = Uint8Array.from(advance);
    fork[fork.length - 1] ^= 1;
    await expectCode(() => offerer.acceptAuthenticatedAdvance(fork), "fork");
  });

  test("rejects future counter and epoch gaps", async () => {
    const source = makeMachine(new FakeMlKem512Backend(), "local");
    const counterPeer = makeMachine(new FakeMlKem512Backend(), "remote");
    const epochPeer = makeMachine(new FakeMlKem512Backend(), "remote");
    const offer = await source.prepareOffer();

    const counterGap = Uint8Array.from(offer);
    new DataView(
      counterGap.buffer,
      counterGap.byteOffset,
      counterGap.byteLength,
    ).setBigUint64(40, 1n, false);
    await expectCode(
      () => counterPeer.acceptAuthenticatedOffer(counterGap),
      "counter-gap",
    );

    const epochGap = Uint8Array.from(offer);
    const epochView = new DataView(
      epochGap.buffer,
      epochGap.byteOffset,
      epochGap.byteLength,
    );
    epochView.setBigUint64(48, 1n, false);
    epochView.setBigUint64(56, 2n, false);
    await expectCode(
      () => epochPeer.acceptAuthenticatedOffer(epochGap),
      "epoch-gap",
    );
  });

  test("aborting or destroying a pending OFFER wipes its ML-KEM secret", async () => {
    const abortBackend = new FakeMlKem512Backend();
    const abortMachine = makeMachine(abortBackend, "local");
    await abortMachine.prepareOffer();
    const abortSecret = abortBackend.generatedSecretKeys[0];
    expect(abortSecret.some((byte) => byte !== 0)).toBe(true);
    abortMachine.abortUnsentOffer();
    expect(abortSecret.every((byte) => byte === 0)).toBe(true);
    expect(abortMachine.phase).toBe("idle");

    const destroyBackend = new FakeMlKem512Backend();
    const destroyMachine = makeMachine(destroyBackend, "local");
    await destroyMachine.prepareOffer();
    const destroySecret = destroyBackend.generatedSecretKeys[0];
    destroyMachine.destroy();
    destroyMachine.destroy();
    expect(destroySecret.every((byte) => byte === 0)).toBe(true);
    expect(destroyMachine.phase).toBe("destroyed");
    expect(destroyMachine.trafficBlocked).toBe(true);
    await expectCode(() => destroyMachine.copyRootKey(), "destroyed");
  });

  test("acknowledgements reject noncanonical records and out-of-range counters", async () => {
    const offerer = makeMachine(new FakeMlKem512Backend(), "local");
    const responder = makeMachine(new FakeMlKem512Backend(), "remote");
    const offer = await offerer.prepareOffer();
    offerer.markOfferDispatched();
    responder.acceptAuthenticatedOffer(offer);
    await responder.prepareAdvance();
    responder.commitPreparedAdvance();

    await expectCode(
      () => responder.acceptAuthenticatedAdvanceAcknowledgement(null),
      "invalid-record",
    );
    await expectCode(
      () =>
        responder.acceptAuthenticatedAdvanceAcknowledgement({
          epoch: "1",
          advanceCounter: 0n,
        }),
      "invalid-record",
    );
    await expectCode(
      () =>
        responder.acceptAuthenticatedAdvanceAcknowledgement({
          epoch: 1n,
          advanceCounter: 0n,
          extra: true,
        }),
      "invalid-record",
    );
    await expectCode(
      () =>
        responder.acceptAuthenticatedAdvanceAcknowledgement({
          epoch: 1n << 64n,
          advanceCounter: 0n,
        }),
      "overflow",
    );
    await expectCode(
      () =>
        responder.acceptAuthenticatedAdvanceAcknowledgement({
          epoch: 1n,
          advanceCounter: -1n,
        }),
      "overflow",
    );
    await expectCode(
      () =>
        responder.acceptAuthenticatedAdvanceAcknowledgement(
          Object.defineProperties(
            {},
            {
              epoch: {
                enumerable: true,
                get: () => 1n,
              },
              advanceCounter: {
                enumerable: true,
                value: 0n,
              },
            },
          ),
        ),
      "invalid-record",
    );
    expect(responder.phase).toBe("outbound-advance-awaiting-ack");
  });

  test("ACK has one exact 64-byte suite/edge-bound encoding", async () => {
    const acknowledgement = {
      epoch: 0x0102_0304_0506_0708n,
      advanceCounter: 0x1112_1314_1516_1718n,
    };
    const encoded = encodePqHealingAck(
      acknowledgement,
      ML_KEM_512_SUITE,
      binding(),
    );
    expect(encoded).toHaveLength(PQ_HEALING_ACK_BYTES);
    expect(Buffer.from(encoded.subarray(0, 4)).toString("ascii")).toBe("P2QH");
    expect(encoded[4]).toBe(1);
    expect(encoded[5]).toBe(3);
    expect(encoded[6]).toBe(2);
    expect(encoded[7]).toBe(0);
    const view = new DataView(
      encoded.buffer,
      encoded.byteOffset,
      encoded.byteLength,
    );
    expect(view.getBigUint64(40, false)).toBe(acknowledgement.advanceCounter);
    expect(view.getBigUint64(48, false)).toBe(acknowledgement.epoch);
    expect(view.getBigUint64(56, false)).toBe(0n);
    expect(decodePqHealingAck(encoded, ML_KEM_512_SUITE, binding())).toEqual(
      acknowledgement,
    );

    await expectCode(
      () =>
        decodePqHealingAck(
          encoded.subarray(0, encoded.length - 1),
          ML_KEM_512_SUITE,
          binding(),
        ),
      "invalid-record",
    );
    await expectCode(
      () => decodePqHealingAck(encoded, ML_KEM_768_SUITE, binding()),
      "suite-mismatch",
    );
    await expectCode(
      () =>
        decodePqHealingAck(
          encoded,
          ML_KEM_512_SUITE,
          new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x43),
        ),
      "binding-mismatch",
    );
    for (const offset of [0, 4, 5, 7, 63]) {
      const corrupted = Uint8Array.from(encoded);
      corrupted[offset] ^= 1;
      await expectCode(
        () => decodePqHealingAck(corrupted, ML_KEM_512_SUITE, binding()),
        "invalid-record",
      );
    }
  });

  test("snapshot/restore preserves every phase and exact replay record", async () => {
    const offererBackend = new FakeMlKem512Backend();
    const responderBackend = new FakeMlKem512Backend();
    const offerer = makeMachine(offererBackend, "local");
    const responder = makeMachine(responderBackend, "remote");

    expectSnapshotRoundTrip(offerer, offererBackend, "idle");

    const offer = await offerer.prepareOffer();
    expectSnapshotRoundTrip(offerer, offererBackend, "outbound-offer-prepared");
    offerer.markOfferDispatched();
    expectSnapshotRoundTrip(
      offerer,
      offererBackend,
      "outbound-offer-dispatched",
    );

    responder.acceptAuthenticatedOffer(offer);
    expectSnapshotRoundTrip(responder, responderBackend, "inbound-offer");
    const advance = await responder.prepareAdvance();
    expectSnapshotRoundTrip(
      responder,
      responderBackend,
      "outbound-advance-prepared",
    );
    responder.commitPreparedAdvance();
    expectSnapshotRoundTrip(
      responder,
      responderBackend,
      "outbound-advance-awaiting-ack",
    );

    await offerer.acceptAuthenticatedAdvance(advance);
    expectSnapshotRoundTrip(
      offerer,
      offererBackend,
      "inbound-advance-prepared",
    );
    const acknowledgement = offerer.commitAcceptedAdvance();
    expectSnapshotRoundTrip(
      offerer,
      offererBackend,
      "inbound-advance-awaiting-ack-dispatch",
    );
    offerer.markAdvanceAcknowledgementDispatched(acknowledgement);
    responder.acceptAuthenticatedAdvanceAcknowledgement(acknowledgement);
    expectSnapshotRoundTrip(offerer, offererBackend, "idle");
    expectSnapshotRoundTrip(responder, responderBackend, "idle");
  });

  test("restored pending OFFER retains an independent usable ML-KEM secret", async () => {
    const offererBackend = new FakeMlKem512Backend();
    const offerer = makeMachine(offererBackend, "local");
    const offer = await offerer.prepareOffer();
    const snapshot = snapshotPqHealing(offerer);
    const snapshotPhase = snapshot.phase;
    if (
      snapshotPhase.kind !== "outbound-offer-prepared" &&
      snapshotPhase.kind !== "outbound-offer-dispatched"
    )
      throw new Error("expected pending OFFER snapshot");
    const savedSecret = Uint8Array.from(snapshotPhase.secretKey);
    const restored = restoreMachine(snapshot, offererBackend);
    wipePqHealingSnapshot(snapshot);
    offerer.destroy();

    restored.markOfferDispatched();
    const responder = makeMachine(new FakeMlKem512Backend(), "remote");
    responder.acceptAuthenticatedOffer(offer);
    const advance = await responder.prepareAdvance();
    await restored.acceptAuthenticatedAdvance(advance);
    expect(restored.phase).toBe("inbound-advance-prepared");
    expect(savedSecret.some((byte) => byte !== 0)).toBe(true);
    savedSecret.fill(0);
    restored.destroy();
    responder.destroy();
  });

  test("snapshot validation rejects extra fields, wrong provenance, and impossible phase state", async () => {
    const backend = new FakeMlKem512Backend();
    const machine = makeMachine(backend, "local");
    await machine.prepareOffer();
    const snapshot = snapshotPqHealing(machine);

    await expectCode(
      () => restoreMachine({ ...snapshot, extra: true }, backend),
      "invalid-record",
    );
    await expectCode(
      () => restoreMachine({ ...snapshot, parameterSet: 768 }, backend),
      "suite-mismatch",
    );
    await expectCode(
      () =>
        restoreMachine(
          snapshot,
          backend,
          new Uint8Array(PQ_HEALING_BINDING_BYTES).fill(0x43),
        ),
      "binding-mismatch",
    );
    await expectCode(
      () =>
        restoreMachine(
          { ...snapshot, localCounter: snapshot.localCounter + 1n },
          backend,
        ),
      "invalid-record",
    );

    const pendingPhase = snapshot.phase;
    if (
      pendingPhase.kind !== "outbound-offer-prepared" &&
      pendingPhase.kind !== "outbound-offer-dispatched"
    )
      throw new Error("expected outbound OFFER snapshot");
    await expectCode(
      () =>
        restoreMachine(
          {
            ...snapshot,
            phase: {
              ...pendingPhase,
              secretKey: pendingPhase.secretKey.subarray(1),
            },
          },
          backend,
        ),
      "invalid-record",
    );
    const corruptedOffer = Uint8Array.from(pendingPhase.offer);
    corruptedOffer[8] ^= 1;
    await expectCode(
      () =>
        restoreMachine(
          {
            ...snapshot,
            phase: { ...pendingPhase, offer: corruptedOffer },
          },
          backend,
        ),
      "binding-mismatch",
    );
    wipePqHealingSnapshot(snapshot);
    machine.destroy();
  });

  test("clone/adopt consumes the successor and wipe clears snapshot secrets without aliasing live state", async () => {
    const backend = new FakeMlKem512Backend();
    const live = makeMachine(backend, "local");
    const candidate = clonePqHealing(live);
    const offer = await candidate.prepareOffer();
    adoptPqHealing(live, candidate);
    expect(candidate.phase).toBe("destroyed");
    expect(live.phase).toBe("outbound-offer-prepared");
    expectBytesEqual(live.copyPendingOutboundRecord(), offer);

    const snapshot = snapshotPqHealing(live);
    const liveRoot = live.copyRootKey();
    wipePqHealingSnapshot(snapshot);
    expect(snapshot.rootKey.every((byte) => byte === 0)).toBe(true);
    expect(snapshot.binding.every((byte) => byte === 0)).toBe(true);
    if (
      snapshot.phase.kind !== "outbound-offer-prepared" &&
      snapshot.phase.kind !== "outbound-offer-dispatched"
    )
      throw new Error("expected outbound OFFER snapshot");
    expect(snapshot.phase.secretKey.every((byte) => byte === 0)).toBe(true);
    expectBytesEqual(live.copyRootKey(), liveRoot);

    live.destroy();
    expect(
      backend.generatedSecretKeys.every((secret) =>
        secret.every((byte) => byte === 0),
      ),
    ).toBe(true);
  });

  test("u64 exhaustion fails closed before key generation", async () => {
    const backend = new FakeMlKem512Backend();
    const machine = new PqHealingMachine({
      module,
      backend,
      suite: ML_KEM_512_SUITE,
      binding: binding(),
      rootKey: root(),
      nextOfferer: "local",
      epoch: (1n << 64n) - 1n,
    });
    await expectCode(() => machine.prepareOffer(), "overflow");
    expect(backend.keyGenerationCount).toBe(0);
  });
});
