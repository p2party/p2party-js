import { beforeAll, describe, expect, test } from "bun:test";

import {
  getPqHealingRecordLengths,
  inspectPqHealingRecord,
  PqHealingError,
  PqHealingMachine,
  PQ_HEALING_BINDING_BYTES,
  PQ_HEALING_ROOT_BYTES,
  type PqHealingAdvanceAcknowledgement,
} from "./pqHealing";
import {
  ML_KEM_512_SUITE,
  ML_KEM_768_SUITE,
  type MlKemBackend,
  type MlKemDecapsulation,
  type MlKemEncapsulation,
  type MlKemKeyPair,
} from "./mlkem";
import { loadTestModule } from "./testModule";

import type { LibCrypto } from "./libcrypto";

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
