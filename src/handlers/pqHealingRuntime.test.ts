import { beforeAll, describe, expect, test } from "bun:test";

import {
  PQ_HEAL_AFTER_MESSAGES,
  PQ_HEAL_AFTER_MS,
  PQ_HEAL_MAX_RETRIES,
  PQ_HEAL_RETRY_MS,
  SparsePqHealingState,
} from "./pqHealingRuntime";
import { getPqHealingRecordLengths } from "../cryptography/pqHealing";
import { ML_KEM_512_SUITE } from "../cryptography/mlkem";
import { loadTestModule } from "../cryptography/testModule";
import { roomPqModeToRootSuite, type RoomPqMode } from "../roomPolicy";
import { WIRE_CHUNK_FRAME_LEN } from "../utils/constants";

import type { LibCrypto } from "../cryptography/libcrypto";

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

const BINDING_FILL = 0x42;
const ROOT_FILL = 0x19;
const T0 = 1_000;

const binding = (fill = BINDING_FILL): Uint8Array =>
  new Uint8Array(32).fill(fill);

const root = (): Uint8Array => new Uint8Array(32).fill(ROOT_FILL);

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const makeState = (
  amInitiator: boolean,
  pqMode: RoomPqMode = "hybrid-mlkem512",
  edgeBinding = binding(),
): SparsePqHealingState =>
  new SparsePqHealingState({
    module,
    pqMode,
    rootSuite: roomPqModeToRootSuite(pqMode),
    binding: edgeBinding,
    rootKey: root(),
    nextOfferer: amInitiator ? "local" : "remote",
    amInitiator,
    now: T0,
  });

const makeEdge = (
  pqMode: RoomPqMode = "hybrid-mlkem512",
): {
  readonly initiator: SparsePqHealingState;
  readonly responder: SparsePqHealingState;
} => ({
  initiator: makeState(true, pqMode),
  responder: makeState(false, pqMode),
});

const restoreState = (
  bytes: Uint8Array,
  amInitiator: boolean,
  pqMode: RoomPqMode = "hybrid-mlkem512",
  edgeBinding = binding(),
): SparsePqHealingState =>
  SparsePqHealingState.restore(bytes, {
    module,
    pqMode,
    rootSuite: roomPqModeToRootSuite(pqMode),
    binding: edgeBinding,
    amInitiator,
  });

const makeDue = (state: SparsePqHealingState): void => {
  for (let index = 0; index < PQ_HEAL_AFTER_MESSAGES; index += 1)
    state.noteApplicationMessage();
};

interface ExchangeFrames {
  readonly offer: Uint8Array;
  readonly advance: Uint8Array;
  readonly ack: Uint8Array;
}

const runExchange = async (
  offerer: SparsePqHealingState,
  accepter: SparsePqHealingState,
  now: number,
): Promise<ExchangeFrames> => {
  makeDue(offerer);
  expect(offerer.healingDue(now)).toBe(true);
  const offer = await offerer.prepareHealingOffer(now);
  offerer.markPendingDispatched(now);

  const advanced = await accepter.acceptControlFrame(offer, now);
  expect(advanced.changed).toBe(true);
  if (advanced.dispatch === null) throw new Error("expected ADVANCE dispatch");
  accepter.markPendingDispatched(now);

  const acknowledged = await offerer.acceptControlFrame(advanced.dispatch, now);
  expect(acknowledged.changed).toBe(true);
  if (acknowledged.dispatch === null) throw new Error("expected ACK dispatch");

  const settled = await accepter.acceptControlFrame(acknowledged.dispatch, now);
  expect(settled.changed).toBe(true);
  expect(settled.dispatch).toBeNull();

  return {
    offer,
    advance: advanced.dispatch,
    ack: acknowledged.dispatch,
  };
};

const expectFail = async (
  action: () => unknown | Promise<unknown>,
  pattern: RegExp,
): Promise<void> => {
  try {
    await action();
  } catch (error) {
    expect(String(error)).toMatch(pattern);
    return;
  }
  throw new Error(`expected a failure matching ${String(pattern)}`);
};

const canonicalKey = (n: number, epoch = 0): string =>
  `${"ab".repeat(32)}:${String(n)}:${String(epoch)}`;

describe("sparse PQ healing runtime", () => {
  for (const pqMode of [
    "hybrid-mlkem512",
    "hybrid-mlkem768",
    "hybrid-mlkem1024",
  ] as const) {
    test(`${pqMode} completes OFFER → ADVANCE → ACK with identical roots and alternating turns`, async () => {
      const { initiator, responder } = makeEdge(pqMode);
      const frames = await runExchange(initiator, responder, T0 + 1);
      expect(frames.offer).toHaveLength(WIRE_CHUNK_FRAME_LEN);
      expect(frames.advance).toHaveLength(WIRE_CHUNK_FRAME_LEN);
      expect(frames.ack).toHaveLength(WIRE_CHUNK_FRAME_LEN);

      for (const state of [initiator, responder]) {
        expect(state.epoch).toBe(1n);
        expect(state.phase).toBe("idle");
        expect(state.trafficBlocked).toBe(false);
        expect(state.messagesSinceHealing).toBe(0);
        expect(state.lastHealedAt).toBe(T0 + 1);
        expect(state.copyPendingFrame()).toBeNull();
        expect(state.pendingAttempts).toBe(0);
      }
      expect(initiator.nextOfferer).toBe("remote");
      expect(responder.nextOfferer).toBe("local");

      const initiatorContext = initiator.currentMessageContext();
      const responderContext = responder.currentMessageContext();
      expect(initiatorContext.epoch).toBe(1n);
      expect(responderContext.epoch).toBe(1n);
      expect(initiatorContext.rootSuite).toBe(roomPqModeToRootSuite(pqMode));
      expectBytesEqual(initiatorContext.rootKey, responderContext.rootKey);
      expectBytesEqual(initiatorContext.binding, responderContext.binding);
      expect(initiator.resolveMessageContext(0n)).toBeNull();
      expect(initiator.resolveMessageContext(2n)).toBeNull();
      expect(initiator.resolveMessageContext(1n)).not.toBeNull();

      // The turn alternates: the responder owns the second exchange.
      expect(responder.healingDue(T0 + 2)).toBe(false);
      await runExchange(responder, initiator, T0 + 2);
      expect(initiator.epoch).toBe(2n);
      expect(responder.epoch).toBe(2n);
      expect(initiator.nextOfferer).toBe("local");
      expect(responder.nextOfferer).toBe("remote");
      expectBytesEqual(
        initiator.currentMessageContext().rootKey,
        responder.currentMessageContext().rootKey,
      );
      initiator.destroy();
      responder.destroy();
    });
  }

  test("healing is due only on the local turn after the message or time threshold", () => {
    const { initiator, responder } = makeEdge();
    expect(initiator.healingDue(T0)).toBe(false);
    for (let index = 0; index < PQ_HEAL_AFTER_MESSAGES - 1; index += 1)
      initiator.noteApplicationMessage();
    expect(initiator.healingDue(T0)).toBe(false);
    initiator.noteApplicationMessage();
    expect(initiator.healingDue(T0)).toBe(true);

    expect(responder.healingDue(T0 + PQ_HEAL_AFTER_MS - 1)).toBe(false);
    expect(responder.healingDue(T0 + PQ_HEAL_AFTER_MS)).toBe(false);
    makeDue(responder);
    expect(responder.healingDue(T0 + PQ_HEAL_AFTER_MS)).toBe(false);
    void expectFail(
      () => responder.prepareHealingOffer(T0 + PQ_HEAL_AFTER_MS),
      /not due/,
    );

    const fresh = makeState(true);
    expect(fresh.healingDue(T0 + PQ_HEAL_AFTER_MS - 1)).toBe(false);
    expect(fresh.healingDue(T0 + PQ_HEAL_AFTER_MS)).toBe(true);
    initiator.destroy();
    responder.destroy();
    fresh.destroy();
  });

  test("serialize/restore round-trips byte-exactly at every durable boundary", async () => {
    let initiator = makeState(true);
    let responder = makeState(false);

    const roundTrip = (
      state: SparsePqHealingState,
      amInitiator: boolean,
    ): SparsePqHealingState => {
      const checkpoint = state.serialize();
      const restored = restoreState(checkpoint, amInitiator);
      expect(restored.phase).toBe(state.phase);
      expect(restored.epoch).toBe(state.epoch);
      expect(restored.nextOfferer).toBe(state.nextOfferer);
      expect(restored.messagesSinceHealing).toBe(state.messagesSinceHealing);
      expect(restored.lastHealedAt).toBe(state.lastHealedAt);
      expect(restored.pendingAttempts).toBe(state.pendingAttempts);
      expect(restored.pendingRetryAt).toBe(state.pendingRetryAt);
      const pending = state.copyPendingFrame();
      const restoredPending = restored.copyPendingFrame();
      if (pending === null) expect(restoredPending).toBeNull();
      else expectBytesEqual(restoredPending ?? new Uint8Array(0), pending);
      expect(Buffer.from(restored.serialize())).toEqual(
        Buffer.from(checkpoint),
      );
      state.destroy();
      return restored;
    };

    // Idle boundary.
    initiator = roundTrip(initiator, true);
    responder = roundTrip(responder, false);

    // Durable boundary 1: OFFER prepared+persisted+dispatched.
    makeDue(initiator);
    const offer = await initiator.prepareHealingOffer(T0 + 1);
    initiator.markPendingDispatched(T0 + 1);
    initiator = roundTrip(initiator, true);
    expectBytesEqual(
      initiator.copyPendingFrame() ?? new Uint8Array(0),
      offer,
    );

    // Durable boundary 2: inbound OFFER answered with a persisted ADVANCE.
    const advanced = await responder.acceptControlFrame(offer, T0 + 1);
    if (advanced.dispatch === null) throw new Error("expected ADVANCE");
    responder.markPendingDispatched(T0 + 1);
    responder = roundTrip(responder, false);
    expectBytesEqual(
      responder.copyPendingFrame() ?? new Uint8Array(0),
      advanced.dispatch,
    );

    // Durable boundary 3: ADVANCE accepted, exact ACK cached.
    const acknowledged = await initiator.acceptControlFrame(
      advanced.dispatch,
      T0 + 1,
    );
    if (acknowledged.dispatch === null) throw new Error("expected ACK");
    initiator = roundTrip(initiator, true);

    // Durable boundary 4: ACK received, both sides idle at the new epoch.
    const settled = await responder.acceptControlFrame(
      acknowledged.dispatch,
      T0 + 1,
    );
    expect(settled.dispatch).toBeNull();
    responder = roundTrip(responder, false);

    expect(initiator.epoch).toBe(1n);
    expect(responder.epoch).toBe(1n);
    expectBytesEqual(
      initiator.currentMessageContext().rootKey,
      responder.currentMessageContext().rootKey,
    );

    // The restored pair must still be able to complete a full second exchange.
    await runExchange(responder, initiator, T0 + 2);
    expect(initiator.epoch).toBe(2n);
    expect(responder.epoch).toBe(2n);
    initiator.destroy();
    responder.destroy();
  });

  test("a discarded mutated clone leaves the live root, outbox, and counters unchanged", async () => {
    const { initiator, responder } = makeEdge();
    makeDue(initiator);
    const before = initiator.serialize();
    const beforeContext = Uint8Array.from(
      initiator.currentMessageContext().rootKey,
    );

    const failedCandidate = initiator.clone();
    const unsentOffer = await failedCandidate.prepareHealingOffer(T0 + 1);
    expect(unsentOffer).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    // Injected persistence failure: the candidate is discarded, never adopted.
    failedCandidate.destroy();

    expect(initiator.phase).toBe("idle");
    expect(initiator.copyPendingFrame()).toBeNull();
    expect(initiator.epoch).toBe(0n);
    expect(initiator.healingDue(T0 + 1)).toBe(true);
    expectBytesEqual(
      initiator.currentMessageContext().rootKey,
      beforeContext,
    );
    expect(Buffer.from(initiator.serialize())).toEqual(Buffer.from(before));

    // The retried transition succeeds on a fresh clone and is adopted.
    const candidate = initiator.clone();
    const offer = await candidate.prepareHealingOffer(T0 + 1);
    initiator.adopt(candidate);
    expect(initiator.phase).toBe("outbound-offer-dispatched");
    expectBytesEqual(initiator.copyPendingFrame() ?? new Uint8Array(0), offer);
    await expectFail(() => candidate.serialize(), /destroyed/);

    // Same discipline on the receive side.
    const responderBefore = responder.serialize();
    const failedReceive = responder.clone();
    const advanced = await failedReceive.acceptControlFrame(offer, T0 + 1);
    expect(advanced.dispatch).not.toBeNull();
    failedReceive.destroy();
    expect(Buffer.from(responder.serialize())).toEqual(
      Buffer.from(responderBefore),
    );
    expect(responder.phase).toBe("idle");

    const receiveCandidate = responder.clone();
    const readvanced = await receiveCandidate.acceptControlFrame(offer, T0 + 1);
    if (readvanced.dispatch === null) throw new Error("expected ADVANCE");
    responder.adopt(receiveCandidate);
    expectBytesEqual(
      responder.copyPendingFrame() ?? new Uint8Array(0),
      readvanced.dispatch,
    );
    initiator.destroy();
    responder.destroy();
  });

  test("every dropped flight retries the exact persisted frame bytes", async () => {
    const { initiator, responder } = makeEdge();
    makeDue(initiator);

    // Dropped OFFER: retry re-reads the exact frame, including after restore.
    const offer = await initiator.prepareHealingOffer(T0 + 1);
    initiator.markPendingDispatched(T0 + 1);
    expect(initiator.pendingAttempts).toBe(1);
    expect(initiator.pendingRetryAt).toBe(T0 + 1 + PQ_HEAL_RETRY_MS);
    const retried = initiator.copyPendingFrame();
    expectBytesEqual(retried ?? new Uint8Array(0), offer);
    const restoredInitiator = restoreState(initiator.serialize(), true);
    expectBytesEqual(
      restoredInitiator.copyPendingFrame() ?? new Uint8Array(0),
      offer,
    );
    restoredInitiator.destroy();

    // Dropped ADVANCE: the exact duplicate OFFER re-emits the exact ADVANCE
    // without another persistence write.
    const advanced = await responder.acceptControlFrame(offer, T0 + 1);
    if (advanced.dispatch === null) throw new Error("expected ADVANCE");
    responder.markPendingDispatched(T0 + 1);
    const responderCheckpoint = responder.serialize();
    const duplicateOffer = await responder.acceptControlFrame(
      Uint8Array.from(offer),
      T0 + 2,
    );
    expect(duplicateOffer.changed).toBe(false);
    expectBytesEqual(
      duplicateOffer.dispatch ?? new Uint8Array(0),
      advanced.dispatch,
    );
    expect(Buffer.from(responder.serialize())).toEqual(
      Buffer.from(responderCheckpoint),
    );

    // Dropped ACK: the exact duplicate ADVANCE re-emits the exact ACK after
    // the old root is gone.
    const acknowledged = await initiator.acceptControlFrame(
      advanced.dispatch,
      T0 + 2,
    );
    if (acknowledged.dispatch === null) throw new Error("expected ACK");
    expect(initiator.epoch).toBe(1n);
    const initiatorCheckpoint = initiator.serialize();
    const duplicateAdvance = await initiator.acceptControlFrame(
      Uint8Array.from(advanced.dispatch),
      T0 + 3,
    );
    expect(duplicateAdvance.changed).toBe(false);
    expectBytesEqual(
      duplicateAdvance.dispatch ?? new Uint8Array(0),
      acknowledged.dispatch,
    );
    expect(Buffer.from(initiator.serialize())).toEqual(
      Buffer.from(initiatorCheckpoint),
    );

    const settled = await responder.acceptControlFrame(
      acknowledged.dispatch,
      T0 + 3,
    );
    expect(settled.dispatch).toBeNull();
    initiator.destroy();
    responder.destroy();
  });

  test("altered bytes in an already-answered slot fail closed without mutating state", async () => {
    const { initiator, responder } = makeEdge();
    makeDue(initiator);
    const offer = await initiator.prepareHealingOffer(T0 + 1);
    const advanced = await responder.acceptControlFrame(offer, T0 + 1);
    if (advanced.dispatch === null) throw new Error("expected ADVANCE");

    // A same-slot OFFER with different bytes is a fork, not a duplicate.
    const forkedOffer = Uint8Array.from(offer);
    forkedOffer[forkedOffer.length - 1] ^= 1;
    const responderCheckpoint = responder.serialize();
    await expectFail(
      () => responder.acceptControlFrame(forkedOffer, T0 + 2),
      /pqHealingFrame|pq-healing/i,
    );
    expect(Buffer.from(responder.serialize())).toEqual(
      Buffer.from(responderCheckpoint),
    );
    expectBytesEqual(
      responder.copyPendingFrame() ?? new Uint8Array(0),
      advanced.dispatch,
    );

    const acknowledged = await initiator.acceptControlFrame(
      advanced.dispatch,
      T0 + 2,
    );
    if (acknowledged.dispatch === null) throw new Error("expected ACK");
    const forkedAdvance = Uint8Array.from(advanced.dispatch);
    forkedAdvance[forkedAdvance.length - 1] ^= 1;
    const initiatorCheckpoint = initiator.serialize();
    await expectFail(
      () => initiator.acceptControlFrame(forkedAdvance, T0 + 3),
      /pqHealingFrame|pq-healing/i,
    );
    expect(Buffer.from(initiator.serialize())).toEqual(
      Buffer.from(initiatorCheckpoint),
    );
    initiator.destroy();
    responder.destroy();
  });

  test("wrong suite, binding, direction, and epoch fail closed", async () => {
    await expectFail(
      () =>
        new SparsePqHealingState({
          module,
          pqMode: "hybrid-mlkem512",
          rootSuite: roomPqModeToRootSuite("hybrid-mlkem768"),
          binding: binding(),
          rootKey: root(),
          nextOfferer: "local",
          amInitiator: true,
          now: T0,
        }),
      /root suite and room PQ mode disagree/,
    );

    // Wrong direction: a peer must not accept its own outbound frame.
    const { initiator, responder } = makeEdge();
    makeDue(initiator);
    const offer = await initiator.prepareHealingOffer(T0 + 1);
    await expectFail(
      () => initiator.acceptControlFrame(Uint8Array.from(offer), T0 + 1),
      /pqHealingFrame/,
    );

    // Wrong suite: an ML-KEM-768 responder rejects an ML-KEM-512 OFFER.
    const wrongSuite = makeState(false, "hybrid-mlkem768");
    await expectFail(
      () => wrongSuite.acceptControlFrame(Uint8Array.from(offer), T0 + 1),
      /pqHealingFrame/,
    );
    wrongSuite.destroy();

    // Wrong binding: another authenticated edge rejects the frame.
    const wrongBinding = makeState(false, "hybrid-mlkem512", binding(0x43));
    await expectFail(
      () => wrongBinding.acceptControlFrame(Uint8Array.from(offer), T0 + 1),
      /pqHealingFrame/,
    );
    wrongBinding.destroy();

    // Stale epoch: after the exchange completes, the settled peers reject the
    // original epoch-zero OFFER instead of resurrecting the old root.
    const advanced = await responder.acceptControlFrame(offer, T0 + 1);
    if (advanced.dispatch === null) throw new Error("expected ADVANCE");
    const acknowledged = await initiator.acceptControlFrame(
      advanced.dispatch,
      T0 + 1,
    );
    if (acknowledged.dispatch === null) throw new Error("expected ACK");
    const settled = await responder.acceptControlFrame(
      acknowledged.dispatch,
      T0 + 1,
    );
    expect(settled.dispatch).toBeNull();
    await expectFail(
      () => responder.acceptControlFrame(Uint8Array.from(offer), T0 + 2),
      /pqHealingFrame/,
    );

    // Malformed frame sizes fail before any decryption.
    await expectFail(
      () =>
        responder.acceptControlFrame(
          new Uint8Array(WIRE_CHUNK_FRAME_LEN - 1),
          T0 + 2,
        ),
      /must be exactly/,
    );
    initiator.destroy();
    responder.destroy();
  });

  test("checkpoint restore rejects a foreign binding, direction, or room suite", () => {
    const state = makeState(true);
    const checkpoint = state.serialize();

    void expectFail(
      () => restoreState(checkpoint, false),
      /opposite edge direction/,
    );
    void expectFail(
      () => restoreState(checkpoint, true, "hybrid-mlkem512", binding(0x43)),
      /another authenticated edge/,
    );
    void expectFail(
      () => restoreState(checkpoint, true, "hybrid-mlkem768"),
      /suite disagrees with the authenticated room policy/,
    );
    state.destroy();
  });

  test("active combined receive keys round-trip separately and are wiped on adopt/destroy", () => {
    const state = makeState(true);
    const firstValue = new Uint8Array(32).fill(0x01);
    const secondValue = new Uint8Array(32).fill(0x02);
    state.activeReceiveKeys.set(canonicalKey(1), firstValue);
    state.activeReceiveKeys.set(canonicalKey(2), secondValue);

    const restored = restoreState(state.serialize(), true);
    expect(restored.activeReceiveKeys.size).toBe(2);
    const restoredFirst = restored.activeReceiveKeys.get(canonicalKey(1));
    if (restoredFirst === undefined) throw new Error("missing restored key");
    expectBytesEqual(restoredFirst, firstValue);
    expect(restoredFirst).not.toBe(firstValue);

    // A staged candidate map overrides the live one without mutating it.
    const staged = new Map<string, Uint8Array>([
      [canonicalKey(3), new Uint8Array(32).fill(0x03)],
    ]);
    const stagedRestore = restoreState(state.serialize(staged), true);
    expect(stagedRestore.activeReceiveKeys.size).toBe(1);
    expect(stagedRestore.activeReceiveKeys.has(canonicalKey(3))).toBe(true);
    expect(state.activeReceiveKeys.size).toBe(2);
    stagedRestore.destroy();

    // Destroy wipes the restored copies.
    restored.destroy();
    expect(restoredFirst.every((byte) => byte === 0)).toBe(true);

    // Adopt wipes the previous live copies and takes the clone's copies.
    const clone = state.clone();
    state.adopt(clone);
    expect(firstValue.every((byte) => byte === 0)).toBe(true);
    expect(secondValue.every((byte) => byte === 0)).toBe(true);
    const adoptedFirst = state.activeReceiveKeys.get(canonicalKey(1));
    if (adoptedFirst === undefined) throw new Error("missing adopted key");
    expect(adoptedFirst[0]).toBe(0x01);

    // Non-canonical keys must fail at serialization time, before persistence.
    state.activeReceiveKeys.set("not-a-canonical-key", new Uint8Array(32));
    void expectFail(() => state.serialize(), /non-canonical/);
    state.destroy();
  });

  test("retry exhaustion fails closed without generating a replacement record", async () => {
    const state = makeState(true);
    makeDue(state);
    const offer = await state.prepareHealingOffer(T0 + 1);
    for (let attempt = 0; attempt < PQ_HEAL_MAX_RETRIES; attempt += 1)
      state.markPendingDispatched(T0 + 1 + attempt);
    expect(state.pendingAttempts).toBe(PQ_HEAL_MAX_RETRIES);

    void expectFail(
      () => state.markPendingDispatched(T0 + 100),
      /retry budget is exhausted/,
    );
    // The exhausted state still holds the exact original frame and cannot
    // fall back to a fresh OFFER or another suite.
    expectBytesEqual(state.copyPendingFrame() ?? new Uint8Array(0), offer);
    expect(state.phase).toBe("outbound-offer-dispatched");
    expect(state.trafficBlocked).toBe(true);
    expect(state.healingDue(T0 + PQ_HEAL_AFTER_MS * 2)).toBe(false);
    await expectFail(
      () => state.prepareHealingOffer(T0 + PQ_HEAL_AFTER_MS * 2),
      /not due/,
    );

    // Exhaustion survives serialize/restore exactly.
    const restored = restoreState(state.serialize(), true);
    expect(restored.pendingAttempts).toBe(PQ_HEAL_MAX_RETRIES);
    void expectFail(
      () => restored.markPendingDispatched(T0 + 200),
      /retry budget is exhausted/,
    );
    restored.destroy();
    state.destroy();
  });

  test("checkpoint truncation, trailing bytes, and header corruption fail closed", () => {
    const state = makeState(true);
    state.activeReceiveKeys.set(canonicalKey(1), new Uint8Array(32).fill(7));
    const checkpoint = state.serialize();

    void expectFail(
      () => restoreState(checkpoint.subarray(0, checkpoint.length - 1), true),
      /truncated/,
    );

    const trailing = new Uint8Array(checkpoint.length + 1);
    trailing.set(checkpoint);
    void expectFail(() => restoreState(trailing, true), /trailing bytes/);

    const badMagic = Uint8Array.from(checkpoint);
    badMagic[0] ^= 1;
    void expectFail(() => restoreState(badMagic, true), /magic is invalid/);

    const badVersion = Uint8Array.from(checkpoint);
    badVersion[8] = 2;
    void expectFail(
      () => restoreState(badVersion, true),
      /version is unsupported/,
    );

    const badReserved = Uint8Array.from(checkpoint);
    expect(badReserved[11]).toBe(0);
    badReserved[11] = 1;
    void expectFail(
      () => restoreState(badReserved, true),
      /reserved byte is non-zero/,
    );

    const oversized = new Uint8Array(256 * 1024 + 1);
    oversized.set(checkpoint);
    void expectFail(() => restoreState(oversized, true), /length is invalid/);
    state.destroy();
  });

  test("impossible phase/outbox combinations and duplicate cache keys fail closed", async () => {
    // Byte offsets inside the canonical checkpoint layout: fixed header (12)
    // + lastHealedAt/messages (16) + binding/root (64) + epoch/counters (24)
    // + turn (1) = 117, then the phase block, machine replay records, outbox.
    const state = makeState(true);
    makeDue(state);
    await state.prepareHealingOffer(T0 + 1);
    const checkpoint = state.serialize();
    const lengths = getPqHealingRecordLengths(ML_KEM_512_SUITE);
    const outboxTagOffset =
      117 +
      1 +
      4 +
      lengths.offer +
      4 +
      ML_KEM_512_SUITE.secretKeyBytes +
      4 +
      4;
    expect(checkpoint[outboxTagOffset]).toBe(1);
    const incoherent = Uint8Array.from(checkpoint);
    incoherent[outboxTagOffset] = 2;
    await expectFail(
      () => restoreState(incoherent, true),
      /phase and sealed outbox disagree/,
    );
    await expectFail(
      () =>
        restoreState(
          (() => {
            const missingOutbox = Uint8Array.from(checkpoint);
            missingOutbox[outboxTagOffset] = 0;
            return missingOutbox;
          })(),
          true,
        ),
      /pqHealingRuntime/,
    );
    state.destroy();

    // Duplicate active-key cache entries are rejected on read.
    const keyed = makeState(true);
    keyed.activeReceiveKeys.set(canonicalKey(1), new Uint8Array(32).fill(1));
    keyed.activeReceiveKeys.set(canonicalKey(2), new Uint8Array(32).fill(2));
    const keyedCheckpoint = keyed.serialize();
    const keyLength = canonicalKey(1).length;
    const secondKeyOffset = keyedCheckpoint.length - 32 - keyLength;
    const firstKeyOffset = keyedCheckpoint.length - 2 * keyLength - 66;
    const decoder = new TextDecoder();
    expect(
      decoder.decode(
        keyedCheckpoint.subarray(firstKeyOffset, firstKeyOffset + keyLength),
      ),
    ).toBe(canonicalKey(1));
    expect(
      decoder.decode(
        keyedCheckpoint.subarray(secondKeyOffset, secondKeyOffset + keyLength),
      ),
    ).toBe(canonicalKey(2));
    const duplicated = Uint8Array.from(keyedCheckpoint);
    duplicated.set(
      keyedCheckpoint.subarray(firstKeyOffset, firstKeyOffset + keyLength),
      secondKeyOffset,
    );
    await expectFail(() => restoreState(duplicated, true), /non-canonical/);
    keyed.destroy();
  });

  test("serialization refuses to exceed the active receive key budget", () => {
    const state = makeState(true);
    const flood = new Map<string, Uint8Array>();
    for (let index = 0; index < 257; index += 1)
      flood.set(canonicalKey(index), new Uint8Array(32).fill(1));
    void expectFail(
      () => state.serialize(flood),
      /too many active receive message keys/,
    );
    state.destroy();
  });

  test("destroy is idempotent and blocks every subsequent transition", async () => {
    const state = makeState(true);
    makeDue(state);
    const offer = await state.prepareHealingOffer(T0 + 1);
    const pending = state.copyPendingFrame();
    if (pending === null) throw new Error("expected a pending frame");
    state.destroy();
    state.destroy();
    expect(state.trafficBlocked).toBe(true);
    await expectFail(() => state.serialize(), /destroyed/);
    await expectFail(() => state.copyPendingFrame(), /destroyed/);
    await expectFail(
      () => state.acceptControlFrame(offer, T0 + 2),
      /destroyed/,
    );
    await expectFail(() => state.clone(), /destroyed/);
    // The runtime wipes its own copy; the caller's copy is unaffected.
    expect(offer.some((byte) => byte !== 0)).toBe(true);
    expect(pending.some((byte) => byte !== 0)).toBe(true);
  });
});
