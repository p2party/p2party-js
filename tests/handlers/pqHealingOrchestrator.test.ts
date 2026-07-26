import { beforeAll, describe, expect, test } from "bun:test";

import { initRatchet } from "../../src/cryptography/ratchet";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  PQ_HEAL_AFTER_MESSAGES,
  PQ_HEAL_MAX_RETRIES,
  PQ_HEAL_RETRY_MS,
  SparsePqHealingState,
} from "../../src/handlers/pqHealingRuntime";
import {
  destroyPqHealingOrchestrator,
  handleInboundPqControlFrame,
  installPqHealingOrchestrator,
  isPqApplicationTrafficBlocked,
  tickPqHealing,
} from "../../src/handlers/pqHealingOrchestrator";
import { RATCHET_ROOT_SUITE_MLKEM512 } from "../../src/utils/constants";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

const ROOM = "pq-orchestrator-room";
const T0 = 10_000;

const rand = (n: number): Uint8Array => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

interface Peer {
  epc: IRTCPeerConnection;
  runtime: SparsePqHealingState;
  /** Frames dispatched and not yet delivered/dropped. */
  wire: Uint8Array[];
  /** Every frame ever dispatched, in order. */
  sent: Uint8Array[];
  /** Serialized candidate checkpoints, one per durable write. */
  persisted: Uint8Array[];
  persistCalls: number;
  persistFailures: number;
  edgeFailures: Error[];
}

const clockBox = { now: T0 };

const makeEdgePair = (): { a: Peer; b: Peer } => {
  clockBox.now = T0;
  const seed = rand(32);
  const ratchetB = initRatchet(seed, false, null, module);
  const ratchetA = initRatchet(
    Uint8Array.from(seed),
    true,
    ratchetB.dhSelfPub,
    module,
  );
  const binding = new Uint8Array(32).fill(0x42);

  const makePeer = (
    amInitiator: boolean,
    ratchet: typeof ratchetA,
  ): Peer => {
    const runtime = new SparsePqHealingState({
      module,
      pqMode: "hybrid-mlkem512",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      binding: Uint8Array.from(binding),
      rootKey: new Uint8Array(32).fill(0x19),
      nextOfferer: amInitiator ? "local" : "remote",
      amInitiator,
      now: T0,
    });
    const epc = {
      roomId: ROOM,
      withPeerId: amInitiator ? "peer-b" : "peer-a",
      withPeerPublicKey: (amInitiator ? "ab" : "ba").repeat(32),
      ratchetState: ratchet,
      pqHealingState: runtime,
      messageChannels: new Set<IRTCDataChannel>(),
    } as unknown as IRTCPeerConnection;
    epc.messageKeyCache = runtime.activeReceiveKeys;

    const peer: Peer = {
      epc,
      runtime,
      wire: [],
      sent: [],
      persisted: [],
      persistCalls: 0,
      persistFailures: 0,
      edgeFailures: [],
    };
    installPqHealingOrchestrator(epc, ROOM, {
      tickMs: 0,
      now: () => clockBox.now,
      sendControlFrame: (frame) => {
        peer.wire.push(Uint8Array.from(frame));
        peer.sent.push(Uint8Array.from(frame));
        return true;
      },
      failEdge: (reason) => {
        peer.edgeFailures.push(reason);
      },
      persistEdge: async (_epc, state, _roomId, serializeCandidate) => {
        peer.persistCalls += 1;
        expect(state).toBe(peer.epc.ratchetState!);
        if (peer.persistFailures > 0) {
          peer.persistFailures -= 1;
          throw new Error("injected edge persistence failure");
        }
        peer.persisted.push(Uint8Array.from(serializeCandidate()));
      },
    });
    return peer;
  };

  return { a: makePeer(true, ratchetA), b: makePeer(false, ratchetB) };
};

const makeDue = (peer: Peer): void => {
  for (let index = 0; index < PQ_HEAL_AFTER_MESSAGES; index += 1)
    peer.runtime.noteApplicationMessage();
};

const deliver = async (from: Peer, to: Peer): Promise<void> => {
  const frame = from.wire.shift();
  if (!frame) throw new Error("no frame on the wire to deliver");
  await handleInboundPqControlFrame(to.epc, ROOM, frame);
};

const drop = (from: Peer): Uint8Array => {
  const frame = from.wire.shift();
  if (!frame) throw new Error("no frame on the wire to drop");
  return frame;
};

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const destroyPair = (pair: { a: Peer; b: Peer }): void => {
  destroyPqHealingOrchestrator(pair.a.epc);
  destroyPqHealingOrchestrator(pair.b.epc);
  pair.a.runtime.destroy();
  pair.b.runtime.destroy();
};

describe("live sparse-healing orchestrator (two in-memory peers)", () => {
  test("a due exchange completes OFFER → ADVANCE → ACK with persist-before-send at every hop", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;

    // Not due yet: the tick does nothing.
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(0);

    makeDue(a);
    // The responder never initiates even when its counters are due.
    makeDue(b);
    await tickPqHealing(b.epc);
    expect(b.sent).toHaveLength(0);

    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(1); // OFFER
    expect(a.persistCalls).toBe(1);
    expect(a.runtime.pendingAttempts).toBe(1);
    expect(isPqApplicationTrafficBlocked(a.epc)).toBe(true);

    await deliver(a, b); // OFFER → B answers ADVANCE
    expect(b.sent).toHaveLength(1);
    expect(b.persistCalls).toBe(1);
    expect(isPqApplicationTrafficBlocked(b.epc)).toBe(true);

    await deliver(b, a); // ADVANCE → A settles + dispatches ACK
    expect(a.sent).toHaveLength(2);
    expect(a.persistCalls).toBe(2);
    expect(a.runtime.epoch).toBe(1n);
    expect(isPqApplicationTrafficBlocked(a.epc)).toBe(false);

    await deliver(a, b); // ACK → B settles
    expect(b.persistCalls).toBe(2);
    expect(b.runtime.epoch).toBe(1n);
    expect(isPqApplicationTrafficBlocked(b.epc)).toBe(false);

    expectBytesEqual(
      a.runtime.currentMessageContext().rootKey,
      b.runtime.currentMessageContext().rootKey,
    );
    expect(a.runtime.nextOfferer).toBe("remote");
    expect(b.runtime.nextOfferer).toBe("local");
    // adopt() replaced the active-key map object; the alias must follow it.
    expect(a.epc.messageKeyCache).toBe(a.runtime.activeReceiveKeys);
    expect(b.epc.messageKeyCache).toBe(b.runtime.activeReceiveKeys);
    // Message counters reset after the settled exchange.
    expect(a.runtime.messagesSinceHealing).toBe(0);

    // The turn alternates: the second exchange belongs to B.
    makeDue(b);
    await tickPqHealing(b.epc);
    expect(b.sent).toHaveLength(2);
    await deliver(b, a);
    await deliver(a, b);
    await deliver(b, a);
    expect(a.runtime.epoch).toBe(2n);
    expect(b.runtime.epoch).toBe(2n);
    expect(a.edgeFailures).toHaveLength(0);
    expect(b.edgeFailures).toHaveLength(0);
    destroyPair(pair);
  });

  test("local initiation waits for a quiescent transfer boundary", async () => {
    const pair = makeEdgePair();
    const { a } = pair;
    makeDue(a);
    a.epc.messageChannels!.add({} as IRTCDataChannel);
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(0);
    a.epc.messageChannels!.clear();
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(1);
    destroyPair(pair);
  });

  test("a dropped OFFER retransmits the exact persisted bytes on the 5-second schedule", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;
    makeDue(a);
    await tickPqHealing(a.epc);
    const original = drop(a); // OFFER lost in transit

    // Before the deadline nothing is resent.
    clockBox.now = T0 + PQ_HEAL_RETRY_MS - 1;
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(1);

    clockBox.now = T0 + PQ_HEAL_RETRY_MS;
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(2);
    expectBytesEqual(a.sent[1], original);
    expect(a.runtime.pendingAttempts).toBe(2);
    expect(a.persistCalls).toBe(2); // the attempt count is durable

    // The retried flight completes the exchange normally.
    await deliver(a, b);
    await deliver(b, a);
    await deliver(a, b);
    expect(a.runtime.epoch).toBe(1n);
    expect(b.runtime.epoch).toBe(1n);
    destroyPair(pair);
  });

  test("a dropped ADVANCE is re-answered from the duplicate cache without another write", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;
    makeDue(a);
    await tickPqHealing(a.epc);
    await deliver(a, b);
    const lostAdvance = drop(b);
    expect(b.persistCalls).toBe(1);

    // A retries the exact OFFER; B answers with the EXACT cached ADVANCE.
    clockBox.now = T0 + PQ_HEAL_RETRY_MS;
    await tickPqHealing(a.epc);
    await deliver(a, b);
    expect(b.sent).toHaveLength(2);
    expectBytesEqual(b.sent[1], lostAdvance);
    expect(b.persistCalls).toBe(1); // duplicate response, no write

    await deliver(b, a);
    await deliver(a, b);
    expect(a.runtime.epoch).toBe(1n);
    expect(b.runtime.epoch).toBe(1n);
    destroyPair(pair);
  });

  test("a dropped ACK is re-answered exactly after the old root is gone", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;
    makeDue(a);
    await tickPqHealing(a.epc);
    await deliver(a, b);
    await deliver(b, a);
    const lostAck = drop(a);
    expect(a.runtime.epoch).toBe(1n); // A already committed the new root

    // B retries its ADVANCE durably; A re-emits the exact cached ACK.
    clockBox.now = T0 + PQ_HEAL_RETRY_MS;
    await tickPqHealing(b.epc);
    expect(b.persistCalls).toBe(2);
    const aPersistsBefore = a.persistCalls;
    await deliver(b, a);
    expect(a.sent).toHaveLength(3);
    expectBytesEqual(a.sent[2], lostAck);
    expect(a.persistCalls).toBe(aPersistsBefore); // duplicate, no write

    await deliver(a, b);
    expect(b.runtime.epoch).toBe(1n);
    destroyPair(pair);
  });

  test("storage failure at every boundary is transient: live state holds and the retry recovers", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;

    // OFFER boundary.
    makeDue(a);
    a.persistFailures = 1;
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(0);
    expect(a.runtime.phase).toBe("idle");
    expect(a.runtime.copyPendingFrame()).toBeNull();
    expect(a.edgeFailures).toHaveLength(0);
    await tickPqHealing(a.epc);
    expect(a.sent).toHaveLength(1);

    // ADVANCE boundary (inbound OFFER, persistence fails on B).
    b.persistFailures = 1;
    const offer = drop(a);
    await handleInboundPqControlFrame(b.epc, ROOM, offer);
    expect(b.sent).toHaveLength(0);
    expect(b.runtime.phase).toBe("idle");
    expect(b.edgeFailures).toHaveLength(0);
    // A's exact retransmit reprocesses the same slot successfully.
    clockBox.now = T0 + PQ_HEAL_RETRY_MS;
    await tickPqHealing(a.epc);
    await deliver(a, b);
    expect(b.sent).toHaveLength(1);

    // ACK boundary (inbound ADVANCE, persistence fails on A).
    a.persistFailures = 1;
    const advance = drop(b);
    await handleInboundPqControlFrame(a.epc, ROOM, advance);
    expect(a.runtime.epoch).toBe(0n);
    expect(a.runtime.copyPendingFrame()).not.toBeNull(); // outbox still OFFER
    expect(a.edgeFailures).toHaveLength(0);
    // B retries the ADVANCE; A now settles and emits the ACK.
    clockBox.now = T0 + 2 * PQ_HEAL_RETRY_MS;
    await tickPqHealing(b.epc);
    await deliver(b, a);
    expect(a.runtime.epoch).toBe(1n);

    // ACK-receipt boundary (inbound ACK, persistence fails on B).
    b.persistFailures = 1;
    const ack = drop(a);
    await handleInboundPqControlFrame(b.epc, ROOM, ack);
    expect(b.runtime.epoch).toBe(1n); // B already committed at ADVANCE time
    expect(b.runtime.trafficBlocked).toBe(true); // still awaiting a durable ACK
    expect(b.edgeFailures).toHaveLength(0);
    // B retries the ADVANCE; A re-answers the exact ACK; B settles durably.
    clockBox.now = T0 + 3 * PQ_HEAL_RETRY_MS;
    await tickPqHealing(b.epc);
    await deliver(b, a);
    await deliver(a, b);
    expect(b.runtime.trafficBlocked).toBe(false);
    expect(b.runtime.epoch).toBe(1n);
    expectBytesEqual(
      a.runtime.currentMessageContext().rootKey,
      b.runtime.currentMessageContext().rootKey,
    );
    expect(a.edgeFailures).toHaveLength(0);
    expect(b.edgeFailures).toHaveLength(0);
    destroyPair(pair);
  });

  test("retry exhaustion fails the authenticated edge instead of regenerating a record", async () => {
    const pair = makeEdgePair();
    const { a } = pair;
    makeDue(a);
    await tickPqHealing(a.epc);
    expect(a.runtime.pendingAttempts).toBe(1);

    for (let attempt = 2; attempt <= PQ_HEAL_MAX_RETRIES; attempt += 1) {
      clockBox.now = T0 + (attempt - 1) * PQ_HEAL_RETRY_MS;
      await tickPqHealing(a.epc);
      expect(a.runtime.pendingAttempts).toBe(attempt);
    }
    // Every retransmit reused the exact bytes; no replacement OFFER exists.
    for (const frame of a.sent.slice(1)) expectBytesEqual(frame, a.sent[0]);
    expect(a.edgeFailures).toHaveLength(0);

    clockBox.now = T0 + PQ_HEAL_MAX_RETRIES * PQ_HEAL_RETRY_MS;
    await tickPqHealing(a.epc);
    expect(a.edgeFailures).toHaveLength(1);
    expect(String(a.edgeFailures[0])).toMatch(/retry budget exhausted/);
    expect(a.sent).toHaveLength(PQ_HEAL_MAX_RETRIES);
    expect(isPqApplicationTrafficBlocked(a.epc)).toBe(true);

    // The failed edge stops all further orchestration.
    clockBox.now += PQ_HEAL_RETRY_MS;
    await tickPqHealing(a.epc);
    expect(a.edgeFailures).toHaveLength(1);
    expect(a.sent).toHaveLength(PQ_HEAL_MAX_RETRIES);
    destroyPair(pair);
  });

  test("altered bytes in an answered slot are a fork and fail the authenticated edge", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;
    makeDue(a);
    await tickPqHealing(a.epc);
    const offer = drop(a);
    const forked = Uint8Array.from(offer);
    forked[forked.length - 1] ^= 1;

    await handleInboundPqControlFrame(b.epc, ROOM, forked);
    expect(b.edgeFailures).toHaveLength(1);
    expect(String(b.edgeFailures[0])).toMatch(/forked control cell/);
    expect(b.runtime.epoch).toBe(0n);
    expect(b.runtime.phase).toBe("idle");
    // The failed edge refuses even the honest frame afterwards.
    await handleInboundPqControlFrame(b.epc, ROOM, offer);
    expect(b.sent).toHaveLength(0);
    destroyPair(pair);
  });

  test("the persisted checkpoint at each boundary restores to the live state", async () => {
    const pair = makeEdgePair();
    const { a, b } = pair;
    makeDue(a);
    await tickPqHealing(a.epc);
    await deliver(a, b);
    await deliver(b, a);
    await deliver(a, b);

    const restored = SparsePqHealingState.restore(
      b.persisted[b.persisted.length - 1],
      {
        module,
        pqMode: "hybrid-mlkem512",
        rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
        binding: new Uint8Array(32).fill(0x42),
        amInitiator: false,
      },
    );
    expect(restored.epoch).toBe(1n);
    expect(restored.phase).toBe("idle");
    expect(restored.nextOfferer).toBe("local");
    expectBytesEqual(
      restored.currentMessageContext().rootKey,
      b.runtime.currentMessageContext().rootKey,
    );
    restored.destroy();
    destroyPair(pair);
  });
});
