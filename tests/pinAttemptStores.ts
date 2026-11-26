// PIN-attempt stores for tests. `workerPinAttemptStore` is the real database
// worker: db.worker.ts's own onmessage handler over fake-indexeddb, the rows
// the browser writes. `memoryPinAttemptStore` keeps rows in a Map and settles
// in microtasks, for handler tests that only need a working store.
import "fake-indexeddb/auto";

import type { PinAttemptStore } from "../src/roomPinAttempts";
import type { PinAttemptState } from "../src/db/types";

let nextWorkerId = 1;
const pendingWorkerCalls = new Map<
  number,
  { resolve: (value: unknown) => void; reject: (reason: Error) => void }
>();

const deliverWorkerReply = (message: unknown): void => {
  const reply = message as { id: number; result?: unknown; error?: unknown };
  const call = pendingWorkerCalls.get(reply.id);
  if (!call) return;
  pendingWorkerCalls.delete(reply.id);
  if (reply.error) call.reject(new Error(String(reply.error)));
  else call.resolve(reply.result);
};

export const callPinWorker = async (
  method: string,
  ...args: unknown[]
): Promise<unknown> => {
  await import("../src/db/db.worker"); // installs onmessage once
  (globalThis as unknown as { postMessage: (m: unknown) => void }).postMessage =
    deliverWorkerReply;
  const handler = (
    globalThis as unknown as {
      onmessage: (event: MessageEvent) => Promise<void>;
    }
  ).onmessage;
  const id = nextWorkerId++;
  return new Promise((resolve, reject) => {
    pendingWorkerCalls.set(id, { resolve, reject });
    void handler({
      data: structuredClone({ id, method, args }),
    } as MessageEvent);
  });
};

export const workerPinAttemptStore: PinAttemptStore = {
  get: (roomId, id) =>
    callPinWorker("getPinAttemptState", roomId, id) as Promise<
      PinAttemptState | undefined
    >,
  increment: (roomId, id, now, maxImmediateAttempts, baseMs, maxMs) =>
    callPinWorker(
      "incrementPinAttemptState",
      roomId,
      id,
      now,
      maxImmediateAttempts,
      baseMs,
      maxMs,
    ) as Promise<PinAttemptState>,
  delete: async (roomId, id) => {
    await callPinWorker("deletePinAttemptState", roomId, id);
  },
};

/** Same row semantics as the worker's three PIN-attempt methods. */
export const memoryPinAttemptStore = (): PinAttemptStore => {
  const rows = new Map<string, PinAttemptState>();
  const key = (roomId: string, id: string) =>
    `${String(roomId.length)}:${roomId}:${id}`;
  return {
    get: async (roomId, id) => rows.get(key(roomId, id)),
    increment: async (roomId, id, now, maxImmediateAttempts, baseMs, maxMs) => {
      const failures = (rows.get(key(roomId, id))?.failures ?? 0) + 1;
      const delay =
        failures < maxImmediateAttempts
          ? 0
          : Math.min(baseMs * 2 ** (failures - maxImmediateAttempts), maxMs);
      const next = { failures, retryAfter: now + delay };
      rows.set(key(roomId, id), next);
      return next;
    },
    delete: async (roomId, id) => {
      if (id !== undefined) {
        rows.delete(key(roomId, id));
        return;
      }
      const prefix = `${String(roomId.length)}:${roomId}:`;
      for (const stored of [...rows.keys()])
        if (stored.startsWith(prefix)) rows.delete(stored);
    },
  };
};
