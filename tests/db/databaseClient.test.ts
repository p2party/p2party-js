import { describe, expect, test } from "bun:test";

import {
  createDatabaseClient,
  type DatabaseWorkerPort,
} from "../../src/db/api";
import { DatabaseWorkerError } from "../../src/db/dbErrors";

// A worker that records what it is sent and never answers, so a test decides
// when (and whether) it fails.
const fakeWorker = () => {
  const posted: unknown[] = [];
  const port: DatabaseWorkerPort = {
    postMessage: (message) => {
      posted.push(message);
    },
    onmessage: null,
    onerror: null,
    onmessageerror: null,
  };
  return { port, posted };
};

describe("database client after the worker fails", () => {
  test("a pending call rejects with DatabaseWorkerError when the worker fails", async () => {
    const { port, posted } = fakeWorker();
    const client = createDatabaseClient(port, true);
    const call = client.call("getAllDBUniqueRooms", []);
    expect(posted).toHaveLength(1);
    port.onerror!({ message: "injected crash" } as ErrorEvent);
    await expect(call).rejects.toBeInstanceOf(DatabaseWorkerError);
  });

  test("calls after a worker crash reject at once", async () => {
    const { port, posted } = fakeWorker();
    const client = createDatabaseClient(port, true);
    port.onerror!({ message: "injected crash" } as ErrorEvent);
    // Nothing is posted to the dead worker; the call does not hang.
    const later = client.call("getAllDBUniqueRooms", []);
    expect(posted).toHaveLength(0);
    await expect(later).rejects.toBeInstanceOf(DatabaseWorkerError);
    await expect(later).rejects.toThrow("injected crash");
  });

  test("an unreadable reply fails the pending calls but not later ones", async () => {
    const { port, posted } = fakeWorker();
    const client = createDatabaseClient(port, true);
    const pending = client.call("getAllDBUniqueRooms", []);
    port.onmessageerror!({} as MessageEvent);
    await expect(pending).rejects.toBeInstanceOf(DatabaseWorkerError);
    const later = client.call("getAllDBUniqueRooms", []);
    expect(posted).toHaveLength(2);
    port.onmessage!({ data: { id: 2, result: [] } } as MessageEvent);
    expect(await later).toEqual([]);
  });
});
