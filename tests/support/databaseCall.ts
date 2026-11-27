import { expect } from "bun:test";
import {
  useDatabaseWorkerForTests,
  type DatabaseWorkerPort,
} from "../../src/db/api";

/** Observe one real DB client's outbound request during a test of a module stand-in. */
export async function expectDatabaseCall(
  method: string,
  args: unknown[],
  operation: () => Promise<unknown>,
): Promise<void> {
  const sent: unknown[] = [];
  const port: DatabaseWorkerPort = {
    onmessage: null,
    onerror: null,
    onmessageerror: null,
    postMessage(message) {
      const request = message as {
        id: number;
        method: string;
        args: unknown[];
      };
      sent.push({ method: request.method, args: request.args });
      port.onmessage?.(
        new MessageEvent("message", {
          data: { id: request.id, result: undefined },
        }),
      );
    },
  };
  const restore = useDatabaseWorkerForTests(port);
  try {
    await operation();
    expect(sent).toEqual([{ method, args }]);
  } finally {
    restore();
  }
}
