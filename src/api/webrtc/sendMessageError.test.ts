import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * `MessageTransferHandle.done` documents that it rejects with a
 * MessageDeliveryError carrying per-peer outcomes, and the README tells callers
 * to check `error instanceof p2party.MessageDeliveryError`.
 *
 * That is only true if the error is RETURNED from the queryFn. RTK Query
 * serializes anything that throws out of one: `unwrap()` then rethrows
 * `action.error`, a plain object, so the instanceof check is false and
 * `.result` is gone. Verified against RTK directly — a throwing queryFn yields
 * `ctor=Object, instanceof=false, .result=undefined`; returning `{ error }`
 * yields the real instance.
 *
 * Structural, because reaching the live path needs WASM, a signaling socket and
 * a peer.
 */

const queryPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "sendMessageQuery.ts",
);
const source = readFileSync(queryPath, "utf8");

describe("send failures reach the caller as a usable error", () => {
  test("MessageDeliveryError is returned, never allowed to escape", () => {
    expect(source).toContain("if (error instanceof MessageDeliveryError)");
    expect(source).toContain("return { error }");
  });

  test("the query imports the class it narrows on", () => {
    // A structural check that narrows on a name it never imported would compile
    // to `undefined` and silently never match.
    expect(source).toMatch(
      /import\s*\{[\s\S]*MessageDeliveryError[\s\S]*\}\s*from\s*"\.\.\/\.\.\/handlers\/handleSendMessage"/,
    );
  });

  test("other errors still propagate", () => {
    // Swallowing everything would hide programming errors as silent successes.
    expect(source).toContain("throw error;");
  });
});
