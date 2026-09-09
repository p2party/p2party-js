import { describe, expect, test } from "bun:test";

import { SignalingAttemptLifecycle } from "../../src/utils/signalingAttemptLifecycle";

describe("signaling attempt lifecycle", () => {
  test("cancelled A settles promptly while its bootstrap keeps B serialized and cannot clear B", async () => {
    const lifecycle = new SignalingAttemptLifecycle();
    const attemptA = lifecycle.begin("A");
    const releaseA = await lifecycle.acquireBootstrap(attemptA.token);

    lifecycle.cancelActive();
    const attemptB = lifecycle.begin("B");
    let bEntered = false;
    const enterB = lifecycle
      .acquireBootstrap(attemptB.token)
      .then((release) => {
        bEntered = true;
        return release;
      });

    // Cancellation must not wait for A to relinquish the bootstrap lock.
    await attemptA.cancelled;
    await Promise.resolve();
    expect(bEntered).toBe(false);

    releaseA();
    const releaseB = await enterB;
    expect(bEntered).toBe(true);
    expect(lifecycle.clear(attemptA.token)).toBe(false);
    expect(lifecycle.isCurrent(attemptB.token)).toBe(true);
    releaseB();
    expect(lifecycle.clear(attemptB.token)).toBe(true);
  });

  test("socket-phase cancellation runs the bootstrap settlement and exact-socket effect once", async () => {
    const lifecycle = new SignalingAttemptLifecycle();
    const attempt = lifecycle.begin("socket");
    let socketCancels = 0;
    expect(
      lifecycle.addCancellationEffect(attempt.token, () => {
        socketCancels += 1;
      }),
    ).toBe(true);

    lifecycle.cancelActive();
    lifecycle.cancelActive();
    await attempt.cancelled;
    expect(socketCancels).toBe(1);
  });

  test("purge waits for an in-flight bootstrap and rejects later bootstrap until identity deletion finishes", async () => {
    const lifecycle = new SignalingAttemptLifecycle();
    const attemptA = lifecycle.begin("A");
    const releaseA = await lifecycle.acquireBootstrap(attemptA.token);

    let purgeEntered = false;
    const enterPurge = lifecycle.cancelAndAcquireBootstrap().then((release) => {
      purgeEntered = true;
      return release;
    });
    await attemptA.cancelled;
    await Promise.resolve();
    expect(purgeEntered).toBe(false);

    releaseA();
    const releasePurge = await enterPurge;
    expect(purgeEntered).toBe(true);

    expect(lifecycle.isIdentityPurgeActive()).toBe(true);
    expect(() => lifecycle.begin("B-during-purge")).toThrow(
      "Identity purge is in progress",
    );

    releasePurge();
    expect(lifecycle.isIdentityPurgeActive()).toBe(false);
    const attemptB = lifecycle.begin("B-after-purge");
    const releaseB = await lifecycle.acquireBootstrap(attemptB.token);
    releaseB();
  });
});
