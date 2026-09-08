export type SignalingPeerRequestKind =
  "join" | "empty-roster" | "redial" | "reconcile";

/**
 * Bounds repeated peer-list requests only within one socket lifecycle.
 *
 * A reconnect must never inherit the previous socket's timestamp: the first
 * post-proof request is what rebuilds all WebRTC edges after teardown.
 */
export class SignalingPeerRequestDebouncer {
  readonly #lastRequests = new Map<string, number>();
  readonly #trailing = new Map<
    string,
    { timer: ReturnType<typeof setTimeout>; send: () => void }
  >();
  readonly #rosterRequests = new Map<string, string>();
  #supportsRosterSnapshots = false;

  get supportsRosterSnapshots(): boolean {
    return this.#supportsRosterSnapshots;
  }
  confirmRosterSnapshots(): void {
    this.#supportsRosterSnapshots = true;
  }

  constructor(
    private readonly clock = {
      now: () => Date.now(),
      setTimeout: (callback: () => void, ms: number) =>
        setTimeout(callback, ms),
      clearTimeout: (timer: ReturnType<typeof setTimeout>) =>
        clearTimeout(timer),
    },
  ) {}

  /** Coalesce a burst, but never lose its final redial. The callback rechecks admission. */
  request(
    kind: SignalingPeerRequestKind,
    roomId: string,
    intervalMs: number,
    send: () => void,
  ): void {
    const key = `${kind}:${roomId}`;
    const now = this.clock.now();
    if (this.shouldSend(kind, roomId, intervalMs, now)) {
      const pending = this.#trailing.get(key);
      if (pending) this.clock.clearTimeout(pending.timer);
      this.#trailing.delete(key);
      send();
      return;
    }
    const pending = this.#trailing.get(key);
    if (pending) {
      pending.send = send;
      return;
    }
    const entry = {
      send,
      timer: this.clock.setTimeout(
        () => {
          if (this.#trailing.get(key) !== entry) return;
          this.#trailing.delete(key);
          this.#lastRequests.set(key, this.clock.now());
          try {
            entry.send();
          } catch (error) {
            console.error("p2party: deferred peer discovery failed", error);
          }
        },
        Math.max(1, intervalMs - (now - this.#lastRequests.get(key)!)),
      ),
    };
    this.#trailing.set(key, entry);
  }

  beginRosterRequest(roomId: string): string {
    const requestId = crypto.randomUUID();
    this.#rosterRequests.set(roomId, requestId);
    return requestId;
  }

  isCurrentRosterRequest(roomId: string, requestId: unknown): boolean {
    return (
      typeof requestId === "string" &&
      this.#rosterRequests.get(roomId) === requestId
    );
  }

  completeRosterRequest(roomId: string, requestId: unknown): boolean {
    if (!this.isCurrentRosterRequest(roomId, requestId)) return false;
    this.#rosterRequests.delete(roomId);
    return true;
  }

  cancelRoom(roomId: string): void {
    this.#rosterRequests.delete(roomId);
    for (const kind of [
      "join",
      "empty-roster",
      "redial",
      "reconcile",
    ] as const) {
      const key = `${kind}:${roomId}`;
      this.#lastRequests.delete(key);
      const pending = this.#trailing.get(key);
      if (pending) this.clock.clearTimeout(pending.timer);
      this.#trailing.delete(key);
    }
  }

  shouldSend(
    kind: SignalingPeerRequestKind,
    roomId: string,
    minimumIntervalMs: number,
    now = Date.now(),
  ): boolean {
    const key = `${kind}:${roomId}`;
    const lastRequest = this.#lastRequests.get(key);
    if (lastRequest !== undefined && now - lastRequest < minimumIntervalMs)
      return false;
    this.#lastRequests.set(key, now);
    return true;
  }

  resetSocketLifecycle(): void {
    this.#supportsRosterSnapshots = false;
    for (const pending of this.#trailing.values())
      this.clock.clearTimeout(pending.timer);
    this.#trailing.clear();
    this.#rosterRequests.clear();
    this.#lastRequests.clear();
  }
}

export const signalingPeerRequestDebouncer =
  new SignalingPeerRequestDebouncer();
