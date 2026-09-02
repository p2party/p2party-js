export type SignalingPeerRequestKind = "join" | "empty-roster" | "redial";

/**
 * Bounds repeated peer-list requests only within one socket lifecycle.
 *
 * A reconnect must never inherit the previous socket's timestamp: the first
 * post-proof request is what rebuilds all WebRTC edges after teardown.
 */
export class SignalingPeerRequestDebouncer {
  readonly #lastRequests = new Map<string, number>();

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
    this.#lastRequests.clear();
  }
}

export const signalingPeerRequestDebouncer =
  new SignalingPeerRequestDebouncer();
