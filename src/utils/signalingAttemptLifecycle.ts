import { AsyncMutex } from "./mutex";

export interface SignalingAttempt {
  readonly token: symbol;
  readonly cancelled: Promise<void>;
}

/**
 * SSOT for socket-attempt ownership, prompt cancellation, and serialized
 * identity bootstrap. Cancellation settles independently of a blocked
 * IndexedDB/crypto operation; the bootstrap lock remains held until that
 * operation unwinds, so its replacement cannot race identity mutation.
 */
export class SignalingAttemptLifecycle {
  private activeToken: symbol | null = null;
  private cancelCurrent: (() => void) | null = null;
  private identityPurgeRequests = 0;
  private readonly bootstrapMutex = new AsyncMutex();

  begin(label: string): SignalingAttempt {
    if (this.identityPurgeRequests > 0)
      throw new Error("Identity purge is in progress");
    const token = Symbol(label);
    let cancel!: () => void;
    const cancelled = new Promise<void>((resolve) => {
      cancel = resolve;
    });
    this.activeToken = token;
    this.cancelCurrent = cancel;
    return { token, cancelled };
  }

  isCurrent(token: symbol): boolean {
    return this.activeToken === token;
  }

  hasActiveAttempt(): boolean {
    return this.activeToken !== null;
  }

  assertCurrent(token: symbol): void {
    if (!this.isCurrent(token))
      throw new Error("WebSocket connection attempt was cancelled");
  }

  addCancellationEffect(token: symbol, effect: () => void): boolean {
    if (!this.isCurrent(token)) return false;
    const cancel = this.cancelCurrent;
    this.cancelCurrent = () => {
      cancel?.();
      effect();
    };
    return true;
  }

  disarmCancellation(token: symbol): boolean {
    if (!this.isCurrent(token)) return false;
    this.cancelCurrent = null;
    return true;
  }

  clear(token: symbol): boolean {
    if (!this.isCurrent(token)) return false;
    this.activeToken = null;
    this.cancelCurrent = null;
    return true;
  }

  cancelActive(): void {
    const cancel = this.cancelCurrent;
    this.activeToken = null;
    this.cancelCurrent = null;
    cancel?.();
  }

  isIdentityPurgeActive(): boolean {
    return this.identityPurgeRequests > 0;
  }

  async acquireBootstrap(token: symbol): Promise<() => void> {
    await this.bootstrapMutex.acquire();
    try {
      this.assertCurrent(token);
    } catch (error) {
      this.bootstrapMutex.release();
      throw error;
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.bootstrapMutex.release();
    };
  }

  /**
   * Cancel any socket/bootstrap attempt, then enter the same exclusive
   * identity boundary used by bootstrap. Purge uses this so no cancelled
   * bootstrap can persist or dispatch an identity after deletion.
   */
  async cancelAndAcquireBootstrap(): Promise<() => void> {
    this.identityPurgeRequests += 1;
    this.cancelActive();
    try {
      await this.bootstrapMutex.acquire();
    } catch (error) {
      this.identityPurgeRequests -= 1;
      throw error;
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.bootstrapMutex.release();
      this.identityPurgeRequests -= 1;
    };
  }
}

export const signalingAttemptLifecycle = new SignalingAttemptLifecycle();
