import { AsyncMutex } from "./mutex";

/**
 * One invocation-order boundary for signaling joins, disconnects, and purges.
 *
 * A join places all awaited prework inside this boundary. A later terminal
 * action therefore runs after it and owns the final state; a later invalid
 * join never cancels an earlier valid one before its own validation succeeds.
 */
export class SignalingRoomOperationLifecycle {
  readonly #mutex = new AsyncMutex();

  runJoin<T>(operation: () => Promise<T>): Promise<T> {
    return this.#mutex.runExclusive(operation);
  }

  runRoomTerminal<T>(
    _roomUrl: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    return this.#mutex.runExclusive(operation);
  }

  runGlobalTerminal<T>(operation: () => Promise<T>): Promise<T> {
    return this.#mutex.runExclusive(operation);
  }
}

export const signalingRoomOperationLifecycle =
  new SignalingRoomOperationLifecycle();
