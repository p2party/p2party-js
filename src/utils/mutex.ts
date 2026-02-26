/**
 * A simple async mutex for serializing access to shared resources.
 *
 * In this codebase, shared WebAssembly.Memory objects back WASM module
 * instances used across async operations. Because JavaScript is
 * single-threaded, synchronous WASM calls between `await` points are
 * atomic. However, multiple async operations (e.g. concurrent RTK Query
 * mutations) can interleave at `await` boundaries, leading to
 * corruption of the shared linear memory (overlapping _malloc regions,
 * stale ArrayBuffer views after memory growth, etc.).
 *
 * Wrapping the critical section with this mutex ensures only one async
 * operation accesses the shared WASM memory at a time.
 */
export class AsyncMutex {
  private queue: (() => void)[] = [];
  private locked = false;

  async acquire(): Promise<void> {
    if (!this.locked) {
      this.locked = true;
      return;
    }

    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    const next = this.queue.shift();
    if (next) {
      // Hand the lock directly to the next waiter without unlocking,
      // preventing queue-jumping.
      next();
    } else {
      this.locked = false;
    }
  }

  async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}
