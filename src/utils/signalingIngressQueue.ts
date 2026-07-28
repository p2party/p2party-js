export const MAX_SIGNALING_INGRESS_BACKLOG = 128;
export const MAX_SIGNALING_INGRESS_BYTES = 2 * 1024 * 1024;
const MAX_HEARTBEAT_SERIALIZED_CHARS = 32;

export type SignalingHeartbeatKind = "raw" | "json";

/**
 * Heartbeats bypass protocol work so an ICE/IndexedDB operation cannot make a
 * healthy client miss the server timeout. Parsing is restricted to a tiny
 * input and the JSON form must be exactly `{type:"ping"}`.
 */
export const classifySignalingHeartbeat = (
  data: unknown,
): SignalingHeartbeatKind | null => {
  if (data === "PING") return "raw";
  if (
    typeof data !== "string" ||
    data.length === 0 ||
    data.length > MAX_HEARTBEAT_SERIALIZED_CHARS
  )
    return null;
  if ((data.match(/"type"\s*:/g) ?? []).length !== 1) return null;
  try {
    const parsed = JSON.parse(data) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      Object.getPrototypeOf(parsed) !== Object.prototype
    )
      return null;
    const record = parsed as Record<string, unknown>;
    return Object.keys(record).length === 1 && record.type === "ping"
      ? "json"
      : null;
  } catch {
    return null;
  }
};

export interface SignalingHeartbeatResponders {
  readonly raw: () => void;
  readonly json: () => void;
}

/** Answer one exact heartbeat synchronously; return false for protocol data. */
export const answerImmediateSignalingHeartbeat = (
  data: unknown,
  responders: SignalingHeartbeatResponders,
): boolean => {
  const heartbeat = classifySignalingHeartbeat(data);
  if (heartbeat === null) return false;
  responders[heartbeat]();
  return true;
};

export interface SignalingIngressQueueOptions {
  readonly maxPending?: number;
  readonly maxPendingBytes?: number;
  readonly onOverflow: () => void;
  readonly onTaskError?: (error: unknown) => void;
}

/**
 * Synchronously revocable ownership for handlers already running on a socket.
 * Closing a WebSocket is asynchronous, so exact-socket identity alone remains
 * true until `close`; this lease makes overflow/oversize rejection immediate.
 */
export class SignalingSocketIngressLease {
  #active = true;

  isCurrent(ownsSocket: () => boolean): boolean {
    return this.#active && ownsSocket();
  }

  invalidate(): void {
    this.#active = false;
  }
}

/**
 * A socket-local, bounded FIFO for signaling frames.
 *
 * WebSocket EventTarget ignores promises returned by `onmessage`; assigning an
 * async handler therefore starts unbounded concurrent protocol and IndexedDB
 * work. This queue preserves wire order and closes admission before invoking
 * the overflow callback, so a synchronous burst cannot schedule more work
 * while the socket close handshake is in flight.
 */
export class SignalingIngressQueue {
  readonly #maxPending: number;
  readonly #maxPendingBytes: number;
  readonly #onOverflow: () => void;
  readonly #onTaskError: (error: unknown) => void;
  #tail: Promise<void> = Promise.resolve();
  #pending = 0;
  #pendingBytes = 0;
  #closed = false;

  constructor(options: SignalingIngressQueueOptions) {
    const maxPending = options.maxPending ?? MAX_SIGNALING_INGRESS_BACKLOG;
    if (!Number.isSafeInteger(maxPending) || maxPending < 1)
      throw new Error("Signaling ingress capacity must be a positive integer");
    const maxPendingBytes =
      options.maxPendingBytes ?? MAX_SIGNALING_INGRESS_BYTES;
    if (!Number.isSafeInteger(maxPendingBytes) || maxPendingBytes < 1)
      throw new Error(
        "Signaling ingress byte capacity must be a positive integer",
      );
    this.#maxPending = maxPending;
    this.#maxPendingBytes = maxPendingBytes;
    this.#onOverflow = options.onOverflow;
    this.#onTaskError = options.onTaskError ?? (() => undefined);
  }

  get pendingCount(): number {
    return this.#pending;
  }

  get pendingBytes(): number {
    return this.#pendingBytes;
  }

  get isClosed(): boolean {
    return this.#closed;
  }

  enqueue(task: () => void | Promise<void>, byteLength = 1): boolean {
    if (!Number.isSafeInteger(byteLength) || byteLength < 0)
      throw new Error("Signaling ingress weight must be a nonnegative integer");
    if (this.#closed) return false;
    if (
      this.#pending >= this.#maxPending ||
      this.#pendingBytes + byteLength > this.#maxPendingBytes
    ) {
      this.#closed = true;
      try {
        this.#onOverflow();
      } catch (error) {
        this.#reportTaskError(error);
      }
      return false;
    }

    this.#pending += 1;
    this.#pendingBytes += byteLength;
    const run = this.#tail.then(async () => {
      if (!this.#closed) await task();
    });
    this.#tail = run
      .catch((error: unknown) => {
        this.#reportTaskError(error);
      })
      .finally(() => {
        this.#pending -= 1;
        this.#pendingBytes -= byteLength;
      });
    return true;
  }

  close(): void {
    this.#closed = true;
  }

  #reportTaskError(error: unknown): void {
    try {
      this.#onTaskError(error);
    } catch {
      // Diagnostics must never break the queue or create an unhandled tail.
    }
  }
}
