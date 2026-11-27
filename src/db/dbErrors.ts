// Errors meaning the database as a whole cannot serve requests, as opposed to
// one request being refused. Shared by the worker and its main-thread client,
// so this module imports nothing.

/** The database cannot serve requests at all. */
export class DatabaseUnavailableError extends Error {}

/** The database worker stopped: it failed, or one of its replies was unreadable. */
export class DatabaseWorkerError extends DatabaseUnavailableError {
  constructor(message: string) {
    super(message);
    this.name = "DatabaseWorkerError";
  }
}

/**
 * A Merkle root or whole-file hash passed to `deleteMessage` or
 * `cancelMessage` is not in a form the SDK accepts: the 128 lower-case
 * hexadecimal characters the SDK reports it as, or the 64 bytes those
 * encode. Nothing was looked up or changed. `argument` says which one.
 */
export class InvalidMessageHashError extends Error {
  readonly code = "invalid-message-hash";

  constructor(readonly argument: "merkleRoot" | "hash") {
    super(
      `p2party: invalid ${argument === "merkleRoot" ? "Merkle root" : "hash"}: ` +
        "expected 128 lower-case hexadecimal characters or 64 bytes",
    );
    this.name = "InvalidMessageHashError";
  }
}

export class InvalidTransferIdError extends Error {
  readonly code = "invalid-transfer-id";
  constructor() {
    super("Invalid transfer ID");
    this.name = "InvalidTransferIdError";
  }
}

export class MissingMessageIdentifierError extends Error {
  readonly code = "missing-message-identifier";
  constructor() {
    super("Need to provide a transfer ID, Merkle root, or hash");
    this.name = "MissingMessageIdentifierError";
  }
}

export const DATABASE_UPGRADE_BLOCKED = "database-upgrade-blocked";

/**
 * This version's database upgrade is blocked by another open tab of this site
 * running an older version, which keeps its connection open. Close the other
 * tabs of this site and reload.
 */
export class DatabaseUpgradeBlockedError extends DatabaseUnavailableError {
  readonly code = DATABASE_UPGRADE_BLOCKED;

  constructor() {
    super(
      "p2party: another open tab of this site is using an older version of " +
        "its database; close the other tabs and reload",
    );
    this.name = "DatabaseUpgradeBlockedError";
  }
}

export const STORAGE_FAILED = "storage-failed";

/** One received file a removal left on disk. */
export interface FileRemovalFailure {
  /**
   * The file: its message's Merkle root in hex, which is also its name in the
   * SDK's directory of the origin private file system. Empty when the failure
   * is the directory's (it could not be listed or removed).
   */
  readonly merkleRootHex: string;
  /** What the browser threw, with its own `name` and `message`. */
  readonly error: Error;
}

/**
 * A removal left a received file on disk: the browser refused to remove it.
 * - `failures` lists every file that is still there, each with the browser's
 *   error for it (an `Error` with the `name` and `message` the browser
 *   threw).
 * - `cause` is the browser's error itself when the call was for one message
 *   (deleteMessage, cancelMessage). For a call that covers several messages
 *   or steps (disconnectFromRoom, disconnectFromAllRooms, purgeRoom, purge)
 *   it is what those steps threw, usually an AggregateError; each file's own
 *   error is in `failures`.
 * Both hold on the page for an error raised in the database worker. An
 * error's class, cause and fields do not survive the worker boundary, so the
 * worker sends each file's root and the name and message of the browser's
 * error as data (SerializedStorageFailure) and the client rebuilds them. The
 * rebuilt errors are plain `Error`s carrying that name and message, not the
 * browser's own DOMException objects.
 */
export class StorageFailedError extends Error {
  readonly code = STORAGE_FAILED;
  readonly failures: readonly FileRemovalFailure[];

  constructor(
    message: string,
    options: { cause?: unknown; failures?: readonly FileRemovalFailure[] } = {},
  ) {
    super(message, "cause" in options ? { cause: options.cause } : undefined);
    this.name = "StorageFailedError";
    this.failures = options.failures ?? [];
  }
}

/** A browser error as it crosses the worker boundary: its name and message. */
export interface SerializedError {
  readonly name: string;
  readonly message: string;
}

/** A StorageFailedError as the worker posts it to its client. */
export interface SerializedStorageFailure {
  readonly message: string;
  readonly cause?: SerializedError;
  readonly failures: ReadonlyArray<
    { readonly merkleRootHex: string } & SerializedError
  >;
}

export const serializeError = (error: unknown): SerializedError => {
  const named = error as { name?: unknown; message?: unknown } | null;
  return {
    name: typeof named?.name === "string" ? named.name : "Error",
    message: typeof named?.message === "string" ? named.message : String(error),
  };
};

/** An Error carrying the name and message of the one that was thrown. */
export const rebuildError = ({ name, message }: SerializedError): Error => {
  const error = new Error(message);
  error.name = name;
  return error;
};

export const serializeStorageFailure = (
  error: StorageFailedError,
): SerializedStorageFailure => ({
  message: error.message,
  ...(error.cause === undefined ? {} : { cause: serializeError(error.cause) }),
  failures: error.failures.map((failure) => ({
    merkleRootHex: failure.merkleRootHex,
    ...serializeError(failure.error),
  })),
});

export const rebuildStorageFailure = (
  detail: SerializedStorageFailure,
): StorageFailedError =>
  new StorageFailedError(detail.message, {
    ...(detail.cause === undefined
      ? {}
      : { cause: rebuildError(detail.cause) }),
    failures: detail.failures.map((failure) => ({
      merkleRootHex: failure.merkleRootHex,
      error: rebuildError(failure),
    })),
  });

/** A StorageFailedError for the files a removal left on disk. */
export const filesNotRemoved = (
  failures: readonly FileRemovalFailure[],
  what = "p2party: could not remove",
): StorageFailedError =>
  new StorageFailedError(
    failures.length === 1
      ? `${what} the received file ${failures[0].merkleRootHex}: ${String(failures[0].error)}`
      : `${what} ${String(failures.length)} received files (listed in failures)`,
    {
      cause:
        failures.length === 1
          ? failures[0].error
          : new AggregateError(
              failures.map((failure) => failure.error),
              "Received files were not removed",
            ),
      failures,
    },
  );

// Every StorageFailedError in an error: itself, the `errors` of an
// AggregateError, or its `cause`, in order.
const storageFailuresIn = (error: unknown, depth = 0): StorageFailedError[] => {
  if (depth > 4 || error === null || typeof error !== "object") return [];
  if (error instanceof StorageFailedError) return [error];
  if (error instanceof AggregateError)
    return error.errors.flatMap((inner) => storageFailuresIn(inner, depth + 1));
  return storageFailuresIn((error as { cause?: unknown }).cause, depth + 1);
};

// Whether an error is or contains one that only reports a storage failure: a
// serialized error that kept the code and lost its class and its files.
const reportsStorageFailure = (error: unknown, depth = 0): boolean => {
  if (depth > 4 || error === null || typeof error !== "object") return false;
  if ((error as { code?: unknown }).code === STORAGE_FAILED) return true;
  if (error instanceof AggregateError)
    return error.errors.some((inner) =>
      reportsStorageFailure(inner, depth + 1),
    );
  return reportsStorageFailure((error as { cause?: unknown }).cause, depth + 1);
};

/**
 * One typed error for a call whose work included removing received files: a
 * StorageFailedError when any part of `error` is a storage failure (the
 * original as `cause`; in `failures`, every file any part names), else
 * `error`.
 */
export const asStorageFailure = (error: unknown, message: string): unknown => {
  if (error instanceof StorageFailedError) return error;
  if (!reportsStorageFailure(error)) return error;
  return new StorageFailedError(message, {
    cause: error,
    failures: storageFailuresIn(error).flatMap((failure) => failure.failures),
  });
};
