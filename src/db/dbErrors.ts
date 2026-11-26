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

/**
 * A storage operation failed and left its work undone (a received file not
 * removed). `cause` is the original error. When one call covered several
 * items (a room's messages, a purge's steps), `failures` holds each item's
 * error; otherwise it holds the one error.
 */
export class StorageFailedError extends Error {
  readonly code = STORAGE_FAILED;
  readonly failures: readonly unknown[];

  constructor(
    message: string,
    options: { cause?: unknown; failures?: readonly unknown[] } = {},
  ) {
    super(message, "cause" in options ? { cause: options.cause } : undefined);
    this.name = "StorageFailedError";
    this.failures =
      options.failures ?? ("cause" in options ? [options.cause] : []);
  }
}

// Whether an error is, contains (as `errors` of an AggregateError, or as its
// `cause`) or reports (a serialized error carrying the code) a storage
// failure.
const holdsStorageFailure = (error: unknown, depth = 0): boolean => {
  if (depth > 4 || error === null || typeof error !== "object") return false;
  if ((error as { code?: unknown }).code === STORAGE_FAILED) return true;
  if (error instanceof AggregateError)
    return error.errors.some((inner) => holdsStorageFailure(inner, depth + 1));
  return holdsStorageFailure((error as { cause?: unknown }).cause, depth + 1);
};

/**
 * One typed error for a call whose work included removing received files: a
 * StorageFailedError when any part of `error` is a storage failure (the
 * original as `cause`, each item's failure in `failures`), else `error`.
 */
export const asStorageFailure = (error: unknown, message: string): unknown => {
  if (error instanceof StorageFailedError) return error;
  if (!holdsStorageFailure(error)) return error;
  return new StorageFailedError(message, {
    cause: error,
    failures: error instanceof AggregateError ? [...error.errors] : [error],
  });
};
