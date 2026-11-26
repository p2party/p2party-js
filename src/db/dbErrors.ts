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
