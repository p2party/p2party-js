import type {
  FileRemovalNotice,
  FileRemovalRetryScope,
  HeldFileProgressNotice,
  HeldFileSettledNotice,
  ReceiveDeleteGuard,
  RoomMessageLoadOptions,
} from "./types";
import type { OutboxLease, OutboxRequest } from "./outboxTypes";
import type {
  WorkerMessages,
  Chunk,
  ReceiveChunk,
  NewChunk,
  NewChunkSelector,
  SendQueue,
  RatchetSession,
  IdentityDerivation,
  IdentityEd25519KeyMaterial,
  IdentityX25519,
} from "./types";
import {
  DATABASE_UPGRADE_BLOCKED,
  DatabaseUpgradeBlockedError,
  DatabaseWorkerError,
  STORAGE_FAILED,
  StorageFailedError,
  rebuildStorageFailure,
} from "./dbErrors";
import type { SerializedStorageFailure } from "./dbErrors";
import { MAX_REPORTED_RECEIVE_STORAGE_ERRORS } from "../utils/constants";
import {
  readIdentityEd25519AtClientBoundary,
  wipeUnclaimedWorkerSecret,
  writeIdentityEd25519AtClientBoundary,
} from "./identityEd25519ClientBoundary";
// import type { MessageType } from "../utils/messageTypes";

// Notices the worker posts outside any request: a held file it verified on
// its own at the next start (see verifyHeldFileAtStart in db.worker.ts).
const heldFileListeners = new Set<(notice: HeldFileSettledNotice) => void>();
export const onHeldFileSettled = (
  listener: (notice: HeldFileSettledNotice) => void,
): (() => void) => {
  heldFileListeners.add(listener);
  return () => {
    heldFileListeners.delete(listener);
  };
};

// Progress the worker reports while it verifies a held file.
const progressListeners = new Set<(notice: HeldFileProgressNotice) => void>();
export const onVerificationProgress = (
  listener: (notice: HeldFileProgressNotice) => void,
): (() => void) => {
  progressListeners.add(listener);
  return () => {
    progressListeners.delete(listener);
  };
};

// ── A received file the browser refused to remove ──────────────────────────
// One refusal reaches the application once, by one route:
//   - a call the application made to delete rejects with it. While that call
//     runs it answers for its file (answeringForRemoval): every other attempt
//     to remove the same file that the call sets off is part of it, and
//     raises nothing of its own;
//   - a removal the SDK started itself is announced to the listeners below,
//     once per file until the page sees that file removed, or a chunk of it
//     stored again. The SDK raises it as the "not-removed" storage error.

const fileRemovalListeners = new Set<(notice: FileRemovalNotice) => void>();
const announcedNotRemoved = new Set<string>();
const removalAnswers = new Map<
  string,
  { callers: number; failure?: StorageFailedError }
>();

/** Hear of each file a removal started by the SDK left on disk. */
export const onFileNotRemoved = (
  listener: (notice: FileRemovalNotice) => void,
): (() => void) => {
  fileRemovalListeners.add(listener);
  return () => {
    fileRemovalListeners.delete(listener);
  };
};

/**
 * Announce a file a removal left on disk, unless a call of the application
 * answers for it or it was announced already.
 */
export const announceFileNotRemoved = (notice: FileRemovalNotice): void => {
  if (removalAnswers.has(notice.merkleRoot)) return;
  if (announcedNotRemoved.has(notice.merkleRoot)) return;
  if (announcedNotRemoved.size >= MAX_REPORTED_RECEIVE_STORAGE_ERRORS)
    announcedNotRemoved.clear();
  announcedNotRemoved.add(notice.merkleRoot);
  for (const listener of fileRemovalListeners) listener(notice);
};

/**
 * Run a call the application made to delete one file's message. Until `run`
 * settles, a refusal to remove that file, from whichever attempt inside the
 * call, is kept instead of being thrown or announced. The call's last attempt
 * decides: if that one was refused, the call rejects with it once, after
 * everything else in `run` was done.
 */
export const answeringForRemoval = async <T>(
  merkleRootHex: string,
  run: () => Promise<T>,
): Promise<T> => {
  const answer = removalAnswers.get(merkleRootHex) ?? { callers: 0 };
  answer.callers += 1;
  removalAnswers.set(merkleRootHex, answer);
  let value: T;
  try {
    value = await run();
  } finally {
    answer.callers -= 1;
    if (answer.callers === 0) removalAnswers.delete(merkleRootHex);
  }
  if (answer.failure) throw answer.failure;
  return value;
};

/** The part of a Worker the database client uses. */
export interface DatabaseWorkerPort {
  postMessage(message: unknown, transfer: Transferable[]): void;
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  onmessageerror: ((event: MessageEvent) => void) | null;
}

// An error's class, cause and fields do not survive the worker boundary, so
// the worker sends a storage failure's parts as data and they are put back
// together here: `cause` is an Error with the browser's name and message, and
// `failures` names each file.
const typedWorkerError = (
  error: unknown,
  errorCode?: string,
  errorDetail?: SerializedStorageFailure,
): unknown =>
  errorCode === DATABASE_UPGRADE_BLOCKED
    ? new DatabaseUpgradeBlockedError()
    : errorCode === STORAGE_FAILED
      ? errorDetail
        ? rebuildStorageFailure(errorDetail)
        : new StorageFailedError(String(error))
      : error;

/**
 * The request/reply client over the database worker. A pending call is only
 * drained by a reply carrying its id, so anything that kills the worker (a
 * module-load failure, a structured-clone failure posting a large chunk, an
 * OOM) would otherwise leave every in-flight call unsettled forever. After the
 * worker fails, every pending and every later call rejects at once with
 * DatabaseWorkerError; the worker is not restarted (the application reloads).
 */
export const createDatabaseClient = (
  worker: DatabaseWorkerPort,
  bundled: boolean,
) => {
  let msgId = 0;
  let failed: DatabaseWorkerError | undefined;
  const pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (reason?: unknown) => void }
  >();
  const rejectAllPending = (reason: Error): void => {
    const inFlight = [...pending.values()];
    pending.clear();
    for (const p of inFlight) p.reject(reason);
  };

  worker.onmessage = (e: MessageEvent) => {
    const { notice, progress, removal } = e.data as {
      notice?: HeldFileSettledNotice;
      progress?: HeldFileProgressNotice;
      removal?: FileRemovalNotice;
    };
    if (notice) {
      for (const listener of heldFileListeners) listener(notice);
      return;
    }
    if (progress) {
      for (const listener of progressListeners) listener(progress);
      return;
    }
    if (removal) {
      announceFileNotRemoved(removal);
      return;
    }
    const { id, result, error, errorCode, errorDetail } = e.data as {
      id: number;
      result: unknown;
      error: unknown;
      errorCode?: string;
      errorDetail?: SerializedStorageFailure;
    };
    const p = pending.get(id);
    if (!p) {
      // A worker-wide error may already have rejected and removed this call.
      // Explicitly retire any late transferred identity secret instead of
      // leaving its lifetime to garbage collection.
      wipeUnclaimedWorkerSecret(result);
      return;
    }
    pending.delete(id);
    if (error) p.reject(typedWorkerError(error, errorCode, errorDetail));
    else p.resolve(result);
  };

  worker.onerror = (event: ErrorEvent) => {
    failed = new DatabaseWorkerError(
      `p2party: the database worker failed: ${event.message || "unknown error"}`,
    );
    rejectAllPending(failed);
  };

  worker.onmessageerror = () => {
    rejectAllPending(
      new DatabaseWorkerError(
        "p2party: a database worker message could not be deserialized",
      ),
    );
  };

  const call = (
    method: WorkerMessages["method"],
    args: readonly unknown[],
    transfer: Transferable[] = [],
  ): Promise<unknown> =>
    new Promise((resolve, reject) => {
      // An empty bundle builds a worker that never replies, so the call would
      // hang rather than fail. Say why instead of stalling the caller.
      if (!bundled) {
        reject(
          new DatabaseWorkerError(
            `p2party: cannot run "${method}" — the database worker bundle is ` +
              "missing (INDEXEDDB_WORKER_JS was not inlined at build time).",
          ),
        );
        return;
      }
      if (failed) {
        reject(failed);
        return;
      }
      const id = ++msgId;
      pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      try {
        worker.postMessage({ id, method, args }, transfer);
      } catch (error) {
        pending.delete(id);
        reject(error);
      }
    });

  return { call };
};

const workerSrc = process.env.INDEXEDDB_WORKER_JS ?? "";
const workerBlob = new Blob([workerSrc], {
  type: "application/javascript",
});
let client = createDatabaseClient(
  new Worker(URL.createObjectURL(workerBlob), {
    type: "module",
  }) as unknown as DatabaseWorkerPort,
  workerSrc.length > 0,
);

/**
 * Test seam: send every database call to `port` (an in-process worker) until
 * the returned function is called. Not part of the package's public exports.
 */
export const useDatabaseWorkerForTests = (
  port: DatabaseWorkerPort,
): (() => void) => {
  const previous = client;
  client = createDatabaseClient(port, true);
  return () => {
    client = previous;
  };
};

const callWorkerOwned = (
  method: WorkerMessages["method"],
  args: readonly unknown[],
  transfer: Transferable[] = [],
): Promise<unknown> => client.call(method, args, transfer);

function callWorker<M extends WorkerMessages["method"]>(
  method: M,
  ...args: Extract<WorkerMessages, { method: M }>["args"]
): Promise<import("./types").WorkerMethodReturnTypes[M]> {
  return callWorkerOwned(method, args) as Promise<
    import("./types").WorkerMethodReturnTypes[M]
  >;
}

export const getDBAddressBookEntry = (
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("getDBAddressBookEntry", peerId, peerPublicKey);

export const getAllDBAddressBookEntries = () =>
  callWorker("getAllDBAddressBookEntries");

export const setDBAddressBookEntry = (
  username: string,
  peerId: string,
  peerPublicKey: string,
) => callWorker("setDBAddressBookEntry", username, peerId, peerPublicKey);

export const deleteDBAddressBookEntry = (
  username?: string,
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("deleteDBAddressBookEntry", username, peerId, peerPublicKey);

/**
 * Fails CLOSED. This is the sole admission gate on every connection path, and
 * an indeterminate answer must never be reported as "not blacklisted" — that
 * would let a storage fault silently readmit every blocked peer. The denial is
 * scoped to the one peer being checked, so a transient fault cannot lock the
 * whole room out.
 */
export const getDBPeerIsBlacklisted = async (
  peerId?: string,
  peerPublicKey?: string,
): Promise<boolean> => {
  try {
    return await callWorker("getDBPeerIsBlacklisted", peerId, peerPublicKey);
  } catch (error) {
    console.error(
      "p2party: blacklist lookup failed; treating this peer as blocked",
      error,
    );
    return true;
  }
};

export const getAllDBBlacklisted = () => callWorker("getAllDBBlacklisted");

export const setDBPeerInBlacklist = (peerId: string, peerPublicKey: string) =>
  callWorker("setDBPeerInBlacklist", peerId, peerPublicKey);

export const deleteDBPeerFromBlacklist = (
  peerId?: string,
  peerPublicKey?: string,
) => callWorker("deleteDBPeerFromBlacklist", peerId, peerPublicKey);

export const getAllDBUniqueRooms = () => callWorker("getAllDBUniqueRooms");

export const setDBUniqueRoom = (
  roomUrl: string,
  roomId: string,
  roomPolicy: ArrayBuffer,
) => callWorker("setDBUniqueRoom", roomUrl, roomId, roomPolicy);

export const getDBMessageData = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBMessageData", merkleRootHex, hashHex);

export const getDBRoomMessageData = (
  roomId: string,
  options?: RoomMessageLoadOptions,
) => callWorker("getDBRoomMessageData", roomId, options);

export const getDBRoomStats = (roomId: string) =>
  callWorker("getDBRoomStats", roomId);

export const setDBRoomMessageData = (
  roomId: string,
  merkleRootHex: string,
  sha512Hex: string,
  fromPeerId: string,
  chunkSize: number,
  totalSize: number,
  messageType: number, // MessageType,
  filename: string,
  channelLabel: string,
  timestamp: number,
  transferId?: string,
) =>
  callWorker(
    "setDBRoomMessageData",
    roomId,
    merkleRootHex,
    sha512Hex,
    fromPeerId,
    chunkSize,
    totalSize,
    messageType,
    filename,
    channelLabel,
    timestamp,
    transferId,
  );

export const getDBChunk = (merkleRootHex: string, chunkIndex: number) =>
  callWorker("getDBChunk", merkleRootHex, chunkIndex);

export const existsDBChunk = (merkleRootHex: string, chunkIndex: number) =>
  callWorker("existsDBChunk", merkleRootHex, chunkIndex);

export const getDBNewChunk = (transferId: string, chunkIndex: number) =>
  callWorker("getDBNewChunk", transferId, chunkIndex);

export const getDBNewChunkByReceipt = (
  merkleRootHex: string,
  receiptTokenHex: string,
) => callWorker("getDBNewChunkByReceipt", merkleRootHex, receiptTokenHex);

export const existsDBNewChunk = (transferId: string, chunkIndex: number) =>
  callWorker("existsDBNewChunk", transferId, chunkIndex);

export const getDBSendQueue = (label: string, toPeerId: string) =>
  callWorker("getDBSendQueue", label, toPeerId);

export const getDBAllChunks = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBAllChunks", merkleRootHex, hashHex);

export const getDBAllChunkLeafHashes = (merkleRootHex: string) =>
  callWorker("getDBAllChunkLeafHashes", merkleRootHex);

export const assembleToOPFS = (
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
) => callWorker("assembleToOPFS", merkleRootHex, totalSize, filename, mimeType);

export const getDBAllChunksCount = (merkleRootHex?: string, hashHex?: string) =>
  callWorker("getDBAllChunksCount", merkleRootHex, hashHex);

export const setDBChunk = (chunk: Chunk) => callWorker("setDBChunk", chunk);

// Atomic receive-time insert + progress: text stays in IndexedDB; file bytes go
// to OPFS at chunkIndex*uniformSize when possible. The worker returns whether
// this distinct index was inserted and the authoritative committed byte count,
// so a duplicate can never be mistaken for the completing chunk.
export const storeReceiveChunk = (chunk: ReceiveChunk) =>
  callWorker("storeReceiveChunk", chunk).then((result) => {
    // The transfer's file is in use again: a later refusal to remove it is a
    // new one, and is announced.
    if (result.failure === undefined)
      announcedNotRemoved.delete(chunk.merkleRoot);
    return result;
  });

// Hash a received file held pending verification (storeReceiveChunk returned
// `verification`) against its whole-file hash. Runs outside the per-file
// lock; the worker keeps serving other requests between reads. `holder`
// names the caller: several callers can hold one attempt, and each settles
// (or detaches from) it under its own name.
export const verifyReceivedFile = (
  merkleRootHex: string,
  token: string,
  holder: string,
) => callWorker("verifyReceivedFile", merkleRootHex, token, holder);

// Commit a verification's verdict (complete, or drop the file as failed) when
// `commit` is true; otherwise leave the file to be verified again by the next
// copy of its last chunk.
export const settleReceivedFileVerification = (
  merkleRootHex: string,
  token: string,
  commit: boolean,
  holder: string,
) =>
  callWorker(
    "settleReceivedFileVerification",
    merkleRootHex,
    token,
    commit,
    holder,
  );

// Detach this holder from a running verification; the run stops at its next
// read only once no holder is left. The holder still settles, with commit
// false.
export const abortReceivedFileVerification = (
  merkleRootHex: string,
  token: string,
  holder: string,
) => callWorker("abortReceivedFileVerification", merkleRootHex, token, holder);

// Open the finished (all offsets filled) OPFS file for a fully-received message
// and hand it back as a disk-backed File — no reassembly. Returns null if OPFS
// is unavailable, so the caller can fall back to the in-memory Blob path.
export const getReceiveFile = (
  merkleRootHex: string,
  totalSize: number,
  filename: string,
  mimeType: string,
) => callWorker("getReceiveFile", merkleRootHex, totalSize, filename, mimeType);

// Flush + close the open write handle for a transfer (called on completion) so
// the finished file can be opened for reading without hitting the exclusive lock.
export const closeReceiveFile = (merkleRootHex: string) =>
  callWorker("closeReceiveFile", merkleRootHex);

/**
 * Atomically retires one inbound transfer behind the same per-Merkle worker
 * lock used by storeReceiveChunk. This is the cancellation primitive: a chunk
 * write that was already in flight completes first and is then removed, while
 * later writes are stopped by the channel's AbortSignal.
 */
export function deleteReceiveTransfer(merkleRootHex: string): Promise<void>;
export function deleteReceiveTransfer(
  merkleRootHex: string,
  guard: ReceiveDeleteGuard,
): Promise<boolean>;
export function deleteReceiveTransfer(
  merkleRootHex: string,
  guard?: ReceiveDeleteGuard,
): Promise<boolean | void> {
  // Whoever answers for this file when the call is made answers for its
  // outcome, even if the answer comes after that call has returned.
  const answer = removalAnswers.get(merkleRootHex);
  return callWorker("deleteReceiveTransfer", merkleRootHex, guard).then(
    (removed) => {
      // An unguarded delete that resolves has removed the file (or found
      // none). A guarded one also resolves when its file was refused, which
      // the worker announces instead.
      if (!guard) {
        announcedNotRemoved.delete(merkleRootHex);
        if (answer) answer.failure = undefined;
      }
      return removed;
    },
    (error: unknown) => {
      // The transfer's records are gone; only its file is left. Inside a
      // call that answers for the file that is the call's to report.
      if (!answer || !(error instanceof StorageFailedError)) throw error;
      answer.failure = error;
      return guard ? true : undefined;
    },
  );
}

/**
 * Try again to remove files an earlier delete left on disk: one file, if no
 * record owns it (a message deleted before, which is no longer listed), or
 * every file a room's deleted messages left behind. Rejects with
 * StorageFailedError while the browser still refuses.
 */
export const retryFileRemovals = (scope: FileRemovalRetryScope) =>
  callWorker("retryFileRemovals", scope).then((done) => {
    if ("merkleRootHex" in scope)
      announcedNotRemoved.delete(scope.merkleRootHex);
    return done;
  });

export const getDBAllNewChunks = (selector: NewChunkSelector) =>
  callWorker("getDBAllNewChunks", selector);

export const getDBAllNewChunksCount = (transferId: string) =>
  callWorker("getDBAllNewChunksCount", transferId);

export const setDBNewChunk = (chunk: NewChunk, lease?: OutboxLease) =>
  callWorker("setDBNewChunk", chunk, lease);

export const setDBSendQueue = (item: SendQueue) =>
  callWorker("setDBSendQueue", item);

export const countDBSendQueue = (label: string, toPeerId: string) =>
  callWorker("countDBSendQueue", label, toPeerId);

export const deleteDBChunk = (hashHex: string, chunkIndex?: number) =>
  callWorker("deleteDBChunk", hashHex, chunkIndex);

export const deleteDBNewChunk = (selector: NewChunkSelector) =>
  callWorker("deleteDBNewChunk", selector);

export const deleteDBUniqueRoom = (roomId: string) =>
  callWorker("deleteDBUniqueRoom", roomId);

export const deleteDB = () => callWorker("deleteDB");

export const deleteDBSendQueue = (
  label: string,
  toPeerId: string,
  position?: number,
) => callWorker("deleteDBSendQueue", label, toPeerId, position);

export const getRatchetSession = (roomId: string, peerPublicKey: string) =>
  callWorker("getRatchetSession", roomId, peerPublicKey);

export const setRatchetSession = (session: RatchetSession) =>
  callWorker("setRatchetSession", session);

export const deleteRatchetSession = (roomId: string, peerPublicKey: string) =>
  callWorker("deleteRatchetSession", roomId, peerPublicKey);

export const getPinAttemptState = (
  roomId: string,
  peerIdentityEd25519: string,
) => callWorker("getPinAttemptState", roomId, peerIdentityEd25519);

export const incrementPinAttemptState = (
  roomId: string,
  peerIdentityEd25519: string,
  now: number,
  maxImmediateAttempts: number,
  baseMs: number,
  maxMs: number,
) =>
  callWorker(
    "incrementPinAttemptState",
    roomId,
    peerIdentityEd25519,
    now,
    maxImmediateAttempts,
    baseMs,
    maxMs,
  );

export const deletePinAttemptState = (
  roomId: string,
  peerIdentityEd25519?: string,
) => callWorker("deletePinAttemptState", roomId, peerIdentityEd25519);

// D2=B: the dedicated X25519 identity, WebCrypto-wrapped at rest (worker-side).
export const getIdentityX25519 = () => callWorker("getIdentityX25519");

export const setIdentityX25519 = (identity: IdentityX25519) =>
  callWorker("setIdentityX25519", identity);

export const deleteIdentityX25519 = () => callWorker("deleteIdentityX25519");

// Ed25519 account identity, also WebCrypto-wrapped at rest (worker-side).
// Seed derivation stays in the configured main cryptography realm; the
// database worker never introduces a second implicit WASM/CDN dependency.
export const getIdentityEd25519 = () =>
  readIdentityEd25519AtClientBoundary(() => callWorker("getIdentityEd25519"));

export const setIdentityEd25519 = async (
  identity: IdentityEd25519KeyMaterial,
): Promise<bigint> => {
  return writeIdentityEd25519AtClientBoundary(
    identity,
    (ownedIdentity, transfer) =>
      callWorkerOwned("setIdentityEd25519", [ownedIdentity], transfer),
  );
};

export const deleteIdentityEd25519 = () => callWorker("deleteIdentityEd25519");

// Non-secret provenance of the account identity: only an identity derived from
// a recovery phrase can ever be exported as one. Null means "unknown" — no flag
// was recorded, or the recorded one describes a superseded account key — and
// callers must treat that as "not exportable".
export const getIdentityDerivation = (): Promise<IdentityDerivation | null> =>
  callWorker("getIdentityDerivation");

export const setIdentityDerivation = (derivation: IdentityDerivation) =>
  callWorker("setIdentityDerivation", derivation);

export const deleteIdentityDerivation = () =>
  callWorker("deleteIdentityDerivation");

export const outboxRequest = (request: OutboxRequest) =>
  callWorker("outboxRequest", request);
export const sweepStaleReceives = () => callWorker("sweepStaleReceives");
export const sweepStaleReceiveDetails = () =>
  callWorker("sweepStaleReceiveDetails");
