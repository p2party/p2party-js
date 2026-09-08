import { getDB } from "./src/getDB";
import { decodeRoomPolicyV1, encodeRoomPolicyV1 } from "../roomPolicy";
import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { MAX_MESSAGE_SIZE } from "../utils/constants";
import type { IDBPTransaction } from "idb";
import type { RepoSchema } from "./src/getDB";
import type { NewChunk, StoredIdentityEd25519 } from "./types";
import type {
  OutboxLease,
  OutboxManifest,
  OutboxRequest,
  OutboxResponse,
} from "./outboxTypes";

export const OUTBOX_RETENTION_MS = 24 * 60 * 60 * 1000;
export const OUTBOX_STAGING_RETENTION_MS = 60 * 60 * 1000;
export const OUTBOX_LEASE_MS = 30_000;
export const MAX_PENDING_OUTBOX = 32;
export const MAX_OUTBOX_RECIPIENTS = 64;
export const MAX_OUTBOX_STAGED_BYTES = 12 * 1024 * 1024 * 1024;
const stores = [
  "outbox",
  "outboxTrees",
  "outboxAcks",
  "newChunks",
  "meta",
  "chunks",
  "messageData",
  "uniqueRoom",
] as const;
type Tx = IDBPTransaction<RepoSchema, typeof stores, "readwrite">;

const identity = async (tx: Tx): Promise<StoredIdentityEd25519 | undefined> => {
  const row = await tx.objectStore("meta").get("identityEd25519");
  return row && "wrappedSecret" in row && "recordRevision" in row
    ? (row as StoredIdentityEd25519)
    : undefined;
};

const identityMatches = async (
  tx: Tx,
  manifest: OutboxManifest,
): Promise<boolean> => {
  const current = await identity(tx);
  return (
    !!current &&
    current.recordRevision === manifest.identityRevision &&
    uint8ArrayToHex(new Uint8Array(current.pub)) === manifest.senderPublicKey
  );
};

export const ownsOutbox = (
  row: OutboxManifest | undefined,
  lease: OutboxLease,
  now = Date.now(),
): row is OutboxManifest =>
  !!row &&
  row.transferId === lease.transferId &&
  row.owner === lease.owner &&
  row.fence === lease.fence &&
  row.leaseUntil > now;

const remove = async (tx: Tx, transferId: string): Promise<void> => {
  const manifest = await tx.objectStore("outbox").get(transferId);
  if (manifest?.phase === "staging" && manifest.merkleRootHex) {
    let local = await tx
      .objectStore("chunks")
      .index("merkleRoot")
      .openCursor(manifest.merkleRootHex);
    while (local) {
      await local.delete();
      local = await local.continue();
    }
    const messageKey = await tx
      .objectStore("messageData")
      .index("merkleRoot")
      .getKey(manifest.merkleRootHex);
    if (messageKey) await tx.objectStore("messageData").delete(messageKey);
  }
  const chunks = tx.objectStore("newChunks");
  let chunk = await chunks.index("transferId").openCursor(transferId);
  while (chunk) {
    await chunk.delete();
    chunk = await chunk.continue();
  }
  const acks = tx.objectStore("outboxAcks");
  let ack = await acks.index("transferId").openCursor(transferId);
  while (ack) {
    await ack.delete();
    ack = await ack.continue();
  }
  await tx.objectStore("outboxTrees").delete(transferId);
  await tx.objectStore("outbox").delete(transferId);
};

/** Every mutation uses one IDB transaction, so separate tab workers fence each other. */
export async function executeOutbox(
  request: OutboxRequest,
): Promise<OutboxResponse> {
  const db = await getDB();
  const tx = db.transaction(stores, "readwrite");
  try {
    const store = tx.objectStore("outbox");
    const now = Date.now();
    let response: OutboxResponse = { accepted: false };
    if (request.kind === "sweep" || request.kind === "create") {
      let cursor = await store
        .index("expiresAt")
        .openCursor(IDBKeyRange.upperBound(now));
      while (cursor) {
        if (cursor.value.leaseUntil <= now)
          await remove(tx, cursor.value.transferId);
        cursor = await cursor.continue();
      }
      for (const row of await store.getAll()) {
        if (
          !(await identityMatches(tx, row)) ||
          (row.leaseUntil <= now &&
            row.recipients.every((peer) => peer.delivered || peer.cancelled))
        )
          await remove(tx, row.transferId);
      }
      response.accepted = true;
    }
    if (request.kind === "create") {
      const input = request.input;
      const policy = decodeRoomPolicyV1(hexToUint8Array(input.policyHex));
      if (
        uint8ArrayToHex(encodeRoomPolicyV1(policy)) !== input.policyHex ||
        !/^[0-9a-f]{64}$/.test(input.transferId) ||
        !/^[0-9a-f]{64}$/.test(input.senderPublicKey) ||
        !/^[0-9a-f]{64}$/.test(input.roomUrl) ||
        !input.roomId ||
        !input.owner ||
        !input.channelLabel ||
        !Number.isSafeInteger(input.totalSize) ||
        input.totalSize <= 0 ||
        input.totalSize > MAX_MESSAGE_SIZE ||
        !Number.isSafeInteger(input.totalChunks) ||
        input.totalChunks <= 0 ||
        input.totalChunks > input.totalSize + 1024 ||
        !Number.isSafeInteger(input.stagedBytes) ||
        input.stagedBytes <= 0 ||
        input.stagedBytes > MAX_OUTBOX_STAGED_BYTES ||
        input.recipients.length === 0 ||
        input.recipients.length > MAX_OUTBOX_RECIPIENTS ||
        input.recipients.some(
          (r) => !/^[0-9a-f]{64}$/.test(r.publicKey) || !r.peerId,
        ) ||
        new Set(input.recipients.map((r) => r.publicKey)).size !==
          input.recipients.length
      )
        throw new Error("Invalid durable outbox manifest");
      const current = await identity(tx);
      if (
        !current ||
        uint8ArrayToHex(new Uint8Array(current.pub)) !== input.senderPublicKey
      )
        throw new Error("Outbox requires the current durable identity");
      const pending = await store.getAll(); // At most MAX_PENDING_OUTBOX small metadata rows.
      if (
        pending.length >= MAX_PENDING_OUTBOX ||
        pending.reduce((sum, row) => sum + row.stagedBytes, input.stagedBytes) >
          MAX_OUTBOX_STAGED_BYTES
      )
        throw new Error(
          "Durable outbox storage budget exhausted; retry or cancel pending messages",
        );
      const manifest: OutboxManifest = {
        ...input,
        identityRevision: current.recordRevision,
        recipients: input.recipients.map((r) => ({ ...r, delivered: false })),
        createdAt: now,
        updatedAt: now,
        expiresAt: now + OUTBOX_STAGING_RETENTION_MS,
        phase: "staging",
        merkleRootHex: "",
        hashHex: "",
        writtenBytes: 0,
        localBytes: 0,
        fence: 1,
        leaseUntil: now + OUTBOX_LEASE_MS,
      };
      await store.add(manifest);
      response = {
        accepted: true,
        manifest,
        lease: { transferId: input.transferId, owner: input.owner, fence: 1 },
      };
    } else if (request.kind === "list") {
      const rows = await store
        .index("senderPublicKey")
        .getAll(request.senderPublicKey);
      const manifests: OutboxManifest[] = [];
      for (const row of rows)
        if (
          (!request.roomId || row.roomId === request.roomId) &&
          row.expiresAt > now &&
          (await identityMatches(tx, row))
        )
          manifests.push(row);
      response = { accepted: true, manifests };
    } else if (request.kind === "claim") {
      const row = await store.get(request.transferId);
      if (
        row &&
        row.phase !== "staging" &&
        row.expiresAt > now &&
        row.leaseUntil <= now &&
        row.senderPublicKey === request.senderPublicKey &&
        row.roomId === request.roomId &&
        row.roomUrl === request.roomUrl &&
        row.policyHex === request.policyHex &&
        (await identityMatches(tx, row))
      ) {
        row.owner = request.owner;
        row.fence++;
        row.leaseUntil = now + OUTBOX_LEASE_MS;
        row.phase = "sending";
        await store.put(row);
        const tree = await tx.objectStore("outboxTrees").get(row.transferId);
        if (!tree) throw new Error("Durable outbox tree is missing");
        response = {
          accepted: true,
          manifest: row,
          lease: {
            transferId: row.transferId,
            owner: row.owner,
            fence: row.fence,
          },
          chunkHashes: tree.chunkHashes,
          acknowledgments: await tx
            .objectStore("outboxAcks")
            .index("transferId")
            .getAll(row.transferId),
        };
      }
    } else if (
      request.kind === "publish" ||
      request.kind === "renew" ||
      request.kind === "release" ||
      request.kind === "selfChunk" ||
      request.kind === "selfMessage"
    ) {
      const row = await store.get(request.lease.transferId);
      if (
        !ownsOutbox(row, request.lease, now) ||
        !(await identityMatches(tx, row))
      )
        throw new Error("Durable outbox ownership was lost");
      if (request.kind === "selfChunk" || request.kind === "selfMessage") {
        const root =
          request.kind === "selfChunk"
            ? request.chunk.merkleRoot
            : request.message.merkleRoot;
        if (
          row.phase !== "staging" ||
          (row.merkleRootHex && row.merkleRootHex !== root)
        )
          throw new Error("Invalid sender self-copy binding");
        row.merkleRootHex = root;
        if (request.kind === "selfChunk") {
          const value = request.chunk;
          if (
            !Number.isSafeInteger(value.chunkIndex) ||
            value.chunkIndex < 0 ||
            value.chunkIndex >= row.totalChunks ||
            !value.data ||
            value.data.byteLength <= 0 ||
            value.data.byteLength > row.totalSize
          )
            throw new Error("Invalid sender self-copy chunk");
          const previous = await tx
            .objectStore("chunks")
            .get([root, value.chunkIndex]);
          const delta =
            value.data.byteLength - (previous?.data?.byteLength ?? 0);
          if (
            row.localBytes + delta > row.totalSize ||
            row.writtenBytes + delta > row.stagedBytes
          )
            throw new Error("Sender self-copy exceeds reservation");
          row.localBytes += delta;
          row.writtenBytes += delta;
          await tx.objectStore("chunks").put(value);
        } else {
          if (
            request.message.transferId !== row.transferId ||
            request.message.roomId !== row.roomId ||
            request.message.totalSize !== row.totalSize ||
            request.message.savedSize !== row.totalSize ||
            row.localBytes !== row.totalSize
          )
            throw new Error("Invalid sender self-copy manifest");
          await tx.objectStore("messageData").put(request.message);
          const room = await tx
            .objectStore("uniqueRoom")
            .index("roomId")
            .get(row.roomId);
          if (room)
            await tx
              .objectStore("uniqueRoom")
              .put({
                ...room,
                messageCount: await tx
                  .objectStore("messageData")
                  .index("roomId")
                  .count(row.roomId),
                lastMessageMerkleRoot: root,
                updatedAt: now,
              });
        }
      }
      if (request.kind === "publish") {
        const localMessage = await tx
          .objectStore("messageData")
          .index("merkleRoot")
          .get(request.merkleRootHex);
        if (
          row.phase !== "staging" ||
          row.localBytes !== row.totalSize ||
          !localMessage ||
          localMessage.transferId !== row.transferId ||
          localMessage.savedSize !== row.totalSize ||
          localMessage.hash !== request.hashHex ||
          !/^[0-9a-f]{128}$/.test(request.merkleRootHex) ||
          !/^[0-9a-f]{128}$/.test(request.hashHex) ||
          request.chunkHashes.byteLength !== row.totalChunks * 64 ||
          (await tx
            .objectStore("newChunks")
            .index("transferId")
            .count(row.transferId)) !== row.totalChunks
        )
          throw new Error("Cannot publish incomplete outbound staging");
        row.merkleRootHex = request.merkleRootHex;
        row.hashHex = request.hashHex;
        row.phase = "sending";
        row.expiresAt = now + OUTBOX_RETENTION_MS;
        await tx
          .objectStore("outboxTrees")
          .put({
            transferId: row.transferId,
            chunkHashes: request.chunkHashes,
          });
      }
      if (request.kind === "release") {
        row.owner = "";
        row.leaseUntil = 0;
        row.phase = "pending";
        row.lastError = request.lastError?.slice(0, 240);
      } else row.leaseUntil = now + OUTBOX_LEASE_MS;
      row.updatedAt = now;
      if (row.recipients.every((r) => r.delivered || r.cancelled))
        await remove(tx, row.transferId);
      else await store.put(row);
      response = { accepted: true, manifest: row, lease: request.lease };
    } else if (request.kind === "receipt") {
      const receipt = request.receipt;
      const row = await store.get(receipt.transferId);
      // Legacy callers have no durable manifest; their existing live receipt checks remain authoritative.
      if (!row) response = { accepted: true };
      else if (
        row.phase !== "staging" &&
        row.roomId === receipt.roomId &&
        row.merkleRootHex === receipt.merkleRootHex &&
        (await identityMatches(tx, row))
      ) {
        const peer = row.recipients.find(
          (r) => r.publicKey === receipt.peerPublicKey,
        );
        if (peer) {
          if (peer.cancelled) {
            await tx.done;
            return { accepted: receipt.cancelled === true };
          }
          if (receipt.cancelled && peer.delivered) {
            await tx.done;
            return { accepted: false };
          }
          if (receipt.cancelled) {
            peer.cancelled = true;
            peer.peerId = receipt.peerId;
            row.updatedAt = now;
            await store.put(row);
          } else if (receipt.chunkIndex === undefined) {
            peer.delivered = true;
            peer.peerId = receipt.peerId;
            row.updatedAt = now;
            await store.put(row);
          } else if (
            Number.isSafeInteger(receipt.chunkIndex) &&
            receipt.chunkIndex >= 0 &&
            receipt.chunkIndex < row.totalChunks
          ) {
            const acks = tx.objectStore("outboxAcks");
            const ack = (await acks.get([row.transferId, peer.publicKey])) ?? {
              transferId: row.transferId,
              publicKey: peer.publicKey,
              bitmap: new Uint8Array(Math.ceil(row.totalChunks / 8)),
            };
            ack.bitmap[receipt.chunkIndex >>> 3] |=
              1 << (receipt.chunkIndex & 7);
            await acks.put(ack);
          } else {
            await tx.done;
            return { accepted: false };
          }
          response = { accepted: true };
        }
      }
    } else if (request.kind === "remove") {
      if (!request.transferId && !request.roomId)
        throw new Error("Outbox removal must select a transfer or room");
      const rows = request.transferId
        ? [await store.get(request.transferId)]
        : await store.index("roomId").getAll(request.roomId!);
      for (const row of rows) {
        if (!row || (request.roomId && row.roomId !== request.roomId)) continue;
        if (request.lease && !ownsOutbox(row, request.lease, now)) continue;
        await remove(tx, row.transferId);
      }
      response = { accepted: true };
    }
    await tx.done;
    return response;
  } catch (error) {
    try {
      tx.abort();
    } catch {
      /* Already aborted by IDB. */
    }
    await tx.done.catch(() => undefined);
    throw error;
  } finally {
    db.close();
  }
}

/** Admission and every queued staging/proof update share the same owner fence. */
export async function storeOutboxChunk(
  chunk: NewChunk,
  lease?: OutboxLease,
): Promise<void> {
  const db = await getDB();
  const tx = db.transaction(stores, "readwrite");
  try {
    const store = tx.objectStore("outbox");
    const row = await store.get(chunk.transferId);
    if (lease) {
      if (!ownsOutbox(row, lease) || !(await identityMatches(tx, row)))
        throw new Error("Durable outbox staging ownership was lost");
      if (
        !Number.isSafeInteger(chunk.chunkIndex) ||
        chunk.chunkIndex < 0 ||
        chunk.chunkIndex >= row.totalChunks
      )
        throw new Error("Invalid outbound staging index");
      const previous = await tx
        .objectStore("newChunks")
        .get([chunk.transferId, chunk.chunkIndex]);
      const size = (value: NewChunk): number =>
        value.data.byteLength +
        value.metadata.byteLength +
        value.merkleProof.byteLength +
        2048;
      const nextBytes =
        row.writtenBytes + size(chunk) - (previous ? size(previous) : 0);
      if (nextBytes > row.stagedBytes)
        throw new Error(
          "Durable outbox padded staging exceeds its reservation",
        );
      row.writtenBytes = nextBytes;
      await store.put(row);
    } else if (row)
      throw new Error("Durable outbox chunk writes require ownership");
    await tx.objectStore("newChunks").put(chunk);
    await tx.done;
  } catch (error) {
    try {
      tx.abort();
    } catch {
      /* Already aborted. */
    }
    await tx.done.catch(() => undefined);
    throw error;
  } finally {
    db.close();
  }
}
