import { describe, expect, spyOn, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  cloneRatchet,
  initRatchet,
  ratchetEncrypt,
} from "../../src/cryptography/ratchet";
import { getMerkleRoot, getMerkleProof } from "../../src/cryptography/merkle";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import { parseChunkFrameHeader } from "../../src/handlers/chunkFrame";
import { handleReceiveMessage } from "../../src/handlers/handleReceiveMessage";
import { sendReceiveFrameReceipt } from "../../src/handlers/handleMessageQueueing";
import {
  sealChunk,
  decryptMessageChunk,
  messageCacheKey,
} from "../../src/handlers/messageChunkCrypto";
import { forgetCompletedReceiveMessageKey } from "../../src/handlers/receiveMessageKeyLifetime";
import {
  decryptMessageChunkDurably,
  forgetReceiveMessageKeyDurably,
  ratchetEncryptDurably,
} from "../../src/handlers/ratchetPersist";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import {
  METADATA_LEN,
  PROOF_LEN,
  CHUNK_LEN,
  DECRYPTED_LEN,
  RATCHET_ROOT_SUITE_MLKEM768,
} from "../../src/utils/constants";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import type { PqMessageKeyContext } from "../../src/cryptography/pqMessageKey";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { RatchetState } from "../../src/cryptography/ratchet";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";

const rand = (n: number): Uint8Array => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

// Bob is the responder (initRatchet false, remote null); Alice the initiator,
// consuming Bob's initial ratchet pub. Same setup as ratchet.test.ts.
const pair = async () => {
  const module = await loadTestModule();
  const seed = rand(32);
  const bob = initRatchet(seed, false, null, module);
  const alice = initRatchet(Uint8Array.from(seed), true, bob.dhSelfPub, module);
  return { module, alice, bob };
};

// Build K *real* chunk plaintexts (`metadata ‖ merkle-proof ‖ chunk`) sharing one
// Merkle root — exactly the DECRYPTED_LEN layout the send path assembles, so the C
// `_receive_message_with_key` decrypts AND verifies. The metadata region is opaque
// to the receive crypto (the C only reads the proof + chunk), so it is left zero.
const buildMessage = async (module: LibCrypto, K: number) => {
  const datas = Array.from({ length: K }, () => rand(CHUNK_LEN));
  const leaves = new Uint8Array(K * crypto_hash_sha512_BYTES);
  datas.forEach((d, i) =>
    leaves.set(hashMerkleLeafWasm(d, module), i * crypto_hash_sha512_BYTES),
  );
  const root = await getMerkleRoot(leaves, module);

  const plaintexts: Uint8Array[] = [];
  for (let i = 0; i < K; i++) {
    const proof = await getMerkleProof(
      leaves,
      hashMerkleLeafWasm(datas[i], module),
      module,
      PROOF_LEN,
    );
    const pt = new Uint8Array(DECRYPTED_LEN);
    pt.set(proof, METADATA_LEN);
    pt.set(datas[i], METADATA_LEN + PROOF_LEN);
    plaintexts.push(pt);
  }
  return { root, datas, plaintexts };
};

const buildRealFirstCoverMessage = async (module: LibCrypto) => {
  const datas = Array.from({ length: 3 }, () => rand(CHUNK_LEN));
  const leaves = new Uint8Array(3 * crypto_hash_sha512_BYTES);
  datas.forEach((data, index) =>
    leaves.set(
      hashMerkleLeafWasm(data, module),
      index * crypto_hash_sha512_BYTES,
    ),
  );
  const root = await getMerkleRoot(leaves, module);
  const messageHash = rand(crypto_hash_sha512_BYTES);
  const plaintexts: Uint8Array[] = [];

  for (let index = 0; index < datas.length; index++) {
    const proof = await getMerkleProof(
      leaves,
      hashMerkleLeafWasm(datas[index], module),
      module,
      PROOF_LEN,
    );
    const plaintext = new Uint8Array(DECRYPTED_LEN);
    plaintext.set(
      serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Text,
        hash: messageHash,
        totalSize: 4,
        date: new Date(1),
        name: "",
        // Cell zero is the real four-byte payload. Cells one and two are valid
        // authenticated/Merkle-rooted cover slots with an empty real range.
        chunkStartIndex: 0,
        chunkEndIndex: index === 0 ? 4 : 0,
        chunkIndex: index,
      }),
    );
    plaintext.set(proof, METADATA_LEN);
    plaintext.set(datas[index], METADATA_LEN + PROOF_LEN);
    plaintexts.push(plaintext);
  }

  return { root, plaintexts };
};

const chunkOf = (decrypted: Uint8Array): Uint8Array =>
  decrypted.slice(METADATA_LEN + PROOF_LEN);
const receiptOf = (decrypted: Uint8Array): Uint8Array =>
  decrypted.slice(METADATA_LEN, METADATA_LEN + crypto_hash_sha512_BYTES);

const edge = (ratchetState: RatchetState): IRTCPeerConnection =>
  ({
    roomId: "room-1",
    withPeerId: "peer-1",
    withPeerPublicKey: "aa".repeat(32),
    ratchetState,
  }) as unknown as IRTCPeerConnection;

describe("messageChunkCrypto (single-call C receive)", () => {
  test("round-trip: a real 2-chunk message decrypts byte-exact through the C receive; chunk 0 steps the ratchet, chunk 1 rides the per-message cache", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);

    // ONE ratchet step for the whole message; seal each chunk with a fresh nonce.
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = plaintexts.map((pt) =>
      sealChunk(messageKey, header, pt, root, module),
    );
    messageKey.fill(0);

    // Same per-message header on every frame, distinct random nonce per chunk.
    const h0 = parseChunkFrameHeader(frames[0]);
    const h1 = parseChunkFrameHeader(frames[1]);
    expect(Buffer.from(h1.header.dhPub)).toEqual(Buffer.from(h0.header.dhPub));
    expect(h1.header.N).toBe(h0.header.N);
    expect(Buffer.from(h1.nonce)).not.toEqual(Buffer.from(h0.nonce));

    const cache = new Map<string, Uint8Array>();
    const d0 = decryptMessageChunk(bob, frames[0], cache, root, module);
    const d1 = decryptMessageChunk(bob, frames[1], cache, root, module);

    expect(d0.ok).toBe(true);
    expect(d1.ok).toBe(true);
    expect(d0.stateAdvanced).toBe(true); // first chunk stepped the ratchet
    expect(d1.stateAdvanced).toBe(false); // second rode the cached key
    expect(bob.Nr).toBe(1); // exactly one receiving-chain step for the message
    expect(cache.size).toBe(1);

    // The chunk region round-trips byte-exact.
    expect(Buffer.from(chunkOf(d0.decrypted!))).toEqual(Buffer.from(datas[0]));
    expect(Buffer.from(chunkOf(d1.decrypted!))).toEqual(Buffer.from(datas[1]));

    // The C wrote the receipt leaf SHA-512(0x00 ‖ chunk) over the proof region.
    expect(Buffer.from(receiptOf(d0.decrypted!))).toEqual(
      Buffer.from(hashMerkleLeafWasm(datas[0], module)),
    );
  });

  test("v4 combines against an explicit PQ epoch, uses an epoch-bound cache identity, and rejects unknown epochs before ratchet mutation", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 1);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const classicalBefore = Uint8Array.from(messageKey);
    const context: PqMessageKeyContext = {
      rootKey: new Uint8Array(32).fill(0x91),
      binding: new Uint8Array(32).fill(0x42),
      rootSuite: RATCHET_ROOT_SUITE_MLKEM768,
      epoch: 9n,
    };
    const frame = sealChunk(
      messageKey,
      header,
      plaintexts[0],
      root,
      module,
      context,
    );

    // sealChunk combines an owned copy per chunk; the caller retains the
    // classical per-message key for streaming/retransmit.
    expect(Buffer.from(messageKey)).toEqual(Buffer.from(classicalBefore));
    messageKey.fill(0);
    expect(parseChunkFrameHeader(frame).pqEpoch).toBe(9n);
    expect(messageCacheKey(header.dhPub, header.N)).not.toBe(
      messageCacheKey(header.dhPub, header.N, 0n),
    );
    expect(messageCacheKey(header.dhPub, header.N, 9n)).not.toBe(
      messageCacheKey(header.dhPub, header.N, 10n),
    );

    const cache = new Map<string, Uint8Array>();
    const resolver = (epoch: bigint): PqMessageKeyContext | null =>
      epoch === context.epoch ? context : null;
    const decrypted = decryptMessageChunk(
      bob,
      frame,
      cache,
      root,
      module,
      resolver,
    );
    expect(decrypted.ok).toBe(true);
    expect(decrypted.stateAdvanced).toBe(true);
    expect(Buffer.from(chunkOf(decrypted.decrypted!))).toEqual(
      Buffer.from(datas[0]),
    );
    expect(cache.has(messageCacheKey(header.dhPub, header.N, 9n))).toBe(true);

    const { bob: untouchedBob } = await pair();
    const rootBefore = Uint8Array.from(untouchedBob.rootKey);
    const unknownEpoch = Uint8Array.from(frame);
    unknownEpoch[56] = 10; // pqEpoch u64 BE: replace low byte 9 -> 10
    const rejected = decryptMessageChunk(
      untouchedBob,
      unknownEpoch,
      new Map(),
      root,
      module,
      resolver,
    );
    expect(rejected.ok).toBe(false);
    expect(rejected.stateAdvanced).toBe(false);
    expect(untouchedBob.Nr).toBe(0);
    expect(Buffer.from(untouchedBob.rootKey)).toEqual(Buffer.from(rootBefore));
  });

  test("v4 app AAD authenticates dhPub, N, and PN clear-header bytes", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, plaintexts[0], root, module);
    messageKey.fill(0);

    for (const offset of [1, 40, 48]) {
      const candidate = cloneRatchet(bob);
      const rootBefore = Uint8Array.from(candidate.rootKey);
      const tampered = Uint8Array.from(frame);
      tampered[offset] ^= 1;
      const result = decryptMessageChunk(
        candidate,
        tampered,
        new Map(),
        root,
        module,
      );
      expect(result.ok).toBe(false);
      expect(result.stateAdvanced).toBe(false);
      expect(candidate.Nr).toBe(0);
      expect(Buffer.from(candidate.rootKey)).toEqual(Buffer.from(rootBefore));
    }
  });

  test("clone-rollback: a corrupted ciphertext byte fails the AEAD (C code -2), so the ratchet is left byte-for-byte unadvanced; a good frame then decrypts", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = plaintexts.map((pt) =>
      sealChunk(messageKey, header, pt, root, module),
    );
    messageKey.fill(0);

    // Bob is the responder and has not stepped: no receiving chain, root == seed.
    const rootBefore = Uint8Array.from(bob.rootKey);
    expect(bob.dhRemotePub).toBeNull();
    expect(bob.Nr).toBe(0);

    // Corrupt one ciphertext byte (past the 69-byte cleartext header).
    const bad = Uint8Array.from(frames[0]);
    bad[80] ^= 0xff;

    const cache = new Map<string, Uint8Array>();
    const r = decryptMessageChunk(bob, bad, cache, root, module);
    expect(r.ok).toBe(false);
    expect(r.stateAdvanced).toBe(false);
    expect(r.decrypted).toBeNull();

    // The clone was discarded; the live state never advanced.
    expect(Buffer.from(bob.rootKey)).toEqual(Buffer.from(rootBefore));
    expect(bob.dhRemotePub).toBeNull();
    expect(bob.Nr).toBe(0);
    expect(cache.size).toBe(0);

    // The GOOD frame of that message still decrypts (rollback left it usable).
    const good = decryptMessageChunk(bob, frames[0], cache, root, module);
    expect(good.ok).toBe(true);
    expect(good.stateAdvanced).toBe(true);
    expect(Buffer.from(chunkOf(good.decrypted!))).toEqual(
      Buffer.from(datas[0]),
    );
  });

  test("failed receive starts with zeroed decrypt scratch and exposes no stale WASM plaintext", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, plaintexts[0], root, module);
    messageKey.fill(0);

    const originalMalloc = module._malloc;
    const originalReceive = module._receive_message_with_key;
    let scratchWasZero = false;
    module._malloc = (size: number): number => {
      const ptr = originalMalloc(size);
      // Simulate allocator reuse containing a previous plaintext.
      if (size === DECRYPTED_LEN)
        new Uint8Array(module.wasmMemory.buffer, ptr, size).fill(0xa5);
      return ptr;
    };
    module._receive_message_with_key = (
      decryptedPtr: number,
      _messagePtr: number,
      _rootPtr: number,
      _keyPtr: number,
    ): number => {
      const scratch = new Uint8Array(
        module.wasmMemory.buffer,
        decryptedPtr,
        DECRYPTED_LEN,
      );
      scratchWasZero = scratch.every((byte) => byte === 0);
      scratch.fill(0x5a);
      return -2;
    };

    try {
      const result = decryptMessageChunk(
        bob,
        frame,
        new Map<string, Uint8Array>(),
        root,
        module,
      );
      expect(scratchWasZero).toBe(true);
      expect(result.ok).toBe(false);
      expect(result.decrypted).toBeNull();
    } finally {
      module._malloc = originalMalloc;
      module._receive_message_with_key = originalReceive;
    }
  });

  test("AEAD-authentic but bad Merkle proof: C returns != -2, so the ratchet COMMITS (stateAdvanced) even though the chunk is dropped (ok false)", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 2);

    // Tamper a proof-artifact byte INSIDE the plaintext, then seal it: the AEAD is
    // valid (we seal the tampered bytes) but the proof no longer folds to the root.
    const tampered = Uint8Array.from(plaintexts[0]);
    tampered[METADATA_LEN + 8] ^= 0xff;
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, tampered, root, module);
    messageKey.fill(0);

    const cache = new Map<string, Uint8Array>();
    const r = decryptMessageChunk(bob, frame, cache, root, module);
    expect(r.ok).toBe(false); // Merkle verification failed inside the C call
    expect(r.decrypted).toBeNull();
    expect(r.stateAdvanced).toBe(true); // but the AEAD authenticated → ratchet stepped
    expect(bob.Nr).toBe(1);
    expect(cache.size).toBe(1); // key cached so the message's other chunks can arrive
  });

  test("reconcile re-seal: same key/header, fresh nonce → a distinct frame that rides the cached per-message key", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 1);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, plaintexts[0], root, module);

    const cache = new Map<string, Uint8Array>();
    const d = decryptMessageChunk(bob, frame, cache, root, module);
    expect(d.ok).toBe(true);
    expect(d.stateAdvanced).toBe(true);

    // Selective-retransmit: re-seal the SAME plaintext under the still-live key
    // with a FRESH nonce. Distinct frame on the wire, opened by the cached key.
    const resend = sealChunk(messageKey, header, plaintexts[0], root, module);
    messageKey.fill(0);
    expect(Buffer.from(resend)).not.toEqual(Buffer.from(frame)); // fresh nonce
    const re = decryptMessageChunk(bob, resend, cache, root, module);
    expect(re.ok).toBe(true);
    expect(re.stateAdvanced).toBe(false); // cache HIT, no ratchet step
    expect(Buffer.from(chunkOf(re.decrypted!))).toEqual(Buffer.from(datas[0]));
  });

  test("failed pre-send persistence leaves live state unchanged and wipes the staged successor", async () => {
    const { module, alice } = await pair();
    const epc = edge(alice);
    const chainBefore = Uint8Array.from(alice.sendingChainKey!);
    let stagedChain: Uint8Array | undefined;

    await expect(
      ratchetEncryptDurably(epc, "room-1", module, async (candidate) => {
        stagedChain = candidate.sendingChainKey!;
        throw new Error("injected persistence failure");
      }),
    ).rejects.toThrow("injected persistence failure");

    expect(alice.Ns).toBe(0);
    expect(Buffer.from(alice.sendingChainKey!)).toEqual(
      Buffer.from(chainBefore),
    );
    expect(stagedChain?.every((byte) => byte === 0)).toBe(true);
  });

  test("failed receive persistence exposes no plaintext and commits neither ratchet nor cache", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frame = sealChunk(messageKey, header, plaintexts[0], root, module);
    messageKey.fill(0);

    const epc = edge(bob);
    const rootBefore = Uint8Array.from(bob.rootKey);
    const cache = new Map<string, Uint8Array>();
    let stagedReceivingChain: Uint8Array | undefined;

    await expect(
      decryptMessageChunkDurably(
        epc,
        "room-1",
        frame,
        cache,
        root,
        module,
        async (candidate) => {
          stagedReceivingChain = candidate.receivingChainKey!;
          throw new Error("injected persistence failure");
        },
      ),
    ).rejects.toThrow("injected persistence failure");

    expect(bob.Nr).toBe(0);
    expect(Buffer.from(bob.rootKey)).toEqual(Buffer.from(rootBefore));
    expect(cache.size).toBe(0);
    expect(stagedReceivingChain?.every((byte) => byte === 0)).toBe(true);
  });

  test("active multi-chunk receive key survives a state restore until durable completion", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = plaintexts.map((plaintext) =>
      sealChunk(messageKey, header, plaintext, root, module),
    );
    messageKey.fill(0);
    const cacheKey = messageCacheKey(header.dhPub, header.N);
    const persist = async () => {};

    const firstCache = new Map<string, Uint8Array>();
    const first = await decryptMessageChunkDurably(
      edge(bob),
      "room-1",
      frames[0],
      firstCache,
      root,
      module,
      persist,
    );
    expect(first.ok).toBe(true);
    expect(bob.skipped.has(cacheKey)).toBe(true);
    expect(firstCache.has(cacheKey)).toBe(true);

    // Simulate a replacement PC/reload: restore only the persisted ratchet and
    // start with an empty RAM cache. The retained skipped-key copy rebuilds it.
    const restored = cloneRatchet(bob);
    const restoredEpc = edge(restored);
    const restoredCache = new Map<string, Uint8Array>();
    const second = await decryptMessageChunkDurably(
      restoredEpc,
      "room-1",
      frames[1],
      restoredCache,
      root,
      module,
      persist,
    );
    expect(second.ok).toBe(true);
    expect(Buffer.from(chunkOf(second.decrypted!))).toEqual(
      Buffer.from(datas[1]),
    );
    expect(restored.skipped.has(cacheKey)).toBe(true);
    expect(restoredCache.has(cacheKey)).toBe(true);

    await forgetReceiveMessageKeyDurably(
      restoredEpc,
      "room-1",
      restoredCache,
      cacheKey,
      persist,
    );
    expect(restored.skipped.has(cacheKey)).toBe(false);
    expect(restoredCache.has(cacheKey)).toBe(false);
  });

  test("real-first completion accepts two late valid cover cells, emits one receipt per frame, then retires once on drained close", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildRealFirstCoverMessage(module);
    const { messageKey, header } = ratchetEncrypt(alice, module);
    const frames = plaintexts.map((plaintext) =>
      sealChunk(messageKey, header, plaintext, root, module),
    );
    messageKey.fill(0);

    const epc = edge(bob);
    epc.messageKeyCache = new Map<string, Uint8Array>();
    const cacheKey = messageCacheKey(header.dhPub, header.N);
    const merkleRootHex = uint8ArrayToHex(root);
    const persist = async () => {};
    const sentReceipts: ArrayBuffer[] = [];
    const receiptChannel = {
      readyState: "open",
      send: (frame: ArrayBuffer) => sentReceipts.push(frame),
    } as unknown as IRTCDataChannel;
    const errorLog = spyOn(console, "error").mockImplementation(() => {});
    let stored = false;

    try {
      const results = [];
      for (const frame of frames) {
        const result = await handleReceiveMessage(
          frame,
          "room-1",
          "chat",
          epc,
          root,
          module,
          undefined,
          {
            persistRatchetState: persist,
            storeReceiveChunk: async () => {
              if (stored)
                throw new Error("cover cell must not reach durable storage");
              stored = true;
              return { stored: true, savedSize: 4, complete: true };
            },
          },
        );
        results.push(result);
        expect(sendReceiveFrameReceipt(result, receiptChannel)).toBe(true);
      }

      expect(results.map((result) => result.receivedFullSize)).toEqual([
        true,
        false,
        false,
      ]);
      expect(results.map((result) => result.chunkIndex)).toEqual([0, -1, -1]);
      expect(sentReceipts).toHaveLength(3);
      expect(errorLog).not.toHaveBeenCalled();
      expect(bob.Nr).toBe(1);
      expect(epc.messageKeyCache.has(cacheKey)).toBe(true);
      expect(epc.messageKeyByMerkleRoot?.get(merkleRootHex)).toBe(cacheKey);

      const cachedMessageKey = epc.messageKeyCache.get(cacheKey)!;
      let forgetCalls = 0;
      const forget = async (
        target: IRTCPeerConnection,
        roomId: string,
        cache: Map<string, Uint8Array>,
        key: string,
      ): Promise<void> => {
        forgetCalls += 1;
        await forgetReceiveMessageKeyDurably(
          target,
          roomId,
          cache,
          key,
          persist,
        );
      };
      expect(
        await forgetCompletedReceiveMessageKey(
          epc,
          "room-1",
          merkleRootHex,
          { savedSize: 4, totalSize: 4 },
          forget,
        ),
      ).toBe(true);
      expect(
        await forgetCompletedReceiveMessageKey(
          epc,
          "room-1",
          merkleRootHex,
          { savedSize: 4, totalSize: 4 },
          forget,
        ),
      ).toBe(false);
      expect(forgetCalls).toBe(1);
      expect(cachedMessageKey.every((byte) => byte === 0)).toBe(true);
      expect(epc.messageKeyCache.has(cacheKey)).toBe(false);
      expect(bob.skipped.has(cacheKey)).toBe(false);
    } finally {
      errorLog.mockRestore();
    }
  });

  test("concurrent sends serialize into distinct durable ratchet steps", async () => {
    const { module, alice } = await pair();
    const epc = edge(alice);
    const persistedNs: number[] = [];
    let releaseFirst!: () => void;
    const firstBlocked = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let markFirstStarted!: () => void;
    const firstStarted = new Promise<void>((resolve) => {
      markFirstStarted = resolve;
    });

    const persist = async (candidate: RatchetState) => {
      persistedNs.push(candidate.Ns);
      if (candidate.Ns === 1) {
        markFirstStarted();
        await firstBlocked;
      }
    };
    const first = ratchetEncryptDurably(epc, "room-1", module, persist);
    const second = ratchetEncryptDurably(epc, "room-1", module, persist);

    await firstStarted;
    expect(persistedNs).toEqual([1]);
    releaseFirst();
    const [a, b] = await Promise.all([first, second]);

    expect(persistedNs).toEqual([1, 2]);
    expect([a.header.N, b.header.N]).toEqual([0, 1]);
    expect(alice.Ns).toBe(2);
    a.messageKey.fill(0);
    b.messageKey.fill(0);
  });
});

describe("v4 durable PQ-combined receive/send paths", () => {
  const pqRuntime = (
    module: LibCrypto,
    amInitiator: boolean,
  ): SparsePqHealingState =>
    new SparsePqHealingState({
      module,
      pqMode: "hybrid-mlkem768",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM768,
      binding: new Uint8Array(32).fill(0x42),
      rootKey: new Uint8Array(32).fill(0x19),
      nextOfferer: amInitiator ? "local" : "remote",
      amInitiator,
      now: 1_000,
    });

  const restorePqRuntime = (
    module: LibCrypto,
    bytes: Uint8Array,
    amInitiator: boolean,
  ): SparsePqHealingState =>
    SparsePqHealingState.restore(bytes, {
      module,
      pqMode: "hybrid-mlkem768",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM768,
      binding: new Uint8Array(32).fill(0x42),
      amInitiator,
    });

  const pqEdge = (
    state: RatchetState,
    runtime: SparsePqHealingState,
  ): IRTCPeerConnection => {
    const epc = edge(state);
    epc.pqHealingState = runtime;
    epc.messageKeyCache = runtime.activeReceiveKeys;
    return epc;
  };

  type EdgeCapture = Uint8Array | null;
  const capturingPersist = (captures: EdgeCapture[]) =>
    async (
      _state: RatchetState,
      _roomId: string,
      _peerPublicKey: string,
      _peerId: string,
      edgeCryptoState?: Uint8Array | null,
    ): Promise<void> => {
      captures.push(
        edgeCryptoState ? Uint8Array.from(edgeCryptoState) : null,
      );
    };

  test("durable receive persists the combined key in the edge checkpoint, never in the skipped map", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);
    const runtimeA = pqRuntime(module, true);
    const runtimeB = pqRuntime(module, false);
    const epcA = pqEdge(alice, runtimeA);
    const epcB = pqEdge(bob, runtimeB);
    const persistNoop = async (): Promise<void> => {};

    // The sender's durable step captures an OWNED context copy atomically and
    // counts exactly one application message.
    const stepped = await ratchetEncryptDurably(
      epcA,
      "room-1",
      module,
      persistNoop,
    );
    expect(stepped.pqContext).not.toBeNull();
    expect(stepped.pqContext!.epoch).toBe(0n);
    expect(stepped.pqContext!.rootSuite).toBe(RATCHET_ROOT_SUITE_MLKEM768);
    expect(stepped.pqContext!.rootKey).not.toBe(
      runtimeA.currentMessageContext().rootKey,
    );
    expect(Buffer.from(stepped.pqContext!.rootKey)).toEqual(
      Buffer.from(runtimeA.currentMessageContext().rootKey),
    );
    expect(runtimeA.messagesSinceHealing).toBe(1);

    const frames = plaintexts.map((plaintext) =>
      sealChunk(
        stepped.messageKey,
        stepped.header,
        plaintext,
        root,
        module,
        stepped.pqContext!,
      ),
    );
    expect(parseChunkFrameHeader(frames[0]).pqEpoch).toBe(0n);
    const epochKey = messageCacheKey(
      stepped.header.dhPub,
      stepped.header.N,
      0n,
    );

    const captures: EdgeCapture[] = [];
    const d0 = await decryptMessageChunkDurably(
      epcB,
      "room-1",
      frames[0],
      epcB.messageKeyCache!,
      root,
      module,
      capturingPersist(captures),
    );
    expect(d0.ok).toBe(true);
    expect(d0.stateAdvanced).toBe(true);
    expect(Buffer.from(chunkOf(d0.decrypted!))).toEqual(Buffer.from(datas[0]));
    // The combined key never touches the classical skipped map …
    expect(bob.skipped.size).toBe(0);
    // … it is durable inside the STAGED edge checkpoint written in the same
    // row as the ratchet successor.
    expect(captures).toHaveLength(1);
    expect(captures[0]).not.toBeNull();
    const restoredFromRow = restorePqRuntime(module, captures[0]!, false);
    expect(restoredFromRow.activeReceiveKeys.has(epochKey)).toBe(true);
    restoredFromRow.destroy();
    // The live cache (the runtime's active map) published after persistence.
    expect(runtimeB.activeReceiveKeys.has(epochKey)).toBe(true);
    expect(runtimeB.messagesSinceHealing).toBe(1);

    // Second chunk rides the epoch-bound cached key without persistence.
    const d1 = await decryptMessageChunkDurably(
      epcB,
      "room-1",
      frames[1],
      epcB.messageKeyCache!,
      root,
      module,
      capturingPersist(captures),
    );
    expect(d1.ok).toBe(true);
    expect(d1.stateAdvanced).toBe(false);
    expect(captures).toHaveLength(1);
    expect(bob.Nr).toBe(1);
    runtimeA.destroy();
    runtimeB.destroy();
  });

  test("restart-mid-message: a restored checkpoint decrypts remaining chunks without re-combining", async () => {
    const { module, alice, bob } = await pair();
    const { root, datas, plaintexts } = await buildMessage(module, 2);
    const runtimeA = pqRuntime(module, true);
    const runtimeB = pqRuntime(module, false);
    const epcA = pqEdge(alice, runtimeA);
    const epcB = pqEdge(bob, runtimeB);
    const persistNoop = async (): Promise<void> => {};

    const stepped = await ratchetEncryptDurably(
      epcA,
      "room-1",
      module,
      persistNoop,
    );
    const frames = plaintexts.map((plaintext) =>
      sealChunk(
        stepped.messageKey,
        stepped.header,
        plaintext,
        root,
        module,
        stepped.pqContext!,
      ),
    );

    const first = await decryptMessageChunkDurably(
      epcB,
      "room-1",
      frames[0],
      epcB.messageKeyCache!,
      root,
      module,
      persistNoop,
    );
    expect(first.ok).toBe(true);

    // Reload: restore the persisted ratchet AND the persisted edge checkpoint.
    const restoredState = cloneRatchet(bob);
    const restoredRuntime = restorePqRuntime(
      module,
      runtimeB.serialize(),
      false,
    );
    const epochKey = messageCacheKey(
      stepped.header.dhPub,
      stepped.header.N,
      0n,
    );
    expect(restoredRuntime.activeReceiveKeys.has(epochKey)).toBe(true);
    const epcB2 = pqEdge(restoredState, restoredRuntime);

    const second = await decryptMessageChunkDurably(
      epcB2,
      "room-1",
      frames[1],
      epcB2.messageKeyCache!,
      root,
      module,
      persistNoop,
    );
    // A cache HIT on the restored ALREADY-combined key: correct plaintext with
    // no second ratchet step and no second combination.
    expect(second.ok).toBe(true);
    expect(second.stateAdvanced).toBe(false);
    expect(Buffer.from(chunkOf(second.decrypted!))).toEqual(
      Buffer.from(datas[1]),
    );
    expect(restoredState.Nr).toBe(bob.Nr);
    runtimeA.destroy();
    runtimeB.destroy();
    restoredRuntime.destroy();
  });

  test("an unknown epoch is rejected before any ratchet mutation or persistence", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const runtimeA = pqRuntime(module, true);
    const runtimeB = pqRuntime(module, false);
    const epcA = pqEdge(alice, runtimeA);
    const epcB = pqEdge(bob, runtimeB);
    const persistNoop = async (): Promise<void> => {};

    const stepped = await ratchetEncryptDurably(
      epcA,
      "room-1",
      module,
      persistNoop,
    );
    const frame = sealChunk(
      stepped.messageKey,
      stepped.header,
      plaintexts[0],
      root,
      module,
      stepped.pqContext!,
    );
    const unknownEpoch = Uint8Array.from(frame);
    unknownEpoch[56] = 1; // pqEpoch u64 BE low byte: 0 -> 1

    const captures: EdgeCapture[] = [];
    const rejected = await decryptMessageChunkDurably(
      epcB,
      "room-1",
      unknownEpoch,
      epcB.messageKeyCache!,
      root,
      module,
      capturingPersist(captures),
    );
    expect(rejected.ok).toBe(false);
    expect(rejected.stateAdvanced).toBe(false);
    expect(bob.Nr).toBe(0);
    expect(captures).toHaveLength(0);
    expect(runtimeB.activeReceiveKeys.size).toBe(0);
    expect(runtimeB.messagesSinceHealing).toBe(0);
    runtimeA.destroy();
    runtimeB.destroy();
  });

  test("failed receive persistence keeps the combined key out of the cache, checkpoint, and live ratchet", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const runtimeA = pqRuntime(module, true);
    const runtimeB = pqRuntime(module, false);
    const epcA = pqEdge(alice, runtimeA);
    const epcB = pqEdge(bob, runtimeB);
    const persistNoop = async (): Promise<void> => {};

    const stepped = await ratchetEncryptDurably(
      epcA,
      "room-1",
      module,
      persistNoop,
    );
    const frame = sealChunk(
      stepped.messageKey,
      stepped.header,
      plaintexts[0],
      root,
      module,
      stepped.pqContext!,
    );

    await expect(
      decryptMessageChunkDurably(
        epcB,
        "room-1",
        frame,
        epcB.messageKeyCache!,
        root,
        module,
        async () => {
          throw new Error("injected persistence failure");
        },
      ),
    ).rejects.toThrow("injected persistence failure");

    expect(bob.Nr).toBe(0);
    expect(runtimeB.activeReceiveKeys.size).toBe(0);
    expect(runtimeB.messagesSinceHealing).toBe(0);
    const restored = restorePqRuntime(module, runtimeB.serialize(), false);
    expect(restored.activeReceiveKeys.size).toBe(0);
    restored.destroy();
    runtimeA.destroy();
    runtimeB.destroy();
  });

  test("durable retirement removes the key from the checkpoint before wiping the RAM copy", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const runtimeA = pqRuntime(module, true);
    const runtimeB = pqRuntime(module, false);
    const epcA = pqEdge(alice, runtimeA);
    const epcB = pqEdge(bob, runtimeB);
    const persistNoop = async (): Promise<void> => {};

    const stepped = await ratchetEncryptDurably(
      epcA,
      "room-1",
      module,
      persistNoop,
    );
    const frame = sealChunk(
      stepped.messageKey,
      stepped.header,
      plaintexts[0],
      root,
      module,
      stepped.pqContext!,
    );
    const epochKey = messageCacheKey(
      stepped.header.dhPub,
      stepped.header.N,
      0n,
    );

    const received = await decryptMessageChunkDurably(
      epcB,
      "room-1",
      frame,
      epcB.messageKeyCache!,
      root,
      module,
      persistNoop,
    );
    expect(received.ok).toBe(true);
    const ramCopy = runtimeB.activeReceiveKeys.get(epochKey);
    expect(ramCopy).toBeDefined();

    const captures: EdgeCapture[] = [];
    await forgetReceiveMessageKeyDurably(
      epcB,
      "room-1",
      epcB.messageKeyCache!,
      epochKey,
      capturingPersist(captures),
    );
    expect(captures).toHaveLength(1);
    const restored = restorePqRuntime(module, captures[0]!, false);
    expect(restored.activeReceiveKeys.has(epochKey)).toBe(false);
    restored.destroy();
    expect(runtimeB.activeReceiveKeys.has(epochKey)).toBe(false);
    expect(ramCopy!.every((byte) => byte === 0)).toBe(true);
    // Classical skipped map was never involved.
    expect(bob.skipped.size).toBe(0);

    // Retirement is idempotent and does not write again for a missing key.
    await forgetReceiveMessageKeyDurably(
      epcB,
      "room-1",
      epcB.messageKeyCache!,
      epochKey,
      capturingPersist(captures),
    );
    expect(captures).toHaveLength(1);
    runtimeA.destroy();
    runtimeB.destroy();
  });

  test("concurrent send and receive serialize under one edge lock with a consistent checkpoint", async () => {
    const { module, alice, bob } = await pair();
    const { root, plaintexts } = await buildMessage(module, 1);
    const runtimeA = pqRuntime(module, true);
    const runtimeB = pqRuntime(module, false);
    const epcA = pqEdge(alice, runtimeA);
    const epcB = pqEdge(bob, runtimeB);
    const persistNoop = async (): Promise<void> => {};

    const stepped = await ratchetEncryptDurably(
      epcA,
      "room-1",
      module,
      persistNoop,
    );
    const frame = sealChunk(
      stepped.messageKey,
      stepped.header,
      plaintexts[0],
      root,
      module,
      stepped.pqContext!,
    );
    const epochKey = messageCacheKey(
      stepped.header.dhPub,
      stepped.header.N,
      0n,
    );

    const [received, bobStep] = await Promise.all([
      decryptMessageChunkDurably(
        epcB,
        "room-1",
        frame,
        epcB.messageKeyCache!,
        root,
        module,
        persistNoop,
      ),
      ratchetEncryptDurably(epcB, "room-1", module, persistNoop),
    ]);
    expect(received.ok).toBe(true);
    expect(bobStep.pqContext).not.toBeNull();
    expect(bob.Nr).toBe(1);
    expect(bob.Ns).toBe(1);
    // Both transitions counted, and the final checkpoint carries the key.
    expect(runtimeB.messagesSinceHealing).toBe(2);
    const finalRestore = restorePqRuntime(module, runtimeB.serialize(), false);
    expect(finalRestore.activeReceiveKeys.has(epochKey)).toBe(true);
    finalRestore.destroy();
    bobStep.messageKey.fill(0);
    bobStep.pqContext?.rootKey.fill(0);
    runtimeA.destroy();
    runtimeB.destroy();
  });
});
