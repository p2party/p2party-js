import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  type CreateSessionOptions,
  type EncryptedSessionMessage,
  type GeneratedSessionIdentity,
  type HandshakeTransport,
  type P2PartySession,
} from "./session";
import type { RoomPqMode } from "./roomPolicy";
import {
  CHUNK_LEN,
  PROTOCOL_VERSION,
  WIRE_CHUNK_FRAME_LEN,
} from "./utils/constants";

const wasmFile = readFileSync(
  new URL("./cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = wasmFile.buffer.slice(
  wasmFile.byteOffset,
  wasmFile.byteOffset + wasmFile.byteLength,
) as ArrayBuffer;
const cryptoOptions = { wasmBinary };

const makeLink = () => {
  const queued: Uint8Array[] = [];
  const waiters: Array<(bytes: Uint8Array) => void> = [];
  return {
    send(bytes: Uint8Array): void {
      const owned = Uint8Array.from(bytes);
      const waiter = waiters.shift();
      if (waiter) waiter(owned);
      else queued.push(owned);
    },
    recv(): Promise<Uint8Array> {
      const bytes = queued.shift();
      if (bytes) return Promise.resolve(bytes);
      return new Promise((resolve) => waiters.push(resolve));
    },
  };
};

const wipeIdentity = (identity: GeneratedSessionIdentity): void => {
  identity.ed25519SecretKey.fill(0);
  identity.x25519SecretKey.fill(0);
};

interface Pair {
  alice: P2PartySession;
  bob: P2PartySession;
}

const createPair = async (
  auth:
    | { mode?: "nopin" }
    | { mode: "pin"; alicePin: Uint8Array; bobPin: Uint8Array } = {},
  pqMode: RoomPqMode = "hybrid-mlkem768",
): Promise<Pair> => {
  const [aliceIdentity, bobIdentity] = await Promise.all([
    generateSessionIdentity(cryptoOptions),
    generateSessionIdentity(cryptoOptions),
  ]);
  const aliceToBob = makeLink();
  const bobToAlice = makeLink();
  const channelId = new Uint8Array(16).fill(0x41);
  const aliceFingerprint = new Uint8Array(32).fill(0xa1);
  const bobFingerprint = new Uint8Array(32).fill(0xb2);

  const options = (
    role: "initiator" | "responder",
    identity: GeneratedSessionIdentity,
    peerIdentity: GeneratedSessionIdentity,
    transport: HandshakeTransport,
  ): CreateSessionOptions => {
    const common = {
      role,
      identity,
      peerIdentityEd25519PublicKey: peerIdentity.ed25519PublicKey,
      transport,
      channel: {
        channelId,
        localFingerprint:
          role === "initiator" ? aliceFingerprint : bobFingerprint,
        remoteFingerprint:
          role === "initiator" ? bobFingerprint : aliceFingerprint,
      },
      pqMode,
      crypto: cryptoOptions,
    };
    return auth.mode === "pin"
      ? {
          ...common,
          mode: "pin",
          pin: role === "initiator" ? auth.alicePin : auth.bobPin,
        }
      : { ...common, mode: "nopin" };
  };

  try {
    const [alice, bob] = await Promise.all([
      createSession(
        options("initiator", aliceIdentity, bobIdentity, {
          send: aliceToBob.send,
          recv: bobToAlice.recv,
        }),
      ),
      createSession(
        options("responder", bobIdentity, aliceIdentity, {
          send: bobToAlice.send,
          recv: aliceToBob.recv,
        }),
      ),
    ]);
    return { alice, bob };
  } finally {
    wipeIdentity(aliceIdentity);
    wipeIdentity(bobIdentity);
  }
};

const patternedBytes = (length: number, salt = 0): Uint8Array =>
  Uint8Array.from({ length }, (_, index) => (index * 131 + salt) & 0xff);

const expectBytes = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

describe("public store-free session API", () => {
  test("all room-selected ML-KEM suites handshake, persist provenance, and round-trip", async () => {
    const modes: RoomPqMode[] = [
      "hybrid-mlkem512",
      "hybrid-mlkem768",
      "hybrid-mlkem1024",
    ];

    for (const mode of modes) {
      const { alice, bob } = await createPair({}, mode);
      expect(alice.pqMode).toBe(mode);
      expect(bob.pqMode).toBe(mode);
      const plaintext = patternedBytes(513, mode.length);
      expectBytes(await bob.decrypt(await alice.encrypt(plaintext)), plaintext);

      const snapshot = await bob.serialize();
      const restored = await restoreSession(snapshot, cryptoOptions);
      expect(restored.pqMode).toBe(mode);
      snapshot.fill(0);
      await Promise.all([alice.destroy(), bob.destroy(), restored.destroy()]);
    }
  });

  test("no-PIN handshake + simultaneous first outbound round trip", async () => {
    const { alice, bob } = await createPair();
    expect(alice.protocolVersion).toBe(PROTOCOL_VERSION);
    expect(alice.canEncrypt).toBe(true);
    expect(bob.canEncrypt).toBe(true);

    const outbound = patternedBytes(CHUNK_LEN + 137, 7);
    const reply = patternedBytes(777, 19);
    // Both message-0 envelopes are produced before either session processes an
    // inbound frame, exercising the fresh responder's handshake-primed chain.
    const [encrypted, encryptedReply] = await Promise.all([
      alice.encrypt(outbound),
      bob.encrypt(reply),
    ]);
    expect(encrypted.protocolVersion).toBe(PROTOCOL_VERSION);
    expect(encrypted.root.length).toBe(64);
    expect(encrypted.frames).toHaveLength(2);
    expect(
      encrypted.frames.every((f) => f.length === WIRE_CHUNK_FRAME_LEN),
    ).toBe(true);

    const [receivedByBob, receivedByAlice] = await Promise.all([
      bob.decrypt(encrypted),
      alice.decrypt(encryptedReply),
    ]);
    expectBytes(receivedByBob, outbound);
    expectBytes(receivedByAlice, reply);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("whole-message decrypt accepts reversed frames and reconstructs order from encrypted metadata", async () => {
    const { alice, bob } = await createPair();
    const plaintext = patternedBytes(CHUNK_LEN + 31, 23);
    const encrypted = await alice.encrypt(plaintext);
    const reversed: EncryptedSessionMessage = {
      ...encrypted,
      frames: [...encrypted.frames].reverse(),
    };
    expectBytes(await bob.decrypt(reversed), plaintext);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("tampering rolls the entire receive state back; the authentic envelope still decrypts", async () => {
    const { alice, bob } = await createPair();
    const plaintext = patternedBytes(CHUNK_LEN + 55, 41);
    const encrypted = await alice.encrypt(plaintext);
    const before = await bob.serialize();
    const tampered: EncryptedSessionMessage = {
      ...encrypted,
      root: Uint8Array.from(encrypted.root),
      frames: encrypted.frames.map((frame) => Uint8Array.from(frame)),
    };
    tampered.frames[1][100] ^= 0x80;

    await expect(bob.decrypt(tampered)).rejects.toThrow();
    expectBytes(await bob.serialize(), before);
    expectBytes(await bob.decrypt(encrypted), plaintext);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("missing and duplicate frames reject atomically", async () => {
    const { alice, bob } = await createPair();
    const plaintext = patternedBytes(CHUNK_LEN + 80, 29);
    const encrypted = await alice.encrypt(plaintext);
    const before = await bob.serialize();

    await expect(
      bob.decrypt({ ...encrypted, frames: encrypted.frames.slice(0, 1) }),
    ).rejects.toThrow();
    expectBytes(await bob.serialize(), before);
    await expect(
      bob.decrypt({
        ...encrypted,
        frames: [encrypted.frames[0], encrypted.frames[0]],
      }),
    ).rejects.toThrow();
    expectBytes(await bob.serialize(), before);
    expectBytes(await bob.decrypt(encrypted), plaintext);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("skipped logical-message keys survive serialization", async () => {
    const original = await createPair();
    const firstPlaintext = patternedBytes(401, 31);
    const secondPlaintext = patternedBytes(402, 32);
    const [first, second] = await Promise.all([
      original.alice.encrypt(firstPlaintext),
      original.alice.encrypt(secondPlaintext),
    ]);

    // Receiving N=1 first stores N=0 in the skipped-key map.
    expectBytes(await original.bob.decrypt(second), secondPlaintext);
    const bobSnapshot = await original.bob.serialize();
    const restoredBob = await restoreSession(bobSnapshot, cryptoOptions);
    await original.bob.destroy();
    expectBytes(await restoredBob.decrypt(first), firstPlaintext);

    await Promise.all([original.alice.destroy(), restoredBob.destroy()]);
  });

  test("serialize/restore preserves both directions across a message boundary", async () => {
    const original = await createPair();
    const first = patternedBytes(333, 5);
    expectBytes(
      await original.bob.decrypt(await original.alice.encrypt(first)),
      first,
    );

    const aliceSnapshot = await original.alice.serialize();
    const bobSnapshot = await original.bob.serialize();
    const [alice, bob] = await Promise.all([
      restoreSession(aliceSnapshot, cryptoOptions),
      restoreSession(bobSnapshot, cryptoOptions),
    ]);
    await Promise.all([original.alice.destroy(), original.bob.destroy()]);

    const reply = patternedBytes(CHUNK_LEN + 9, 77);
    expectBytes(await alice.decrypt(await bob.encrypt(reply)), reply);
    const next = patternedBytes(2048, 11);
    expectBytes(await bob.decrypt(await alice.encrypt(next)), next);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("snapshots require explicit ML-KEM-768 root-suite provenance", async () => {
    const { alice, bob } = await createPair();
    const snapshot = await alice.serialize();

    // "P2PSESS\0" occupies bytes 0..7; format v3 and root-suite byte 3 reject
    // pre-draft-21 CPace / pre-interactive-3DH roots.
    expect(snapshot[8]).toBe(3);
    expect(snapshot[11]).toBe(3);

    const preHybrid = Uint8Array.from(snapshot);
    preHybrid[8] = 2;
    await expect(restoreSession(preHybrid, cryptoOptions)).rejects.toThrow(
      "unsupported snapshot version",
    );

    const untagged = Uint8Array.from(snapshot);
    untagged[11] = 0;
    await expect(restoreSession(untagged, cryptoOptions)).rejects.toThrow(
      "unsupported root suite",
    );

    const preIdentityPossession = Uint8Array.from(snapshot);
    preIdentityPossession[11] = 1;
    await expect(
      restoreSession(preIdentityPossession, cryptoOptions),
    ).rejects.toThrow("unsupported root suite");

    snapshot.fill(0);
    preHybrid.fill(0);
    untagged.fill(0);
    preIdentityPossession.fill(0);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("serialize waits for an in-flight encrypt before snapshotting the ratchet", async () => {
    const original = await createPair();
    const firstPlaintext = patternedBytes(CHUNK_LEN + 17, 61);

    // Do not await encrypt before requesting the snapshot: serialize must queue
    // behind it or the restored sender would reuse the first message's N/key.
    const inFlightEncryption = original.alice.encrypt(firstPlaintext);
    const queuedSnapshot = original.alice.serialize();
    const [firstEncrypted, snapshot] = await Promise.all([
      inFlightEncryption,
      queuedSnapshot,
    ]);

    const restoredAlice = await restoreSession(snapshot, cryptoOptions);
    await original.alice.destroy();
    expectBytes(await original.bob.decrypt(firstEncrypted), firstPlaintext);

    const secondPlaintext = patternedBytes(511, 62);
    expectBytes(
      await original.bob.decrypt(await restoredAlice.encrypt(secondPlaintext)),
      secondPlaintext,
    );
    snapshot.fill(0);
    await Promise.all([restoredAlice.destroy(), original.bob.destroy()]);
  });

  test("rejects missing, unknown, and internally inconsistent auth modes", async () => {
    const identity = await generateSessionIdentity(cryptoOptions);
    const base = {
      role: "initiator" as const,
      identity,
      peerIdentityEd25519PublicKey: new Uint8Array(32),
      transport: {
        send: () => undefined,
        recv: () => Promise.resolve(new Uint8Array()),
      },
      channel: {
        channelId: new Uint8Array([1]),
        localFingerprint: new Uint8Array(32),
        remoteFingerprint: new Uint8Array(32),
      },
      crypto: cryptoOptions,
    };
    try {
      await expect(
        createSession(base as unknown as CreateSessionOptions),
      ).rejects.toThrow("mode must be pin or nopin");
      await expect(
        createSession({
          ...base,
          mode: "password",
        } as unknown as CreateSessionOptions),
      ).rejects.toThrow("mode must be pin or nopin");
      await expect(
        createSession({
          ...base,
          mode: "nopin",
          pin: new Uint8Array([1]),
        } as unknown as CreateSessionOptions),
      ).rejects.toThrow("pin must not be provided in nopin mode");
      await expect(
        createSession({
          ...base,
          mode: "pin",
        } as unknown as CreateSessionOptions),
      ).rejects.toThrow("pin must be a Uint8Array");
      await expect(
        createSession({
          ...base,
          mode: "pin",
          pin: new Uint8Array(),
        }),
      ).rejects.toThrow("pin must not be empty");
    } finally {
      wipeIdentity(identity);
    }
  });

  test("matching PIN succeeds; different PINs reject both handshake legs", async () => {
    const pin = new TextEncoder().encode("correct horse battery staple");
    const matched = await createPair({
      mode: "pin",
      alicePin: pin,
      bobPin: pin,
    });
    expectBytes(
      await matched.bob.decrypt(
        await matched.alice.encrypt(new Uint8Array([1, 2, 3])),
      ),
      new Uint8Array([1, 2, 3]),
    );
    await Promise.all([matched.alice.destroy(), matched.bob.destroy()]);

    const [aliceIdentity, bobIdentity] = await Promise.all([
      generateSessionIdentity(cryptoOptions),
      generateSessionIdentity(cryptoOptions),
    ]);
    const ab = makeLink();
    const ba = makeLink();
    const base = {
      channel: {
        channelId: new Uint8Array([1]),
        localFingerprint: new Uint8Array(32).fill(1),
        remoteFingerprint: new Uint8Array(32).fill(2),
      },
      crypto: cryptoOptions,
      mode: "pin" as const,
    };
    const results = await Promise.allSettled([
      createSession({
        ...base,
        role: "initiator",
        identity: aliceIdentity,
        peerIdentityEd25519PublicKey: bobIdentity.ed25519PublicKey,
        transport: { send: ab.send, recv: ba.recv },
        pin: new TextEncoder().encode("one"),
      }),
      createSession({
        ...base,
        role: "responder",
        identity: bobIdentity,
        peerIdentityEd25519PublicKey: aliceIdentity.ed25519PublicKey,
        transport: { send: ba.send, recv: ab.recv },
        channel: {
          channelId: base.channel.channelId,
          localFingerprint: base.channel.remoteFingerprint,
          remoteFingerprint: base.channel.localFingerprint,
        },
        pin: new TextEncoder().encode("two"),
      }),
    ]);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    wipeIdentity(aliceIdentity);
    wipeIdentity(bobIdentity);
  });

  test("rejects Ed25519-sized X25519 secrets, corrupt snapshots, and use after destroy", async () => {
    const identity = await generateSessionIdentity(cryptoOptions);
    await expect(
      createSession({
        role: "initiator",
        identity: {
          ...identity,
          x25519SecretKey: new Uint8Array(64),
        },
        peerIdentityEd25519PublicKey: new Uint8Array(32),
        transport: {
          send: () => undefined,
          recv: () => Promise.resolve(new Uint8Array()),
        },
        channel: {
          channelId: new Uint8Array([1]),
          localFingerprint: new Uint8Array(32),
          remoteFingerprint: new Uint8Array(32),
        },
        mode: "nopin",
        crypto: cryptoOptions,
      }),
    ).rejects.toThrow("x25519SecretKey must be 32 bytes");
    wipeIdentity(identity);

    const { alice, bob } = await createPair();
    const snapshot = await alice.serialize();
    const badMagic = Uint8Array.from(snapshot);
    badMagic[0] ^= 0xff;
    await expect(restoreSession(badMagic, cryptoOptions)).rejects.toThrow(
      "invalid magic",
    );
    await expect(
      restoreSession(snapshot.subarray(0, snapshot.length - 1), cryptoOptions),
    ).rejects.toThrow();

    await alice.destroy();
    expect(alice.canEncrypt).toBe(false);
    await expect(alice.serialize()).rejects.toThrow("destroyed");
    await expect(alice.encrypt(new Uint8Array([1]))).rejects.toThrow(
      "destroyed",
    );
    await bob.destroy();
  });

  test("rejects imported identities whose X25519 keypair or cross-signature is inconsistent", async () => {
    const identity = await generateSessionIdentity(cryptoOptions);
    const base = {
      role: "initiator" as const,
      peerIdentityEd25519PublicKey: identity.ed25519PublicKey,
      transport: {
        send: () => undefined,
        recv: () => Promise.resolve(new Uint8Array()),
      },
      channel: {
        channelId: new Uint8Array([1]),
        localFingerprint: new Uint8Array(32),
        remoteFingerprint: new Uint8Array(32),
      },
      mode: "nopin" as const,
      crypto: cryptoOptions,
    };

    try {
      const wrongPublic = Uint8Array.from(identity.x25519PublicKey);
      wrongPublic[0] ^= 0x80;
      await expect(
        createSession({
          ...base,
          identity: { ...identity, x25519PublicKey: wrongPublic },
        }),
      ).rejects.toThrow("public and secret keys do not match");

      const wrongSignature = Uint8Array.from(identity.x25519CrossSignature);
      wrongSignature[0] ^= 0x80;
      await expect(
        createSession({
          ...base,
          identity: {
            ...identity,
            x25519CrossSignature: wrongSignature,
          },
        }),
      ).rejects.toThrow("cross-signature is invalid");
    } finally {
      wipeIdentity(identity);
    }
  });

  test("awaits and propagates an asynchronous transport send failure", async () => {
    const identity = await generateSessionIdentity(cryptoOptions);
    let recvCalled = false;
    try {
      await expect(
        createSession({
          role: "initiator",
          identity,
          peerIdentityEd25519PublicKey: identity.ed25519PublicKey,
          transport: {
            send: async () => {
              await Promise.resolve();
              throw new Error("async transport write failed");
            },
            recv: () => {
              recvCalled = true;
              return Promise.resolve(new Uint8Array());
            },
          },
          channel: {
            channelId: new Uint8Array([1]),
            localFingerprint: new Uint8Array(32),
            remoteFingerprint: new Uint8Array(32),
          },
          mode: "nopin",
          crypto: cryptoOptions,
        }),
      ).rejects.toThrow("async transport write failed");
      expect(recvCalled).toBe(false);
    } finally {
      wipeIdentity(identity);
    }
  });
});
