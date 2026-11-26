import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  SessionReplayError,
  type CreateSessionOptions,
  type EncryptedSessionMessage,
  type GeneratedSessionIdentity,
  type HandshakeTransport,
  type P2PartySession,
} from "../src/session";
import type { RoomPqMode } from "../src/roomPolicy";
import {
  CHUNK_LEN,
  PROTOCOL_VERSION,
  WIRE_CHUNK_FRAME_LEN,
} from "../src/utils/constants";

const wasmFile = readFileSync(
  new URL("../src/cryptography/libcrypto.wasm", import.meta.url),
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

const expectReplayRejected = async (
  attempt: Promise<unknown>,
): Promise<void> => {
  await expect(attempt).rejects.toBeInstanceOf(SessionReplayError);
};

// One logical message each way, so every round turns both DH ratchets.
const pingPong = async (
  alice: P2PartySession,
  bob: P2PartySession,
  round: number,
): Promise<void> => {
  const forward = patternedBytes(24, round);
  expectBytes(await bob.decrypt(await alice.encrypt(forward)), forward);
  const back = patternedBytes(24, round + 1);
  expectBytes(await alice.decrypt(await bob.encrypt(back)), back);
};

interface FixtureMessage {
  plaintext: string;
  root: string;
  frames: string[];
}

const readFixture = (name: string): unknown =>
  JSON.parse(
    readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"),
  );

// Both written by the format-4 session code of p2party 0.14.10 (commit
// 62661e0), before the replay record existed; see their description fields.
const v4Fixture = readFixture("session-snapshot-v4.json") as {
  aliceSnapshot: string;
  bobSnapshot: string;
  messages: Record<
    "previousChain" | "currentChain" | "pendingSkipped",
    FixtureMessage
  >;
};
const v4SkippedFixture = readFixture(
  "session-snapshot-v4-skipped-superseded.json",
) as { bobSnapshot: string; skippedOnSupersededChain: FixtureMessage };

const fromBase64 = (value: string): Uint8Array =>
  Uint8Array.from(Buffer.from(value, "base64"));

const fixtureEnvelope = (message: FixtureMessage): EncryptedSessionMessage => ({
  protocolVersion: PROTOCOL_VERSION,
  root: fromBase64(message.root),
  frames: message.frames.map(fromBase64),
});

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

    // "P2PSESS\0" occupies bytes 0..7; format 5 (format 4 plus the replay
    // record) and root-suite byte 3 reject pre-draft-21 CPace /
    // pre-interactive-3DH roots. A v3 snapshot is rejected outright; format 4
    // is still read (see "restores a 0.14.10 snapshot").
    expect(snapshot[8]).toBe(5);
    expect(snapshot[11]).toBe(3);

    const preHybrid = Uint8Array.from(snapshot);
    preHybrid[8] = 3;
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

// Drive the store-free healing handshake between two sessions with the
// persist-before-send contract: whenever a call returns a frame, snapshot
// before delivering it. Returns nothing; both sessions advance in place.
const runSessionHealing = async (
  offerer: P2PartySession,
  accepter: P2PartySession,
): Promise<void> => {
  const offer = await offerer.prepareHealing();
  expect(offer.requiresPersistBeforeSend).toBe(true);
  if (!offer.frame) throw new Error("expected an OFFER frame");
  await offerer.serialize(); // persist-before-send

  const advance = await accepter.acceptControlFrame(offer.frame);
  expect(advance.requiresPersistBeforeSend).toBe(true);
  if (!advance.frame) throw new Error("expected an ADVANCE frame");
  await accepter.serialize();

  const ack = await offerer.acceptControlFrame(advance.frame);
  expect(ack.requiresPersistBeforeSend).toBe(true);
  if (!ack.frame) throw new Error("expected an ACK frame");
  await offerer.serialize();

  const settled = await accepter.acceptControlFrame(ack.frame);
  expect(settled.frame).toBeNull();
  await accepter.serialize();
};

describe("public store-free session sparse-PQ healing", () => {
  test("prepareHealing is not due before the message/time threshold", async () => {
    const { alice, bob } = await createPair();
    expect(alice.pqEpoch).toBe(0n);
    expect(bob.pqEpoch).toBe(0n);
    expect(alice.healingInProgress).toBe(false);
    const early = await alice.prepareHealing();
    expect(early.frame).toBeNull();
    expect(early.requiresPersistBeforeSend).toBe(false);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("a healing exchange advances both sessions to a shared epoch and messages keep round-tripping", async () => {
    const { alice, bob } = await createPair();

    // Reach the message threshold so the initiator's exchange is due.
    for (let index = 0; index < 64; index += 1)
      await bob.decrypt(await alice.encrypt(patternedBytes(97, index)));

    await runSessionHealing(alice, bob);
    expect(alice.pqEpoch).toBe(1n);
    expect(bob.pqEpoch).toBe(1n);
    expect(alice.healingInProgress).toBe(false);
    expect(bob.healingInProgress).toBe(false);

    // Messages under the new epoch still decrypt, both directions.
    const afterHeal = patternedBytes(CHUNK_LEN + 3, 200);
    expectBytes(await bob.decrypt(await alice.encrypt(afterHeal)), afterHeal);
    const reply = patternedBytes(321, 201);
    expectBytes(await alice.decrypt(await bob.encrypt(reply)), reply);

    // A snapshot taken after healing restores at the new epoch and keeps
    // decrypting messages sealed under it.
    const snapshot = await bob.serialize();
    const restoredBob = await restoreSession(snapshot, cryptoOptions);
    expect(restoredBob.pqEpoch).toBe(1n);
    const postRestore = patternedBytes(CHUNK_LEN + 9, 202);
    expectBytes(
      await restoredBob.decrypt(await alice.encrypt(postRestore)),
      postRestore,
    );
    snapshot.fill(0);
    await Promise.all([
      alice.destroy(),
      bob.destroy(),
      restoredBob.destroy(),
    ]);
  });

  test("encrypt is blocked while a healing exchange is mid-flight", async () => {
    const { alice, bob } = await createPair();
    for (let index = 0; index < 64; index += 1)
      await bob.decrypt(await alice.encrypt(patternedBytes(64, index)));

    const offer = await alice.prepareHealing();
    if (!offer.frame) throw new Error("expected an OFFER frame");
    expect(alice.healingInProgress).toBe(true);
    expect(alice.canEncrypt).toBe(false);
    await expect(alice.encrypt(patternedBytes(10))).rejects.toThrow(
      "healing is in progress",
    );

    // Completing the exchange re-opens application traffic.
    const advance = await bob.acceptControlFrame(offer.frame);
    if (!advance.frame) throw new Error("expected ADVANCE");
    const ack = await alice.acceptControlFrame(advance.frame);
    if (!ack.frame) throw new Error("expected ACK");
    await bob.acceptControlFrame(ack.frame);
    expect(alice.healingInProgress).toBe(false);
    expect(alice.canEncrypt).toBe(true);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("a dropped ACK is answered from the duplicate cache without a new write", async () => {
    const { alice, bob } = await createPair();
    for (let index = 0; index < 64; index += 1)
      await bob.decrypt(await alice.encrypt(patternedBytes(48, index)));

    const offer = await alice.prepareHealing();
    if (!offer.frame) throw new Error("expected OFFER");
    const advance = await bob.acceptControlFrame(offer.frame);
    if (!advance.frame) throw new Error("expected ADVANCE");
    const ack = await alice.acceptControlFrame(advance.frame);
    if (!ack.frame) throw new Error("expected ACK");
    expect(alice.pqEpoch).toBe(1n);

    // The ACK is lost; bob retransmits the exact ADVANCE (its pending control),
    // and alice re-answers the exact ACK without persisting again.
    const pending = await bob.pendingControl();
    if (!pending) throw new Error("expected a pending ADVANCE");
    expectBytes(pending, advance.frame);
    const duplicateAck = await alice.acceptControlFrame(pending);
    expect(duplicateAck.requiresPersistBeforeSend).toBe(false);
    if (!duplicateAck.frame) throw new Error("expected duplicate ACK");
    expectBytes(duplicateAck.frame, ack.frame);
    await bob.acceptControlFrame(duplicateAck.frame);
    expect(bob.pqEpoch).toBe(1n);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });
});

// These sessions never call prepareHealing(), so they stay at pqEpoch 0 by
// design: healing is caller-driven in the store-free API.
describe("public store-free session replay rejection and bounded receive state", () => {
  test("rejects a replayed message", async () => {
    const { alice, bob } = await createPair();
    const plaintext = patternedBytes(CHUNK_LEN + 9, 3);
    const message = await alice.encrypt(plaintext);
    expectBytes(await bob.decrypt(message), plaintext);
    const afterFirst = await bob.serialize();

    await expectReplayRejected(bob.decrypt(message));
    await expectReplayRejected(
      bob.decrypt({ ...message, frames: [...message.frames].reverse() }),
    );
    // A rejected replay commits nothing.
    expectBytes(await bob.serialize(), afterFirst);

    // Bob replies and Alice's next message opens a new chain, so the replayed
    // message now belongs to a chain Bob has superseded.
    await pingPong(alice, bob, 10);
    const next = patternedBytes(77, 4);
    expectBytes(await bob.decrypt(await alice.encrypt(next)), next);
    await expectReplayRejected(bob.decrypt(message));

    const after = patternedBytes(78, 5);
    expectBytes(await bob.decrypt(await alice.encrypt(after)), after);
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("concurrent deliveries of one message decrypt it once", async () => {
    const { alice, bob } = await createPair();
    const plaintext = patternedBytes(CHUNK_LEN + 1, 8);
    const message = await alice.encrypt(plaintext);

    const outcomes = await Promise.allSettled([
      bob.decrypt(message),
      bob.decrypt(message),
    ]);
    const fulfilled = outcomes.filter((o) => o.status === "fulfilled");
    const rejected = outcomes.filter((o) => o.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expectBytes(
      (fulfilled[0] as PromiseFulfilledResult<Uint8Array>).value,
      plaintext,
    );
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      SessionReplayError,
    );
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("a message decrypted before a healing exchange stays rejected after it", async () => {
    const { alice, bob } = await createPair();
    const firstPlaintext = patternedBytes(48, 70);
    const first = await alice.encrypt(firstPlaintext);
    expectBytes(await bob.decrypt(first), firstPlaintext);
    for (let index = 1; index < 64; index += 1)
      await bob.decrypt(await alice.encrypt(patternedBytes(48, index)));

    await runSessionHealing(alice, bob);
    expect(bob.pqEpoch).toBe(1n);
    await expectReplayRejected(bob.decrypt(first));

    const healedPlaintext = patternedBytes(49, 71);
    const healed = await alice.encrypt(healedPlaintext);
    expectBytes(await bob.decrypt(healed), healedPlaintext);
    await expectReplayRejected(bob.decrypt(healed));
    await Promise.all([alice.destroy(), bob.destroy()]);
  });

  test("rejects a replay after serialize and restore", async () => {
    const { alice, bob } = await createPair();
    const firstPlaintext = patternedBytes(100, 1);
    const first = await alice.encrypt(firstPlaintext);
    expectBytes(await bob.decrypt(first), firstPlaintext);

    const restored = await restoreSession(await bob.serialize(), cryptoOptions);
    await bob.destroy();
    await expectReplayRejected(restored.decrypt(first));

    // Supersede the first message's chain, then restore again.
    const reply = patternedBytes(60, 2);
    expectBytes(await alice.decrypt(await restored.encrypt(reply)), reply);
    const secondPlaintext = patternedBytes(90, 3);
    const second = await alice.encrypt(secondPlaintext);
    expectBytes(await restored.decrypt(second), secondPlaintext);

    const restoredAgain = await restoreSession(
      await restored.serialize(),
      cryptoOptions,
    );
    await restored.destroy();
    await expectReplayRejected(restoredAgain.decrypt(first));
    await expectReplayRejected(restoredAgain.decrypt(second));

    const third = patternedBytes(33, 4);
    expectBytes(await restoredAgain.decrypt(await alice.encrypt(third)), third);
    await Promise.all([alice.destroy(), restoredAgain.destroy()]);
  });

  test("serialize succeeds after 1000 one-way messages", async () => {
    const { alice, bob } = await createPair();
    for (let index = 0; index < 1000; index += 1) {
      const plaintext = patternedBytes(16, index);
      expectBytes(await bob.decrypt(await alice.encrypt(plaintext)), plaintext);
      (await bob.serialize()).fill(0);
    }
    const restored = await restoreSession(await bob.serialize(), cryptoOptions);
    const last = patternedBytes(16, 1000);
    expectBytes(await restored.decrypt(await alice.encrypt(last)), last);
    await Promise.all([alice.destroy(), bob.destroy(), restored.destroy()]);
  }, 120_000);

  test("serialize succeeds after 1000 ping-pong rounds", async () => {
    const { alice, bob } = await createPair();
    for (let round = 0; round < 1000; round += 1) {
      await pingPong(alice, bob, round);
      (await alice.serialize()).fill(0);
      (await bob.serialize()).fill(0);
    }
    const [restoredAlice, restoredBob] = await Promise.all([
      restoreSession(await alice.serialize(), cryptoOptions),
      restoreSession(await bob.serialize(), cryptoOptions),
    ]);
    await Promise.all([alice.destroy(), bob.destroy()]);
    await pingPong(restoredAlice, restoredBob, 1000);
    await Promise.all([restoredAlice.destroy(), restoredBob.destroy()]);
  }, 120_000);

  test("snapshot size is flat for in-order traffic", async () => {
    // One direction: a single receiving chain, so the receiver's snapshot
    // is the same size after every message.
    const oneWay = await createPair();
    const oneWaySizes = new Set<number>();
    for (let index = 0; index < 300; index += 1) {
      const plaintext = patternedBytes(16, index);
      await oneWay.bob.decrypt(await oneWay.alice.encrypt(plaintext));
      oneWaySizes.add((await oneWay.bob.serialize()).length);
    }
    expect([...oneWaySizes]).toHaveLength(1);
    await Promise.all([oneWay.alice.destroy(), oneWay.bob.destroy()]);

    // Alternating: every round supersedes one receiving chain per side. The
    // record of superseded chains is capped, so the size stops changing.
    const alternating = await createPair();
    const sizesAfterCap = new Set<string>();
    for (let round = 0; round < 400; round += 1) {
      await pingPong(alternating.alice, alternating.bob, round);
      if (round >= 300)
        sizesAfterCap.add(
          `${String((await alternating.alice.serialize()).length)}/${String(
            (await alternating.bob.serialize()).length,
          )}`,
        );
    }
    expect([...sizesAfterCap]).toHaveLength(1);
    await Promise.all([alternating.alice.destroy(), alternating.bob.destroy()]);
  }, 120_000);

  test("out-of-order messages inside the skip window decrypt exactly once", async () => {
    const { alice, bob } = await createPair();
    const plaintexts = Array.from({ length: 5 }, (_, index) =>
      patternedBytes(64 + index, 50 + index),
    );
    const messages: EncryptedSessionMessage[] = [];
    for (const plaintext of plaintexts)
      messages.push(await alice.encrypt(plaintext));

    for (const index of [3, 0, 4, 1, 2]) {
      expectBytes(await bob.decrypt(messages[index]), plaintexts[index]);
      await expectReplayRejected(bob.decrypt(messages[index]));
    }
    for (const message of messages)
      await expectReplayRejected(bob.decrypt(message));

    // A key skipped on a chain that is later superseded still opens its
    // message once, including after a restore.
    const latePlaintext = patternedBytes(41, 90);
    const late = await alice.encrypt(latePlaintext);
    const deliveredPlaintext = patternedBytes(42, 91);
    const delivered = await alice.encrypt(deliveredPlaintext);
    expectBytes(await bob.decrypt(delivered), deliveredPlaintext);
    await pingPong(alice, bob, 92);
    const newChainPlaintext = patternedBytes(43, 93);
    expectBytes(
      await bob.decrypt(await alice.encrypt(newChainPlaintext)),
      newChainPlaintext,
    );

    const restored = await restoreSession(await bob.serialize(), cryptoOptions);
    await bob.destroy();
    expectBytes(await restored.decrypt(late), latePlaintext);
    await expectReplayRejected(restored.decrypt(late));
    await expectReplayRejected(restored.decrypt(delivered));
    await expectReplayRejected(restored.decrypt(messages[3]));
    await Promise.all([alice.destroy(), restored.destroy()]);
  });

  test("restores a 0.14.10 snapshot", async () => {
    const { messages } = v4Fixture;
    const bobSnapshot = fromBase64(v4Fixture.bobSnapshot);
    expect(bobSnapshot[8]).toBe(4);
    const [alice, bob] = await Promise.all([
      restoreSession(fromBase64(v4Fixture.aliceSnapshot), cryptoOptions),
      restoreSession(bobSnapshot, cryptoOptions),
    ]);
    const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

    // The message skipped before the upgrade opens once.
    expect(
      text(await bob.decrypt(fixtureEnvelope(messages.pendingSkipped))),
    ).toBe(messages.pendingSkipped.plaintext);
    await expectReplayRejected(
      bob.decrypt(fixtureEnvelope(messages.pendingSkipped)),
    );
    // Messages 0.14.10 already returned stay rejected: on the current
    // receiving chain and on the chain it superseded.
    await expectReplayRejected(
      bob.decrypt(fixtureEnvelope(messages.currentChain)),
    );
    await expectReplayRejected(
      bob.decrypt(fixtureEnvelope(messages.previousChain)),
    );

    // Both directions keep working.
    await pingPong(alice, bob, 7);

    const upgraded = await bob.serialize();
    expect(upgraded[8]).toBe(5);
    const restoredAgain = await restoreSession(upgraded, cryptoOptions);
    await bob.destroy();
    await expectReplayRejected(
      restoredAgain.decrypt(fixtureEnvelope(messages.previousChain)),
    );
    await pingPong(alice, restoredAgain, 8);
    await Promise.all([alice.destroy(), restoredAgain.destroy()]);
  });

  test("a key skipped on a chain 0.14.10 superseded opens its message once after restore", async () => {
    const message = v4SkippedFixture.skippedOnSupersededChain;
    const bob = await restoreSession(
      fromBase64(v4SkippedFixture.bobSnapshot),
      cryptoOptions,
    );
    expect(
      new TextDecoder().decode(await bob.decrypt(fixtureEnvelope(message))),
    ).toBe(message.plaintext);
    await expectReplayRejected(bob.decrypt(fixtureEnvelope(message)));

    const restoredAgain = await restoreSession(
      await bob.serialize(),
      cryptoOptions,
    );
    await bob.destroy();
    await expectReplayRejected(restoredAgain.decrypt(fixtureEnvelope(message)));
    await restoredAgain.destroy();
  });
});
