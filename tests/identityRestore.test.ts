import { describe, expect, test } from "bun:test";

// The store reads localStorage at module load and the public-surface check
// imports the SDK entry point, so the shim has to exist before any of these
// imports are evaluated. Static imports hoist, hence the dynamic form.
const memory = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage = {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => memory.set(key, value),
  removeItem: (key: string) => memory.delete(key),
  clear: () => memory.clear(),
  key: () => null,
  length: 0,
};

const {
  InvalidRecoveryPhraseError,
  createRecoverableIdentityWith,
  restoreIdentityFromMnemonicWith,
} = await import("../src/utils/identityRestore");
const { keyPairFromMnemonic } = await import("../src/cryptography/mnemonic");

import type {
  DerivedIdentityKeyPair,
  IdentityRestoreEffects,
} from "../src/utils/identityRestore";

/** Reused from tests/cryptography/mnemonic.test.ts: a phrase whose checksum is valid. */
const KAT_MNEMONIC =
  "adapt patrol eternal modify make run common noble salute lecture detail air";
/** The same entropy with the last word replaced, so only the checksum rejects it. */
const KAT_MNEMONIC_CORRUPTED =
  "adapt patrol eternal modify make run common noble salute lecture detail zoo";

/**
 * Argon2id over a 75 MiB heap costs roughly 0.4 s per derivation here. Only
 * the round-trip test runs the real thing, and it needs two derivations.
 */
const DERIVATION_TIMEOUT_MS = 60_000;

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

/**
 * A stand-in for everything restore touches: the signaling socket, the room
 * transports, both identity records, the derivation flag and the in-memory
 * identity. Durable room data lives here too, so a step that deleted it would
 * be visible.
 */
const harness = (
  derive: (
    mnemonic: string,
    password?: string,
  ) => Promise<DerivedIdentityKeyPair>,
  /** Replaces individual effects with failing ones, sharing the same log. */
  failing?: (order: string[]) => Partial<IdentityRestoreEffects>,
) => {
  const order: string[] = [];
  const rooms = [
    { id: "room-1", transportOpen: true, messages: ["kept"] },
    { id: "room-2", transportOpen: true, messages: ["also kept"] },
  ];
  const addressBook = ["a peer"];
  const stored = {
    ed25519: { publicKey: "old".padEnd(64, "0"), secretKey: "old" },
    x25519: true as boolean | false,
    derivation: "random" as string | null,
  };
  const redux = {
    publicKey: "old".padEnd(64, "0"),
    secretKey: "old",
    peerId: "a peer id bound to the old identity",
  };
  /** The exact buffer handed to the write step, so its wiping can be observed. */
  let writtenSecretBuffer: Uint8Array | undefined;
  let socketConnected = true;

  const working: IdentityRestoreEffects = {
    deriveIdentity: async (mnemonic, password) => {
      order.push("derive");
      return await derive(mnemonic, password);
    },
    runExclusive: async (operation) => {
      order.push("exclusive-enter");
      try {
        return await operation();
      } finally {
        order.push("exclusive-exit");
      }
    },
    disconnectSignaling: () => {
      order.push("disconnect");
      socketConnected = false;
    },
    teardownRooms: () => {
      order.push("rooms-terminal");
      for (const room of rooms) room.transportOpen = false;
    },
    deleteIdentityX25519: () => {
      order.push("x25519-deleted");
      stored.x25519 = false;
    },
    writeIdentityEd25519: (identity) => {
      order.push("ed25519-written");
      writtenSecretBuffer = identity.secretKey;
      stored.ed25519 = {
        publicKey: toHex(identity.publicKey),
        secretKey: toHex(identity.secretKey),
      };
    },
    recordDerivation: () => {
      order.push("derivation-recorded");
      stored.derivation = "mnemonic";
    },
    resetIdentityState: () => {
      order.push("identity-reset");
      redux.publicKey = "";
      redux.secretKey = "";
      redux.peerId = "";
    },
    adoptIdentity: (publicKey, secretKey) => {
      order.push("adopted");
      redux.publicKey = publicKey;
      redux.secretKey = secretKey;
    },
  };

  return {
    order,
    rooms,
    addressBook,
    stored,
    redux,
    effects: { ...working, ...failing?.(order) } as IdentityRestoreEffects,
    get writtenSecretBuffer() {
      return writtenSecretBuffer;
    },
    get socketConnected() {
      return socketConnected;
    },
  };
};

/** A derivation that costs nothing, for every test that is not about argon2id. */
const stubDerivation = (seed: number) => {
  const calls: { mnemonic: string; password?: string }[] = [];
  const derive = async (
    mnemonic: string,
    password?: string,
  ): Promise<DerivedIdentityKeyPair> => {
    calls.push({ mnemonic, password });
    return {
      publicKey: new Uint8Array(32).fill(seed),
      secretKey: new Uint8Array(64).fill(seed + 1),
    };
  };

  return { calls, derive };
};

describe("restoring an identity from its recovery phrase", () => {
  test("an invalid phrase rejects before anything is torn down", async () => {
    const { calls, derive } = stubDerivation(0x11);
    const fake = harness(derive);

    const failing = restoreIdentityFromMnemonicWith(
      fake.effects,
      KAT_MNEMONIC_CORRUPTED,
    );

    await expect(failing).rejects.toBeInstanceOf(InvalidRecoveryPhraseError);
    await expect(failing).rejects.toThrow(/checksum/i);

    // Not one lifecycle step ran: no derivation, no exclusive boundary, no
    // socket teardown. A mistyped phrase must cost the user nothing.
    expect(calls).toEqual([]);
    expect(fake.order).toEqual([]);
    expect(fake.socketConnected).toBe(true);
    expect(fake.stored.x25519).toBe(true);
    expect(fake.stored.derivation).toBe("random");
    expect(fake.redux.peerId).toBe("a peer id bound to the old identity");
  });

  test("a phrase with an unknown word names the word it could not read", async () => {
    const { derive } = stubDerivation(0x22);
    const fake = harness(derive);
    const words = KAT_MNEMONIC.split(" ");
    words[3] = "notaword";

    await expect(
      restoreIdentityFromMnemonicWith(fake.effects, words.join(" ")),
    ).rejects.toThrow(/notaword/);
    expect(fake.order).toEqual([]);
  });

  test("a valid phrase adopts the identity in a fixed order and keeps every room", async () => {
    const { calls, derive } = stubDerivation(0x33);
    const fake = harness(derive);

    const restored = await restoreIdentityFromMnemonicWith(
      fake.effects,
      KAT_MNEMONIC,
      "a password",
    );

    expect(calls).toEqual([{ mnemonic: KAT_MNEMONIC, password: "a password" }]);
    expect(fake.order).toEqual([
      // Derivation is deliberately outside the exclusive boundary: argon2id
      // takes seconds, and nothing is torn down until a key actually exists.
      "derive",
      "exclusive-enter",
      "disconnect",
      "rooms-terminal",
      // The X25519 identity is cross-signed by the outgoing Ed25519 key, so it
      // goes before the key that would orphan it.
      "x25519-deleted",
      // The derivation flag binds to whatever Ed25519 key is stored when it is
      // written, so the key has to be there first.
      "ed25519-written",
      "derivation-recorded",
      // Stale reconnect data belongs to the previous identity.
      "identity-reset",
      "adopted",
      "exclusive-exit",
    ]);

    expect(restored.publicKey).toBe("33".repeat(32));
    expect(fake.stored.ed25519).toEqual({
      publicKey: "33".repeat(32),
      secretKey: "34".repeat(64),
    });
    expect(fake.stored.x25519).toBe(false);
    expect(fake.stored.derivation).toBe("mnemonic");
    expect(fake.redux).toEqual({
      publicKey: "33".repeat(32),
      secretKey: "34".repeat(64),
      peerId: "",
    });
    expect(fake.socketConnected).toBe(false);

    // Rooms, their messages and the address book survive: this rotates the
    // account key, it does not purge the account.
    expect(fake.rooms).toEqual([
      { id: "room-1", transportOpen: false, messages: ["kept"] },
      { id: "room-2", transportOpen: false, messages: ["also kept"] },
    ]);
    expect(fake.addressBook).toEqual(["a peer"]);

    // The derived secret is wiped once it has been handed on, so a restore
    // leaves no copy of the key behind in the caller's heap.
    expect(fake.writtenSecretBuffer).toBeDefined();
    expect(
      (fake.writtenSecretBuffer as Uint8Array).every((byte) => byte === 0),
    ).toBe(true);
  });

  test("a failed identity write never adopts the key, and still wipes it", async () => {
    const { derive } = stubDerivation(0x44);
    const fake = harness(derive, (order) => ({
      writeIdentityEd25519: () => {
        order.push("ed25519-written");
        throw new Error("IndexedDB unavailable");
      },
    }));

    await expect(
      restoreIdentityFromMnemonicWith(fake.effects, KAT_MNEMONIC),
    ).rejects.toThrow("IndexedDB unavailable");

    expect(fake.order).toEqual([
      "derive",
      "exclusive-enter",
      "disconnect",
      "rooms-terminal",
      "x25519-deleted",
      "ed25519-written",
      "exclusive-exit",
    ]);
    // Redux still holds the previous identity rather than one that no reload
    // could ever bring back.
    expect(fake.redux.publicKey).toBe("old".padEnd(64, "0"));
    expect(fake.stored.derivation).toBe("random");
  });

  test("teardown settles fully before the new identity is written", async () => {
    const { derive } = stubDerivation(0x55);
    const fake = harness(derive, (order) => ({
      disconnectSignaling: () => {
        order.push("disconnect");
        throw new Error("socket close failed");
      },
    }));

    await expect(
      restoreIdentityFromMnemonicWith(fake.effects, KAT_MNEMONIC),
    ).rejects.toBeInstanceOf(AggregateError);

    // Every teardown step still ran, and the identity was not swapped under a
    // transport that may still be live.
    expect(fake.order).toEqual([
      "derive",
      "exclusive-enter",
      "disconnect",
      "rooms-terminal",
      "x25519-deleted",
      "exclusive-exit",
    ]);
    expect(fake.stored.ed25519.publicKey).toBe("old".padEnd(64, "0"));
  });
});

describe("creating a recoverable identity", () => {
  test(
    "the phrase it hands back restores the very same public key",
    async () => {
      const created = await createRecoverableIdentityWith(
        harness(keyPairFromMnemonic).effects,
        { strength: 128 },
      );

      expect(created.mnemonic.split(" ")).toHaveLength(12);

      const restoring = harness(keyPairFromMnemonic);
      const restored = await restoreIdentityFromMnemonicWith(
        restoring.effects,
        created.mnemonic,
      );

      expect(restored.publicKey).toBe(created.publicKey);
      expect(restored.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(restoring.stored.ed25519.publicKey).toBe(created.publicKey);
      expect(restoring.stored.derivation).toBe("mnemonic");
    },
    DERIVATION_TIMEOUT_MS,
  );

  test("the default strength is a 24-word phrase", async () => {
    const { calls, derive } = stubDerivation(0x66);
    const created = await createRecoverableIdentityWith(
      harness(derive).effects,
    );

    expect(created.mnemonic.split(" ")).toHaveLength(24);
    expect(calls).toEqual([
      { mnemonic: created.mnemonic, password: undefined },
    ]);
    expect(created.publicKey).toBe("66".repeat(32));
  });
});

describe("the public identity backup surface", () => {
  test("is exported from the SDK entry point", async () => {
    const p2party = (await import("../src/index")).default;

    expect(p2party.restoreIdentityFromMnemonic).toBeFunction();
    expect(p2party.createRecoverableIdentity).toBeFunction();
    expect(p2party.getIdentityBackupStatus).toBeFunction();
    expect(p2party.validateMnemonic).toBeFunction();
    expect(p2party.validateMnemonicWords).toBeFunction();

    expect(await p2party.validateMnemonic(KAT_MNEMONIC)).toBe(true);
    expect(p2party.validateMnemonicWords(KAT_MNEMONIC).ok).toBe(true);
    expect(p2party.validateMnemonicWords("adapt notaword eternal").ok).toBe(
      false,
    );
  });
});
