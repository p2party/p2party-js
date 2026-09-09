import { describe, expect, test } from "bun:test";

import { encodeRoomPolicyV1, hashRoomPolicyV1 } from "../../src/roomPolicy";
import {
  addressBookPresenceRank,
  authorityPresenceRank,
  base64urlNoPad,
  base64urlNoPadDecode,
  byteOf,
  domain,
  emptySchedulerWorkloadDigest,
  establishedPairRoot,
  hkdfSha256Expand,
  hkdfSha256Extract,
  identityHelloPskId,
  localPeerId,
  localPeerIdDigest,
  localRoomId,
  observedRosterHash,
  openPresenceRank,
  pairFlightAeadKey,
  pairFlightRoot,
  pairFlightSecret,
  policyHash,
  roomContextConfirmation,
  roomContextId,
  roomRoot,
  sha256,
  stableIdentityCommitment,
  u16be,
  u32be,
  u64be,
  validatedPairRootExporterContext,
} from "../../src/blindRendezvous/derivations";
import {
  DEFAULT_BLIND_POLICY_V4_0,
  DEFAULT_BLIND_SESSION_POLICY_V1,
} from "../../src/blindRendezvous/roomPolicyV4";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../gu) ?? [], (pair) => parseInt(pair, 16));

const filled = (value: number, length = 32): Uint8Array =>
  new Uint8Array(length).fill(value);

const shadowByteSurfaces = (
  bytes: Uint8Array,
  claimedLength = 0,
): Uint8Array => {
  Object.defineProperty(bytes, "length", { value: claimedLength });
  Object.defineProperty(bytes, Symbol.iterator, {
    value: (): never => {
      throw new Error("hostile iterator must not run");
    },
  });
  Object.defineProperty(bytes, "constructor", {
    get: (): never => {
      throw new Error("hostile constructor must not run");
    },
  });
  return bytes;
};

describe("Section 3.3 primitive encodings", () => {
  test("domain strings are exact ASCII octets with no terminator", () => {
    const encoded = domain("p2party/room-policy/v4");
    expect(encoded.length).toBe("p2party/room-policy/v4".length);
    expect(encoded[encoded.length - 1]).not.toBe(0);
    expect(() => domain("naïve")).toThrow("is not ASCII");
  });

  test("integer encodings are big-endian and range-checked", () => {
    expect(hex(byteOf(0xab))).toBe("ab");
    expect(hex(u16be(0x0102))).toBe("0102");
    expect(hex(u32be(0x01020304))).toBe("01020304");
    expect(hex(u64be(0x0102030405060708n))).toBe("0102030405060708");
    expect(() => byteOf(256)).toThrow("out of range");
    expect(() => u16be(-1)).toThrow("out of range");
    expect(() => u64be(2n ** 64n)).toThrow("out of range");
  });

  test("base64url is unpadded and rejects alternate encodings", () => {
    const value = Uint8Array.of(1, 2, 3, 4);
    expect(base64urlNoPad(value)).toBe("AQIDBA");
    expect([...base64urlNoPadDecode("AQIDBA")]).toEqual([1, 2, 3, 4]);
    // "AQIDBB" carries the same four bytes with non-zero trailing bits.
    expect(() => base64urlNoPadDecode("AQIDBB")).toThrow("not canonical");
    expect(() => base64urlNoPadDecode("AQIDBA==")).toThrow(
      "unpadded base64url",
    );
    expect(() => base64urlNoPadDecode("AQID+A")).toThrow("unpadded base64url");
  });
});

describe("HKDF-SHA-256 matches RFC 5869 test vectors", () => {
  // RFC 5869 Appendix A.1: basic test case with SHA-256.
  const ikm = fromHex("0b".repeat(22));
  const salt = fromHex("000102030405060708090a0b0c");
  const info = fromHex("f0f1f2f3f4f5f6f7f8f9");

  test("A.1 extract produces the specified PRK", async () => {
    expect(hex(await hkdfSha256Extract(salt, ikm))).toBe(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    );
  });

  test("A.1 expand produces the specified 42-byte OKM", async () => {
    const prk = await hkdfSha256Extract(salt, ikm);
    expect(hex(await hkdfSha256Expand(prk, info, 42))).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
        "34007208d5b887185865",
    );
  });

  test("A.3 zero-length salt and info produce the specified OKM", async () => {
    // RFC 5869 Appendix A.3: test with zero-length salt/info.
    const prk = await hkdfSha256Extract(new Uint8Array(0), ikm);
    expect(hex(prk)).toBe(
      "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    );
    expect(hex(await hkdfSha256Expand(prk, new Uint8Array(0), 42))).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
        "9d201395faa4b61a96c8",
    );
  });

  test("rejects an out-of-range expand length", async () => {
    const prk = await hkdfSha256Extract(salt, ikm);
    await expect(hkdfSha256Expand(prk, info, 0)).rejects.toThrow(
      "output length is out of range",
    );
    await expect(hkdfSha256Expand(prk, info, 255 * 32 + 1)).rejects.toThrow(
      "output length is out of range",
    );
  });
});

describe("the specification's published policy vector", () => {
  test("DEFAULT_BLIND_SESSION_POLICY_V1 re-derives from the shipped v1 codec", () => {
    // Section 4.1 publishes these exact 32 bytes; deriving rather than
    // trusting the literal is what makes the constant checkable.
    expect(hex(encodeRoomPolicyV1(DEFAULT_BLIND_SESSION_POLICY_V1))).toBe(
      "5032525001040001020000000000000000000000000000000000000000000000",
    );
  });

  test("its published v1 policy hash matches the shipped hash function", async () => {
    expect(hex(await hashRoomPolicyV1(DEFAULT_BLIND_SESSION_POLICY_V1))).toBe(
      "87456f93e509440102dbd4c77534963820c77a32d98a5b18de9af1dedfd704bb",
    );
  });

  test("it differs from the shipped legacy default only in rendezvous mode", () => {
    const legacy = encodeRoomPolicyV1({
      ...DEFAULT_BLIND_SESSION_POLICY_V1,
      rendezvousMode: "legacy-signaling",
    });
    const blind = encodeRoomPolicyV1(DEFAULT_BLIND_SESSION_POLICY_V1);
    const differing = [...blind].flatMap((byte, index) =>
      byte === legacy[index] ? [] : [index],
    );
    expect(differing).toEqual([8]);
  });
});

describe("room identity derivations", () => {
  const capability = new Uint8Array(32).fill(0x11);

  test("room context binds the capability and the exact policy", async () => {
    const hashOfPolicy = await policyHash(DEFAULT_BLIND_POLICY_V4_0);
    const contextId = await roomContextId(capability, hashOfPolicy);

    // A different capability under the same policy is a different room.
    const otherCapability = new Uint8Array(32).fill(0x22);
    expect(hex(await roomContextId(otherCapability, hashOfPolicy))).not.toBe(
      hex(contextId),
    );

    // A different policy under the same capability is also a different room,
    // which is why a changed policy fails closed instead of joining.
    const otherPolicy = await policyHash({
      ...DEFAULT_BLIND_POLICY_V4_0,
      maxRoomMembers: 63,
    });
    expect(hex(await roomContextId(capability, otherPolicy))).not.toBe(
      hex(contextId),
    );
  });

  test("room root is HKDF-Extract over the policy hash and capability", async () => {
    const hashOfPolicy = await policyHash(DEFAULT_BLIND_POLICY_V4_0);
    expect(hex(await roomRoot(capability, hashOfPolicy))).toBe(
      hex(await hkdfSha256Extract(hashOfPolicy, capability)),
    );
    await expect(roomRoot(new Uint8Array(31), hashOfPolicy)).rejects.toThrow(
      "exactly 32 bytes",
    );
  });

  test("carrier key derivation rejects a wrong-length room root", async () => {
    const { carrierKey } =
      await import("../../src/blindRendezvous/derivations");
    await expect(
      carrierKey(
        new Uint8Array(31),
        {
          deliveryProfileHash: new Uint8Array(32),
          carrierContextId: new Uint8Array(32),
          ingressWindow: 1n,
          sizeClass: 0,
        },
        new Uint8Array(24),
      ),
    ).rejects.toThrow("RoomRoot must be exactly 32 bytes");
  });

  test("local room id is unpadded base64url of a 32-byte digest", async () => {
    const contextId = await roomContextId(
      capability,
      await policyHash(DEFAULT_BLIND_POLICY_V4_0),
    );
    const identifier = await localRoomId(contextId);
    expect(identifier).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(base64urlNoPadDecode(identifier).length).toBe(32);
  });

  test("room confirmation is derived from the context, not the capability", async () => {
    const contextId = await roomContextId(
      capability,
      await policyHash(DEFAULT_BLIND_POLICY_V4_0),
    );
    expect(hex(await roomContextConfirmation(contextId))).toBe(
      hex(
        await sha256(
          Uint8Array.from([
            ...domain("p2party/room-confirmation/v1"),
            ...contextId,
          ]),
        ),
      ),
    );
  });

  test("stable identity commitments and peer handles are scoped to one room", async () => {
    const hashOfPolicy = await policyHash(DEFAULT_BLIND_POLICY_V4_0);
    const contextId = await roomContextId(capability, hashOfPolicy);
    const otherContextId = await roomContextId(
      new Uint8Array(32).fill(0x22),
      hashOfPolicy,
    );
    const stableKey = new Uint8Array(32).fill(0x44);

    const commitment = await stableIdentityCommitment(contextId, stableKey);
    expect(hex(commitment)).toBe(
      hex(
        await sha256(
          Uint8Array.from([
            ...domain("p2party/stable-identity-commitment/v1"),
            ...contextId,
            ...stableKey,
          ]),
        ),
      ),
    );
    expect(
      hex(await stableIdentityCommitment(otherContextId, stableKey)),
    ).not.toBe(hex(commitment));

    const digest = await localPeerIdDigest(contextId, commitment);
    const peerId = await localPeerId(contextId, commitment);
    expect(peerId).toBe(`peer.v1.${base64urlNoPad(digest)}`);
    expect(base64urlNoPadDecode(peerId.slice("peer.v1.".length))).toHaveLength(
      32,
    );
  });

  test("stable identity derivations reject non-canonical input lengths", async () => {
    const contextId = new Uint8Array(32);
    const commitment = new Uint8Array(32);
    await expect(
      stableIdentityCommitment(new Uint8Array(31), new Uint8Array(32)),
    ).rejects.toThrow("RoomContextId must be exactly 32 bytes");
    await expect(
      stableIdentityCommitment(contextId, new Uint8Array(31)),
    ).rejects.toThrow("stableEd25519PublicKey must be exactly 32 bytes");
    await expect(
      localPeerIdDigest(contextId, new Uint8Array(31)),
    ).rejects.toThrow("StableIdentityCommitment must be exactly 32 bytes");
    await expect(localPeerId(new Uint8Array(31), commitment)).rejects.toThrow(
      "RoomContextId must be exactly 32 bytes",
    );
  });
});

describe("local admissible projection derivations", () => {
  const room = filled(0x11);
  const permitSerial = filled(0x22);
  const commitment = filled(0x33);
  const presenceOperationId = filled(0x44);

  test("presence ranks pin each eligibility class and exact argument order", async () => {
    expect(hex(await authorityPresenceRank(room, permitSerial, 7n))).toBe(
      hex(
        await sha256(
          Uint8Array.from([
            ...domain("p2party/presence-rank/authority/v1"),
            ...room,
            ...permitSerial,
            ...u64be(7n),
          ]),
        ),
      ),
    );
    expect(hex(await addressBookPresenceRank(room, commitment))).toBe(
      hex(
        await sha256(
          Uint8Array.from([
            ...domain("p2party/presence-rank/address-book/v1"),
            ...room,
            ...commitment,
          ]),
        ),
      ),
    );
    expect(hex(await openPresenceRank(room, presenceOperationId))).toBe(
      hex(
        await sha256(
          Uint8Array.from([
            ...domain("p2party/presence-rank/open/v1"),
            ...room,
            ...presenceOperationId,
          ]),
        ),
      ),
    );
  });

  test("observed roster hashing binds the reference window and canonical set", async () => {
    const first = filled(0x01);
    const second = filled(0x02);
    const canonicalSet = Uint8Array.from([0, 2, ...first, ...second]);
    expect(hex(await observedRosterHash(9n, [first, second]))).toBe(
      hex(
        await sha256(
          Uint8Array.from([
            ...domain("p2party/observed-roster/v1"),
            ...u64be(9n),
            ...canonicalSet,
          ]),
        ),
      ),
    );
    await expect(observedRosterHash(9n, [second, first])).rejects.toThrow(
      "must be sorted",
    );
    await expect(observedRosterHash(9n, [first, first])).rejects.toThrow(
      "duplicate-free",
    );
  });
});

describe("closed sentinels", () => {
  test("the empty scheduler workload digest is a fixed constant", async () => {
    const digest = await emptySchedulerWorkloadDigest();
    expect(hex(digest)).toBe(
      hex(await sha256(domain("p2party/scheduler-workload/v1/none"))),
    );
    expect(digest.length).toBe(32);
  });
});

describe("Section 4.11 pair derivation byte ownership", () => {
  const checkpointSlot = {
    kind: "PAIR_CHECKPOINT",
    direction: 0,
    pairSequence: 2n,
  } as const;

  test("rejects hostile proxies without invoking their traps", async () => {
    const hostile = new Proxy(new Uint8Array(32), {
      getPrototypeOf(): never {
        throw new Error("hostile getPrototypeOf must not run");
      },
    });

    await expect(identityHelloPskId(hostile, filled(0x11))).rejects.toThrow(
      "PolicyHash must be exactly 32 bytes",
    );
    expect(() => pairFlightRoot(hostile, checkpointSlot)).toThrow(
      "pair base secret must be exactly 32 bytes",
    );
    await expect(
      validatedPairRootExporterContext("IDENTITY_HELLO", hostile),
    ).rejects.toThrow("canonical pair plaintext must be a Uint8Array");
  });

  test("uses intrinsic bytes despite shadowed metadata and iteration", async () => {
    const policy = filled(0x11);
    const presenceOperationId = filled(0x12);
    expect(
      await identityHelloPskId(
        shadowByteSurfaces(Uint8Array.from(policy)),
        shadowByteSurfaces(Uint8Array.from(presenceOperationId), 65_536),
      ),
    ).toEqual(await identityHelloPskId(policy, presenceOperationId));

    const helloRoot = filled(0x21);
    const acceptRoot = filled(0x22);
    const helloOperationId = filled(0x23);
    const acceptOperationId = filled(0x24);
    expect(
      await establishedPairRoot(
        shadowByteSurfaces(Uint8Array.from(helloRoot)),
        shadowByteSurfaces(Uint8Array.from(acceptRoot), 31),
        shadowByteSurfaces(Uint8Array.from(helloOperationId), 33),
        shadowByteSurfaces(Uint8Array.from(acceptOperationId), 1_000_000),
      ),
    ).toEqual(
      await establishedPairRoot(
        helloRoot,
        acceptRoot,
        helloOperationId,
        acceptOperationId,
      ),
    );

    const baseSecret = filled(0x31);
    expect(
      await pairFlightRoot(
        shadowByteSurfaces(Uint8Array.from(baseSecret), 31),
        checkpointSlot,
      ),
    ).toEqual(await pairFlightRoot(baseSecret, checkpointSlot));

    const plaintext = Uint8Array.of(1, 2, 3, 4);
    expect(
      await validatedPairRootExporterContext(
        "IDENTITY_ACCEPT",
        shadowByteSurfaces(Uint8Array.from(plaintext), 0),
      ),
    ).toEqual(
      await validatedPairRootExporterContext("IDENTITY_ACCEPT", plaintext),
    );
  });

  test("wipes owned secret snapshots when later validation fails", async () => {
    const baseSecret = filled(0x41);
    const helloRoot = filled(0x42);
    const invalidAcceptRoot = filled(0x43, 31);
    const operationId = filled(0x44);
    const flightRoot = filled(0x45);
    const flightSecret = filled(0x46);
    const callerInputs = [
      baseSecret,
      helloRoot,
      invalidAcceptRoot,
      operationId,
      flightRoot,
      flightSecret,
    ];
    const originals = callerInputs.map((bytes) => Uint8Array.from(bytes));

    const typedArrayPrototype = Object.getPrototypeOf(
      Uint8Array.prototype,
    ) as object;
    const fillDescriptor = Object.getOwnPropertyDescriptor(
      typedArrayPrototype,
      "fill",
    );
    if (fillDescriptor === undefined)
      throw new Error("Uint8Array.prototype.fill descriptor is unavailable");
    const intrinsicFill = Uint8Array.prototype.fill;
    const zeroFilledBuffers: Uint8Array[] = [];
    Object.defineProperty(typedArrayPrototype, "fill", {
      ...fillDescriptor,
      value: function observedFill(
        this: Uint8Array,
        value: number,
        start?: number,
        end?: number,
      ): Uint8Array {
        const result = Reflect.apply(intrinsicFill, this, [
          value,
          start,
          end,
        ]) as Uint8Array;
        if (value === 0) zeroFilledBuffers.push(this);
        return result;
      },
    });

    let establishedFailure: Promise<Uint8Array> | undefined;
    let aeadFailure: Promise<Uint8Array> | undefined;
    try {
      expect(() =>
        pairFlightRoot(baseSecret, {
          ...checkpointSlot,
          kind: "NOT_A_PAIR_STEP",
        }),
      ).toThrow("PairStepKindV1");
      establishedFailure = establishedPairRoot(
        helloRoot,
        invalidAcceptRoot,
        operationId,
        operationId,
      );
      void establishedFailure.catch(() => undefined);
      expect(() =>
        pairFlightSecret(flightRoot, "PAIR_CHECKPOINT", {}),
      ).toThrow();
      aeadFailure = pairFlightAeadKey(flightSecret, {});
      void aeadFailure.catch(() => undefined);
    } finally {
      Object.defineProperty(typedArrayPrototype, "fill", fillDescriptor);
    }

    if (establishedFailure === undefined || aeadFailure === undefined)
      throw new Error("expected derivation failures were not created");
    await expect(establishedFailure).rejects.toThrow(
      "AcceptRoot must be exactly 32 bytes",
    );
    await expect(aeadFailure).rejects.toThrow();

    expect(
      zeroFilledBuffers.filter(
        (bytes) =>
          bytes.length === 32 &&
          bytes.every((byte) => byte === 0) &&
          !callerInputs.includes(bytes),
      ).length,
    ).toBeGreaterThanOrEqual(4);
    for (const [index, bytes] of callerInputs.entries())
      expect(bytes).toEqual(originals[index]);
  });
});
