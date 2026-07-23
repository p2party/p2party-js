/**
 * Standalone E2EE example — p2party's crypto WITHOUT WebRTC/signaling/OPFS.
 *
 * This is the shape every E2EE library uses to demonstrate itself (libsignal's
 * SessionBuilder/SessionCipher, Matrix olm's create_outbound/inbound): everything
 * runs in one process, and the developer simply hands the handshake bytes and the
 * ciphertext from one party to the other. The "channel" is a variable — here two
 * in-memory pipes standing in for the two WebRTC data channels.
 *
 * Run it:  bun run examples/standalone-e2ee.ts
 *
 * NOTE: it imports a few functions that are currently INTERNAL (the handshake +
 * ratchet primitives). A `p2party.createSession(...)` wrapper that packages this
 * flow behind `.encrypt()/.decrypt()` is the planned public API (see docs/HANDOFF).
 */
import { readFileSync } from "node:fs";

import libcrypto from "../src/cryptography/libcrypto";
import { newKeyPair } from "../src/cryptography/ed25519";
import { newX25519KeyPair } from "../src/cryptography/x25519";
import { crossSignIdentityX25519 } from "../src/cryptography/identityCrossSig";
import {
  buildChannelInput,
  performHandshakeCore,
  type HandshakeTransport,
} from "../src/handlers/handshakeCore";
import { ratchetEncrypt } from "../src/cryptography/ratchet";
import { getMerkleRoot, getMerkleProof } from "../src/cryptography/merkle";
import { hashMerkleLeafWasm } from "../src/utils/leafHash";
import {
  sealChunk,
  decryptMessageChunk,
} from "../src/handlers/messageChunkCrypto";
import { crypto_hash_sha512_BYTES } from "../src/cryptography/interfaces";
import {
  METADATA_LEN,
  PROOF_LEN,
  CHUNK_LEN,
  DECRYPTED_LEN,
} from "../src/utils/constants";

import type { LibCrypto } from "../src/cryptography/libcrypto";
import type { RatchetState } from "../src/cryptography/ratchet";

// Each peer would run its own wasm instance in production, so we load one per party.
const loadModule = async (): Promise<LibCrypto> => {
  const bytes = readFileSync(
    new URL("../src/cryptography/libcrypto.wasm", import.meta.url),
  );
  const wasmBinary = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(wasmBinary).set(bytes);
  const wasmMemory = new WebAssembly.Memory({ initial: 32, maximum: 32 });
  return (await libcrypto({ wasmBinary, wasmMemory })) as LibCrypto;
};

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));
const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

// A one-way in-memory byte pipe; two of them = a full-duplex "channel".
const makeLink = () => {
  const q: Uint8Array[] = [];
  const w: ((b: Uint8Array) => void)[] = [];
  return {
    send: (b: Uint8Array) => (w.shift() ?? ((x: Uint8Array) => q.push(x)))(b),
    recv: (): Promise<Uint8Array> =>
      new Promise((res) => {
        const b = q.shift();
        if (b) res(b);
        else w.push(res);
      }),
  };
};

// A party's long-term identity: an Ed25519 anchor + a dedicated X25519 identity
// key cross-signed by it (the D2=B key separation).
const makeIdentity = async (module: LibCrypto) => {
  const ed = await newKeyPair(module);
  const x = await newX25519KeyPair(module);
  const crossSig = await crossSignIdentityX25519(
    x.publicKey,
    ed.secretKey,
    module,
  );
  return { ed, x, crossSig };
};
type Identity = Awaited<ReturnType<typeof makeIdentity>>;

// Run BOTH sides of the real protocol-v3 handshake concurrently over a fresh
// duplex link. Returns each party's seeded Double-Ratchet state.
const handshake = async (
  a: { id: Identity; module: LibCrypto; role: "initiator" | "responder" },
  b: { id: Identity; module: LibCrypto; role: "initiator" | "responder" },
  ci: Uint8Array,
) => {
  const ab = makeLink();
  const ba = makeLink();
  const params = (
    self: typeof a,
    peer: typeof b,
    transport: HandshakeTransport,
  ) => ({
    transport,
    p: {
      mode: "nopin" as const,
      pin: null,
      channelInput: ci,
      amInitiator: self.role === "initiator",
      // idSelfSec is the X25519 identity SECRET (used for the X3DH DH). The
      // Ed25519 key only cross-signs the X25519 pub + is the pinned peer anchor.
      idSelfSec: self.id.x.secretKey,
      selfIdentityX25519Pub: self.id.x.publicKey,
      selfIdentityCrossSignature: self.id.crossSig,
      peerIdentityEd25519Pub: peer.id.ed.publicKey,
    },
  });
  const pa = params(a, b, { send: ab.send, recv: ba.recv });
  const pb = params(b, a, { send: ba.send, recv: ab.recv });
  const [ra, rb] = await Promise.all([
    performHandshakeCore(pa.transport, pa.p, a.module),
    performHandshakeCore(pb.transport, pb.p, b.module),
  ]);
  return { aState: ra.state, bState: rb.state };
};

// Build a real message (metadata ‖ merkle-proof ‖ chunk) on the sender's module.
const buildMessage = async (mod: LibCrypto, payloads: Uint8Array[]) => {
  const datas = payloads.map((p) => {
    const d = new Uint8Array(CHUNK_LEN); // one payload per fixed-size chunk
    d.set(p.subarray(0, CHUNK_LEN));
    return d;
  });
  const leaves = new Uint8Array(datas.length * crypto_hash_sha512_BYTES);
  datas.forEach((d, i) =>
    leaves.set(hashMerkleLeafWasm(d, mod), i * crypto_hash_sha512_BYTES),
  );
  const root = await getMerkleRoot(leaves, mod);
  const plaintexts: Uint8Array[] = [];
  for (let i = 0; i < datas.length; i++) {
    const proof = await getMerkleProof(
      leaves,
      hashMerkleLeafWasm(datas[i], mod),
      mod,
      PROOF_LEN,
    );
    const pt = new Uint8Array(DECRYPTED_LEN);
    pt.set(proof, METADATA_LEN);
    pt.set(datas[i], METADATA_LEN + PROOF_LEN);
    plaintexts.push(pt);
  }
  return { root, datas, plaintexts };
};

// Encrypt on the sender's ratchet, hand the frames over the "channel", decrypt on
// the receiver's. Returns the recovered chunk payloads.
const send = async (
  from: RatchetState,
  fromMod: LibCrypto,
  to: RatchetState,
  toMod: LibCrypto,
  payloads: Uint8Array[],
): Promise<Uint8Array[]> => {
  const { root, plaintexts } = await buildMessage(fromMod, payloads);
  const { messageKey, header } = ratchetEncrypt(from, fromMod); // one step / message
  const frames = plaintexts.map((pt) =>
    sealChunk(messageKey, header, pt, root, fromMod),
  );
  messageKey.fill(0);
  const cache = new Map<string, Uint8Array>();
  return frames.map((f) => {
    const d = decryptMessageChunk(to, f, cache, root, toMod);
    if (!d.ok || !d.decrypted) throw new Error("decrypt failed");
    return d.decrypted.slice(METADATA_LEN + PROOF_LEN);
  });
};

const main = async () => {
  const aliceMod = await loadModule();
  const bobMod = await loadModule();

  // 1. Identities (long-term). In a real app these are persisted.
  const aliceId = await makeIdentity(aliceMod);
  const bobId = await makeIdentity(bobMod);

  // 2. Handshake transcript input. channelId + DTLS fingerprints come from the
  //    connection in production; both parties must build the identical CI.
  const ci = buildChannelInput({
    channelId: rand(16),
    ikInitiator: aliceId.ed.publicKey,
    ikResponder: bobId.ed.publicKey,
    fpInitiator: rand(32),
    fpResponder: rand(32),
  });

  // 3. THE HANDSHAKE — over the simulated channel. This is the transport-free
  //    stand-in for what runs on the WebRTC data channel at connection time.
  const { aState: alice, bState: bob } = await handshake(
    { id: aliceId, module: aliceMod, role: "initiator" },
    { id: bobId, module: bobMod, role: "responder" },
    ci,
  );
  console.log("handshake complete — both parties hold a seeded Double Ratchet");

  // 4. Encrypted messaging, both ways. The initiator sends first (a Double-Ratchet
  //    responder has no sending chain until it has received once).
  const msg1 = new TextEncoder().encode("hello bob, from alice");
  const got1 = await send(alice, aliceMod, bob, bobMod, [msg1]);
  console.log(
    "alice → bob:",
    new TextDecoder().decode(got1[0].subarray(0, msg1.length)),
  );
  if (!eq(got1[0].subarray(0, msg1.length), msg1))
    throw new Error("alice→bob mismatch");

  const msg2 = new TextEncoder().encode("hi alice, bob here");
  const got2 = await send(bob, bobMod, alice, aliceMod, [msg2]);
  console.log(
    "bob → alice:",
    new TextDecoder().decode(got2[0].subarray(0, msg2.length)),
  );
  if (!eq(got2[0].subarray(0, msg2.length), msg2))
    throw new Error("bob→alice mismatch");

  console.log("\nOK — standalone E2EE round-trip verified (no WebRTC).");
};

main().catch((e) => {
  console.error("FAILED:", e);
  process.exit(1);
});
