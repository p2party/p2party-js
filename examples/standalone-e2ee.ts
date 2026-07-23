/**
 * Public standalone E2EE API — no WebRTC, signaling, Redux, IndexedDB, OPFS,
 * `window`, or `localStorage`.
 *
 * Run from this repository:
 *   bun run examples/standalone-e2ee.ts
 *
 * Installed package:
 *   import { createSession, generateSessionIdentity, restoreSession }
 *     from "p2party/session";
 */
import { readFileSync } from "node:fs";

import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  type HandshakeTransport,
} from "../src/session";

const wasmFile = readFileSync(
  new URL("../src/cryptography/libcrypto.wasm", import.meta.url),
);
const wasmBinary = wasmFile.buffer.slice(
  wasmFile.byteOffset,
  wasmFile.byteOffset + wasmFile.byteLength,
) as ArrayBuffer;
const cryptoOptions = { wasmBinary };

// One one-way byte pipe. Two pipes form the full-duplex transport that carries
// the two-round authenticated handshake; a network app sends these bytes over
// its own socket/channel instead.
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
      return bytes
        ? Promise.resolve(bytes)
        : new Promise((resolve) => waiters.push(resolve));
    },
  };
};

const main = async () => {
  // Long-term identities. Persist these securely in a real application.
  const [aliceIdentity, bobIdentity] = await Promise.all([
    generateSessionIdentity(cryptoOptions),
    generateSessionIdentity(cryptoOptions),
  ]);

  const aliceToBob = makeLink();
  const bobToAlice = makeLink();
  const channelId = crypto.getRandomValues(new Uint8Array(16));
  const aliceFingerprint = crypto.getRandomValues(new Uint8Array(32));
  const bobFingerprint = crypto.getRandomValues(new Uint8Array(32));

  const transport = (
    send: (bytes: Uint8Array) => void,
    recv: () => Promise<Uint8Array>,
  ): HandshakeTransport => ({ send, recv });

  // Both peers run concurrently. `x25519SecretKey` is the identity DH secret;
  // the Ed25519 key anchors/cross-signs it and is never passed as idSelfSec.
  const [alice, bob] = await Promise.all([
    createSession({
      role: "initiator",
      identity: aliceIdentity,
      peerIdentityEd25519PublicKey: bobIdentity.ed25519PublicKey,
      channel: {
        channelId,
        localFingerprint: aliceFingerprint,
        remoteFingerprint: bobFingerprint,
      },
      transport: transport(aliceToBob.send, bobToAlice.recv),
      mode: "nopin",
      crypto: cryptoOptions,
    }),
    createSession({
      role: "responder",
      identity: bobIdentity,
      peerIdentityEd25519PublicKey: aliceIdentity.ed25519PublicKey,
      channel: {
        channelId,
        localFingerprint: bobFingerprint,
        remoteFingerprint: aliceFingerprint,
      },
      transport: transport(bobToAlice.send, aliceToBob.recv),
      mode: "nopin",
      crypto: cryptoOptions,
    }),
  ]);
  console.log("handshake complete — protocol", alice.protocolVersion);

  // The envelope carries the Merkle root once alongside uniform chunk frames.
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const aliceMessage = encoder.encode("hello bob, from alice");
  const receivedByBob = await bob.decrypt(await alice.encrypt(aliceMessage));
  console.log("alice → bob:", decoder.decode(receivedByBob));

  const bobMessage = encoder.encode("hi alice, bob here");
  const receivedByAlice = await alice.decrypt(await bob.encrypt(bobMessage));
  console.log("bob → alice:", decoder.decode(receivedByAlice));

  // Snapshots are plaintext secrets: encrypt them at rest and protect against
  // rollback. Restoration needs no Redux/DB and continues the same ratchet.
  const aliceSnapshot = await alice.serialize();
  const restoredAlice = await restoreSession(aliceSnapshot, cryptoOptions);
  await alice.destroy();

  const afterRestore = encoder.encode("still here after restore");
  const restoredMessage = await restoredAlice.decrypt(
    await bob.encrypt(afterRestore),
  );
  if (decoder.decode(restoredMessage) !== decoder.decode(afterRestore))
    throw new Error("restore round-trip mismatch");

  aliceIdentity.ed25519SecretKey.fill(0);
  aliceIdentity.x25519SecretKey.fill(0);
  bobIdentity.ed25519SecretKey.fill(0);
  bobIdentity.x25519SecretKey.fill(0);
  aliceSnapshot.fill(0);
  await Promise.all([restoredAlice.destroy(), bob.destroy()]);

  console.log(
    "\nOK — public createSession E2EE + restore verified (no browser).",
  );
};

main().catch((error) => {
  console.error("FAILED:", error);
  process.exit(1);
});
