# Store-free session API

`p2party/session` exposes protocol-v3 without Redux, IndexedDB, OPFS, WebRTC,
signaling, `window`, or `localStorage`. It still requires WebCrypto,
WebAssembly, secure identity storage, and a transport supplied by the
application.

The public surface is:

```ts
import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  type CreateSessionOptions,
  type EncryptedSessionMessage,
  type GeneratedSessionIdentity,
  type HandshakeTransport,
  type LocalSessionIdentity,
  type P2PartySession,
  type SessionChannelBinding,
  type SessionCryptoOptions,
} from "p2party/session";
```

## Complete Node/Bun example

This executable example uses two in-memory byte pipes. Replace those pipes with
your socket, stream multiplexer, native bridge, or other message transport.

```ts
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  type HandshakeTransport,
} from "p2party/session";

const require = createRequire(import.meta.url);
const wasmBinary = Uint8Array.from(
  await readFile(require.resolve("p2party/libcrypto.wasm")),
);
const cryptoOptions = { wasmBinary };

const makePipe = (): HandshakeTransport => {
  const queued: Uint8Array[] = [];
  const waiters: Array<(bytes: Uint8Array) => void> = [];
  return {
    send(bytes): void {
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

const [aliceIdentity, bobIdentity] = await Promise.all([
  generateSessionIdentity(cryptoOptions),
  generateSessionIdentity(cryptoOptions),
]);

const aliceToBob = makePipe();
const bobToAlice = makePipe();
const channelId = globalThis.crypto.getRandomValues(new Uint8Array(16));
const aliceFingerprint = globalThis.crypto.getRandomValues(new Uint8Array(32));
const bobFingerprint = globalThis.crypto.getRandomValues(new Uint8Array(32));

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
    transport: {
      send: aliceToBob.send,
      recv: bobToAlice.recv,
    },
    mode: "nopin",
    pqMode: "hybrid-mlkem768",
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
    transport: {
      send: bobToAlice.send,
      recv: aliceToBob.recv,
    },
    mode: "nopin",
    pqMode: "hybrid-mlkem768",
    crypto: cryptoOptions,
  }),
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const envelope = await alice.encrypt(encoder.encode("hello"));
console.log(decoder.decode(await bob.decrypt(envelope)));

// serialize() returns a plaintext secret snapshot.
const snapshot = await alice.serialize();
await alice.destroy();
const restoredAlice = await restoreSession(snapshot, cryptoOptions);
snapshot.fill(0);

const reply = await bob.encrypt(encoder.encode("still synchronized"));
console.log(decoder.decode(await restoredAlice.decrypt(reply)));

await Promise.all([restoredAlice.destroy(), bob.destroy()]);
aliceIdentity.ed25519SecretKey.fill(0);
aliceIdentity.x25519SecretKey.fill(0);
bobIdentity.ed25519SecretKey.fill(0);
bobIdentity.x25519SecretKey.fill(0);
```

The repository version is
[`examples/standalone-e2ee.ts`](https://github.com/p2party/p2party-js/blob/master/examples/standalone-e2ee.ts)
and runs with:

```sh
bun run examples/standalone-e2ee.ts
```

## Transport contract

The entire handshake adapter is:

```ts
interface HandshakeTransport {
  send(bytes: Uint8Array): void | Promise<void>;
  recv(): Promise<Uint8Array>;
}
```

The application must provide one full-duplex transport with these semantics:

- reliable, ordered, message-delimited delivery for handshake byte arrays;
- every `send(bytes)` becomes one `recv()` value on the peer, without
  concatenation, splitting, mutation, or unrelated application frames;
- asynchronous send failures reject the returned promise; and
- closure, timeout, and cancellation reject pending operations rather than
  hanging forever.

TCP and WebSocket adapters therefore need explicit message framing and routing.
Run the initiator and responder calls concurrently. The roles, auth mode, exact
ML-KEM suite, channel ID, identities, and endpoint fingerprints must describe
the same session from opposite ends. There is no suite negotiation or fallback.

`HandshakeTransport` carries only handshake flights. After creation, the
application serializes the returned `EncryptedSessionMessage` structure over
its normal message transport. p2party intentionally does not prescribe an
outer CBOR/JSON/stream framing; preserve `protocolVersion`, `root`, frame
ordering, and every frame byte exactly.

## Identity and channel binding

`generateSessionIdentity()` returns:

```ts
interface GeneratedSessionIdentity {
  ed25519PublicKey: Uint8Array;
  ed25519SecretKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  x25519SecretKey: Uint8Array;
  x25519CrossSignature: Uint8Array;
}
```

The critical naming rule is:

> `x25519SecretKey` is the long-term X25519 identity-DH secret. It is never the
> Ed25519 signing secret.

Ed25519 anchors the externally pinned identity and cross-signs the dedicated
X25519 public key. The interactive 3DH handshake proves possession of the
X25519 secret. Persist both secret keys with an OS keystore or equivalent, and
pin the peer's Ed25519 public key through a trusted directory, QR exchange, or
an explicit trust-on-first-use policy. Merely receiving that key over the same
untrusted connection is not authentication.

`SessionChannelBinding` contains:

```ts
interface SessionChannelBinding {
  channelId: Uint8Array;
  localFingerprint: Uint8Array; // exactly 32 bytes
  remoteFingerprint: Uint8Array; // exactly 32 bytes
}
```

Both peers use the same non-empty `channelId`. Their local and remote
fingerprints are reversed. For WebRTC these are SHA-256 DTLS certificate
fingerprints. A custom transport should derive equivalent 32-byte endpoint
bindings from its authenticated connection context. Random shared values, as
used by the single-process example, demonstrate the API but do not independently
authenticate a real network path.

## Authentication and suite selection

No-PIN creation uses:

```ts
{
  mode: "nopin";
}
```

PIN creation uses:

```ts
{
  mode: "pin";
  pin: Uint8Array;
}
```

Both peers must provide the same non-empty PIN. The implementation copies
sensitive inputs it needs; the caller still owns and should wipe its original
buffer. PIN mode adds exact draft-21 CPace to interactive 3DH and the selected
ML-KEM secret.

`pqMode` is exactly one of `hybrid-mlkem512`, `hybrid-mlkem768`, or
`hybrid-mlkem1024`, and defaults to `hybrid-mlkem768`. Both peers choose the
same value out of band. A mismatch fails the transcript; it is never a request
to downgrade.

## Encrypt, decrypt, snapshot, destroy

A live session exposes:

```ts
interface P2PartySession {
  readonly protocolVersion: 3;
  readonly pqMode: "hybrid-mlkem512" | "hybrid-mlkem768" | "hybrid-mlkem1024";
  readonly canEncrypt: boolean;
  encrypt(plaintext: Uint8Array): Promise<EncryptedSessionMessage>;
  decrypt(message: EncryptedSessionMessage): Promise<Uint8Array>;
  serialize(): Promise<Uint8Array>;
  destroy(): Promise<void>;
}
```

Each encrypted envelope has one authenticated Merkle root and one or more
uniform protocol-v3 frames. Either role may send first, and simultaneous first
messages are supported. Ratchet state advances transactionally: a failed
decrypt does not commit the candidate receive state.

`serialize()` waits for in-flight encryption and returns the current ratchet as
a plaintext secret blob. Before persistence:

1. encrypt it with authenticated encryption under a device-bound storage key;
2. bind it to the account, peer, room/channel, and suite in associated data;
3. add a monotonic version or equivalent rollback guard; and
4. replace the previous snapshot atomically.

Confidentiality without rollback protection is insufficient: restoring an old
ratchet can reuse state and violate forward-security assumptions. Never send a
snapshot to the peer, sync it through an unauthenticated store, log it, or
place it in browser storage as plaintext.

After `restoreSession(snapshot, cryptoOptions)`, wipe the caller's snapshot
buffer.
Call `destroy()` on replaced and shutdown sessions; after destruction,
`canEncrypt` is false. Wipe caller-owned identity secrets when their lifecycle
ends.

## WASM behavior

`SessionCryptoOptions` is:

```ts
interface SessionCryptoOptions {
  wasmBinary?: ArrayBuffer | Uint8Array;
}
```

Supplying bytes is the reproducible, offline-safe path. Resolve the exported
`p2party/libcrypto.wasm` package subpath or pin a self-hosted copy from the same
release. When `wasmBinary` is omitted, the loader fetches the immutable
versioned p2party CDN artifact and checks the build-pinned SHA-384 SRI.

See [Protocol-v3 security](protocol-v3-security.md) for the exact claims and
non-claims of the session this API constructs.
