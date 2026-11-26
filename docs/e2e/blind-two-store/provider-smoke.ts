// Browser entry for the WebRTC-provider smoke test of the flagged two-store
// blind-rendezvous prototype. Bundled with `bun build --target=browser` (see
// README.md) and driven by `provider-smoke.mjs` in headless Chromium.
//
// It exercises `src/blindRendezvous/prototype/webrtcProvider.ts` on its own,
// with no store, no carrier and no pair driver: two providers in ONE page pass
// offer/answer to each other by direct call, open a real DTLS/SCTP data
// channel, verify their live certificates against the fingerprints parsed out
// of the exact SDP bytes, run a real protocol-v4 `createSession` on both sides
// over `dataChannelTransport`, and exchange a multi-chunk message each way.
import {
  WebRtcCandidateProvider,
  WebRtcProviderError,
  dataChannelTransport,
  type DataChannelTransport,
} from "../../../src/blindRendezvous/prototype/webrtcProvider";
import { parseFingerprintFromSdp } from "../../../src/utils/sdpFingerprint";
import { isIdentityInitiator } from "../../../src/utils/identityRole";
import {
  createSession,
  generateSessionIdentity,
  type EncryptedSessionMessage,
  type GeneratedSessionIdentity,
  type P2PartySession,
} from "../../../src/session";

const te = new TextEncoder();
const td = new TextDecoder();

/** Exactly 32 bytes; both sides bind the same rendezvous channel id. */
const CHANNEL_ID = te.encode("p2party-blind-provider-smoke-32b");

/** SCTP-friendly application slice; the session's own frames are 65,490 B. */
const APP_SLICE = 16 * 1024;

const CHANNEL_OPEN_TIMEOUT_MS = 20_000;
const CONNECTED_TIMEOUT_MS = 20_000;
const HANDSHAKE_TIMEOUT_MS = 60_000;
const MESSAGE_TIMEOUT_MS = 60_000;

const toHex = (bytes: Uint8Array): string => {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
};

const withTimeout = <T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> =>
  Promise.race([
    promise,
    new Promise<T>((_resolve, reject) =>
      setTimeout(() => reject(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms),
    ),
  ]);

const waitChannelOpen = (channel: RTCDataChannel): Promise<void> =>
  channel.readyState === "open"
    ? Promise.resolve()
    : withTimeout(
        new Promise<void>((resolve, reject) => {
          channel.addEventListener("open", () => resolve(), { once: true });
          channel.addEventListener(
            "close",
            () => reject(new Error("data channel closed before it opened")),
            { once: true },
          );
        }),
        CHANNEL_OPEN_TIMEOUT_MS,
        `${channel.label} open`,
      );

const waitConnected = (pc: RTCPeerConnection, label: string): Promise<void> =>
  pc.connectionState === "connected"
    ? Promise.resolve()
    : withTimeout(
        new Promise<void>((resolve, reject) => {
          const onChange = (): void => {
            if (pc.connectionState === "connected") {
              pc.removeEventListener("connectionstatechange", onChange);
              resolve();
            } else if (
              pc.connectionState === "failed" ||
              pc.connectionState === "closed"
            ) {
              pc.removeEventListener("connectionstatechange", onChange);
              reject(
                new Error(`${label} connectionState=${pc.connectionState}`),
              );
            }
          };
          pc.addEventListener("connectionstatechange", onChange);
          onChange();
        }),
        CONNECTED_TIMEOUT_MS,
        `${label} connected`,
      );

// ── application framing over the transport's app lane ─────────────────────────
// The session hands back {root, frames[]}; this flattens it to one blob,
// length-prefixes it and ships it as 16 KiB app-tagged slices. Purely a harness
// concern: the provider only promises an ordered byte lane.

const serializeEnvelope = (message: EncryptedSessionMessage): Uint8Array => {
  let total = 2 + message.root.length + 2;
  for (const frame of message.frames) total += 4 + frame.length;
  const blob = new Uint8Array(total);
  const view = new DataView(blob.buffer);
  let offset = 0;
  view.setUint16(offset, message.root.length, false);
  offset += 2;
  blob.set(message.root, offset);
  offset += message.root.length;
  view.setUint16(offset, message.frames.length, false);
  offset += 2;
  for (const frame of message.frames) {
    view.setUint32(offset, frame.length, false);
    offset += 4;
    blob.set(frame, offset);
    offset += frame.length;
  }
  return blob;
};

const parseEnvelope = (blob: Uint8Array): EncryptedSessionMessage => {
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  let offset = 0;
  const rootLength = view.getUint16(offset, false);
  offset += 2;
  const root = blob.slice(offset, offset + rootLength);
  offset += rootLength;
  const frameCount = view.getUint16(offset, false);
  offset += 2;
  const frames: Uint8Array[] = [];
  for (let index = 0; index < frameCount; index++) {
    const frameLength = view.getUint32(offset, false);
    offset += 4;
    frames.push(blob.slice(offset, offset + frameLength));
    offset += frameLength;
  }
  return { protocolVersion: 4, root, frames };
};

const sendMessage = async (
  session: P2PartySession,
  transport: DataChannelTransport,
  plaintext: Uint8Array,
): Promise<number> => {
  const message = await session.encrypt(plaintext);
  const blob = serializeEnvelope(message);
  const framed = new Uint8Array(4 + blob.length);
  new DataView(framed.buffer).setUint32(0, blob.length, false);
  framed.set(blob, 4);
  // Every slice is queued before any is awaited, so they enter the lane in
  // order; awaiting them all waits for the channel to take them and carries a
  // refused or closed channel into run()'s result instead of leaving it
  // unhandled.
  const slices: Promise<void>[] = [];
  for (let offset = 0; offset < framed.length; offset += APP_SLICE)
    slices.push(
      transport.sendApp(
        framed.subarray(offset, Math.min(offset + APP_SLICE, framed.length)),
      ),
    );
  await Promise.all(slices);
  return message.frames.length;
};

const recvMessage = async (
  session: P2PartySession,
  transport: DataChannelTransport,
): Promise<Uint8Array> => {
  const first = await transport.recvApp();
  if (first.length < 4)
    throw new Error("app frame shorter than its length prefix");
  const total = new DataView(
    first.buffer,
    first.byteOffset,
    first.byteLength,
  ).getUint32(0, false);
  const accumulator = new Uint8Array(4 + total);
  accumulator.set(first, 0);
  let have = first.length;
  while (have < accumulator.length) {
    const next = await transport.recvApp();
    accumulator.set(next, have);
    have += next.length;
  }
  return session.decrypt(parseEnvelope(accumulator.subarray(4)));
};

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

// ── the smoke run ────────────────────────────────────────────────────────────

export interface ProviderSmokeResult {
  connected: boolean;
  connectionStates: { a: string; b: string };
  dtls: { a: "verified" | "unsupported"; b: "verified" | "unsupported" };
  bytesExactAB: boolean;
  bytesExactBA: boolean;
  sdpBytes: { offer: number; answer: number };
  fingerprints: { a: string; b: string };
  roles: { a: string; b: string };
  frames: { ab: number; ba: number };
  /** A close must reject pending waiters, never leave them pending forever. */
  closeRejectsWaiters: { channel: boolean; recvApp: boolean };
  timings: Record<string, number>;
}

/** True when the promise rejected with this module's own error type. */
const rejectsWithProviderError = (
  promise: Promise<unknown>,
): Promise<boolean> =>
  promise.then(
    () => false,
    (error: unknown) => error instanceof WebRtcProviderError,
  );

let wasmBinary: ArrayBuffer | null = null;
const loadWasm = async (): Promise<ArrayBuffer> => {
  if (!wasmBinary) {
    const response = await fetch("./libcrypto.wasm");
    if (!response.ok)
      throw new Error(`libcrypto.wasm fetch failed: ${response.status}`);
    wasmBinary = await response.arrayBuffer();
  }
  return wasmBinary;
};

const run = async (): Promise<ProviderSmokeResult> => {
  const t0 = performance.now();
  const timings: Record<string, number> = {};
  const mark = (name: string, from: number): void => {
    timings[name] = Math.round(performance.now() - from);
  };

  const rtcConfig: RTCConfiguration = { iceServers: [] };
  const a = new WebRtcCandidateProvider({ rtcConfig, role: "initiator" });
  const b = new WebRtcCandidateProvider({ rtcConfig, role: "responder" });

  let transportA: DataChannelTransport | null = null;
  let transportB: DataChannelTransport | null = null;
  let sessionA: P2PartySession | null = null;
  let sessionB: P2PartySession | null = null;

  try {
    // 1-2. Offer -> answer -> answer accepted, by direct call. No signaling.
    const tOffer = performance.now();
    const offer = await a.createOffer();
    mark("createOfferMs", tOffer);
    const tAnswer = performance.now();
    const answer = await b.acceptOffer(offer);
    mark("acceptOfferMs", tAnswer);
    const tAccept = performance.now();
    await a.acceptAnswer(answer);
    mark("acceptAnswerMs", tAccept);

    // 3. Both channels open and both peer connections connected.
    const tConnect = performance.now();
    const [channelA, channelB] = await Promise.all([
      withTimeout(a.channel(), CHANNEL_OPEN_TIMEOUT_MS, "A channel"),
      withTimeout(b.channel(), CHANNEL_OPEN_TIMEOUT_MS, "B channel"),
    ]);
    await Promise.all([waitChannelOpen(channelA), waitChannelOpen(channelB)]);
    await Promise.all([
      waitConnected(a.peerConnection, "A"),
      waitConnected(b.peerConnection, "B"),
    ]);
    mark("connectMs", tConnect);

    // 4. DTLS fingerprints out of the EXACT SDP bytes each side exchanged.
    const fingerprintA = parseFingerprintFromSdp(td.decode(offer));
    const fingerprintB = parseFingerprintFromSdp(td.decode(answer));
    const tDtls = performance.now();
    const [dtlsA, dtlsB] = await Promise.all([
      a.verifyCertificates(fingerprintA, fingerprintB),
      b.verifyCertificates(fingerprintB, fingerprintA),
    ]);
    mark("verifyCertificatesMs", tDtls);

    // 5. A real protocol-v4 session on both sides over the one data channel.
    const binary = await loadWasm();
    const tIdentity = performance.now();
    const identities = (await Promise.all([
      generateSessionIdentity({ wasmBinary: binary }),
      generateSessionIdentity({ wasmBinary: binary }),
    ])) as [GeneratedSessionIdentity, GeneratedSessionIdentity];
    mark("identityMs", tIdentity);
    const [identityA, identityB] = identities;
    const hexA = toHex(identityA.ed25519PublicKey);
    const hexB = toHex(identityB.ed25519PublicKey);
    // Session role comes from the byte order of the two identity keys, not
    // from who dialled: the lexically lower Ed25519 public key is initiator.
    const aIsInitiator = isIdentityInitiator(hexA, hexB);

    transportA = dataChannelTransport(channelA);
    transportB = dataChannelTransport(channelB);

    const tHandshake = performance.now();
    const sessions = (await withTimeout(
      Promise.all([
        createSession({
          transport: transportA,
          role: aIsInitiator ? "initiator" : "responder",
          identity: identityA,
          peerIdentityEd25519PublicKey: identityB.ed25519PublicKey,
          channel: {
            channelId: CHANNEL_ID,
            localFingerprint: fingerprintA,
            remoteFingerprint: fingerprintB,
          },
          mode: "nopin",
          crypto: { wasmBinary: binary },
        }),
        createSession({
          transport: transportB,
          role: aIsInitiator ? "responder" : "initiator",
          identity: identityB,
          peerIdentityEd25519PublicKey: identityA.ed25519PublicKey,
          channel: {
            channelId: CHANNEL_ID,
            localFingerprint: fingerprintB,
            remoteFingerprint: fingerprintA,
          },
          mode: "nopin",
          crypto: { wasmBinary: binary },
        }),
      ]),
      HANDSHAKE_TIMEOUT_MS,
      "createSession",
    )) as [P2PartySession, P2PartySession];
    mark("handshakeMs", tHandshake);
    [sessionA, sessionB] = sessions;

    // 6. Multi-chunk message each way, asserted byte-exact.
    const messageAB = te.encode(`A->B ${"x".repeat(140_000)}`);
    const messageBA = te.encode(`B->A ${"y".repeat(90_000)}`);

    const tAB = performance.now();
    const [framesAB, gotAB] = await withTimeout(
      Promise.all([
        sendMessage(sessionA, transportA, messageAB),
        recvMessage(sessionB, transportB),
      ]),
      MESSAGE_TIMEOUT_MS,
      "A->B message",
    );
    mark("messageAbMs", tAB);

    const tBA = performance.now();
    const [framesBA, gotBA] = await withTimeout(
      Promise.all([
        sendMessage(sessionB, transportB, messageBA),
        recvMessage(sessionA, transportA),
      ]),
      MESSAGE_TIMEOUT_MS,
      "B->A message",
    );
    mark("messageBaMs", tBA);

    // 7. Teardown discipline. A pending receive whose peer went away has to
    // surface as a rejection: a rendezvous that hangs forever on a dead channel
    // is the failure mode this rule exists to prevent. Same for a responder
    // waiting on a data channel that will never arrive.
    const idle = new WebRtcCandidateProvider({ rtcConfig, role: "responder" });
    const pendingChannel = rejectsWithProviderError(idle.channel());
    idle.close();
    const pendingRecv = rejectsWithProviderError(transportA.recvApp());
    transportA.close();
    const closeRejectsWaiters = {
      channel: await pendingChannel,
      recvApp: await pendingRecv,
    };

    mark("totalMs", t0);

    return {
      connected:
        a.peerConnection.connectionState === "connected" &&
        b.peerConnection.connectionState === "connected",
      connectionStates: {
        a: a.peerConnection.connectionState,
        b: b.peerConnection.connectionState,
      },
      dtls: { a: dtlsA, b: dtlsB },
      bytesExactAB: sameBytes(messageAB, gotAB),
      bytesExactBA: sameBytes(messageBA, gotBA),
      sdpBytes: { offer: offer.length, answer: answer.length },
      fingerprints: { a: toHex(fingerprintA), b: toHex(fingerprintB) },
      roles: {
        a: aIsInitiator ? "initiator" : "responder",
        b: aIsInitiator ? "responder" : "initiator",
      },
      frames: { ab: framesAB, ba: framesBA },
      closeRejectsWaiters,
      timings,
    };
  } finally {
    await sessionA?.destroy();
    await sessionB?.destroy();
    transportA?.close();
    transportB?.close();
    a.close();
    b.close();
  }
};

declare global {
  interface Window {
    __providerSmoke: { run: () => Promise<ProviderSmokeResult> };
  }
}

window.__providerSmoke = { run };
