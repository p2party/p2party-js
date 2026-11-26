/**
 * The browser composition of the flagged two-store rendezvous prototype: the
 * one call a page makes to go from a room capability to an authenticated,
 * encrypted protocol-v4 session with a peer it has never signalled with.
 *
 * Everything below this file already exists and is tested on its own. What is
 * here is the wiring, and the wiring is where the prototype's claims live or
 * die, so three joins are deliberate rather than incidental:
 *
 *   1. THE WEBRTC PROVIDER IS BUILT LAZILY. `RTCPeerConnection` construction is
 *      role-asymmetric — the initiator must create its data channel before the
 *      offer, the responder must be listening on `ondatachannel` before it sets
 *      the remote description — but which role this endpoint plays is not known
 *      until the driver has seen the peer's presence and compared operation
 *      ids. So the driver is handed a lazy `TransportCandidateProvider` that
 *      builds the real one on the first call, and the call itself names the
 *      role: only a rendezvous initiator ever calls `createOffer`, only a
 *      responder ever calls `acceptOffer`. The role is therefore the driver's,
 *      derived from the driver, never guessed here.
 *   2. THE DTLS CHECK GATES THE SESSION. `verifyCertificates` runs after the
 *      connection reports `connected` and before `createSession`, against the
 *      fingerprints the pair transcript bound. A throw ends the session: the
 *      peer connection is closed and a `session-failed` event says why. It
 *      does NOT end the carrier schedule. Both endpoints of a pair reach their
 *      handoff together, so a schedule that stopped with the session would
 *      put both of them silent at an instant the pair's handshake chose, which
 *      a store joins across its log. The schedule runs until the caller stops
 *      the run. (`"unsupported"` — an engine with no certificate stats — is
 *      reported and allowed, exactly as `webrtcProvider.ts` documents.)
 *   3. NOTHING HERE IS NODE. This module is bundled for the browser with
 *      `bun build --target=browser`, so it may not import `node:*`, the Redux
 *      layer, or anything under `prototype/store/` (which reaches for
 *      `node:fs` and `bun:sqlite`). The store is spoken to over `fetch` and
 *      nothing else.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte, and the prototype
 * earns no privacy label — see the design doc's "What this is not".
 */

import libcrypto from "../../cryptography/libcrypto";
import { decodeRoomPolicyV1 } from "../../roomPolicy";
import { createSession, generateSessionIdentity } from "../../session";
import { crypto_hash_sha512_BYTES } from "../../cryptography/interfaces";
import {
  CHUNK_RATCHET_HEADER_END,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_LEN,
  PROTOTYPE_STOP_DRAIN_TIMEOUT_MS,
  WIRE_CHUNK_FRAME_LEN,
} from "../../utils/constants";
import { deliveryProfileHash } from "../derivations";
import { CarrierRuntime } from "./carrierRuntime";
import { PairDriver } from "./pairDriver";
import { PROTOTYPE_DELIVERY_PROFILE_V0, withDeliveryWindowMs } from "./profile";
import { PrototypeStoreClient } from "./storeClient";
import {
  WebRtcCandidateProvider,
  WebRtcProviderError,
  dataChannelTransport,
} from "./webrtcProvider";

import type { LibCrypto } from "../../cryptography/libcrypto";
import type { RoomPqMode } from "../../roomPolicy";
import type {
  EncryptedSessionMessage,
  GeneratedSessionIdentity,
  P2PartySession,
} from "../../session";
import type {
  CarrierTimerHandle,
  CarrierTimers,
  StoreTopology,
} from "./carrierRuntime";
import type {
  HandoffFacts,
  PairDriverPhase,
  TransportCandidateProvider,
} from "./pairDriver";
import type { DeliveryProfileV1 } from "./profile";
import type {
  StoreAdmissionTokenProvider,
  StoreFaultRecord,
} from "./storeClient";
import type { DataChannelTransport } from "./webrtcProvider";

/**
 * Linear memory for this run's own libcrypto instance, the same 1,024 pages the
 * blind-rendezvous tests use. The session API allocates its own instances.
 */
const WASM_PAGES = 1024;

/**
 * How long the handoff waits for the transport to become usable.
 *
 * These are deliberately long. The responder reaches `handoff` the moment it
 * publishes its ANSWER, which is a whole delivery window before the initiator
 * can possibly read it and call `setRemoteDescription`, so the responder's
 * connection legitimately sits in `connecting` for that window. A short
 * deadline here would fail a run that was working.
 *
 * The protocol-v4 handshake that follows is the last step of making the
 * transport usable and gets the connection's budget: once both ends are
 * connected it needs round trips, not windows, so a handshake still pending
 * after this long is a peer that stopped answering.
 */
const CHANNEL_TIMEOUT_MS = 60_000;
const CONNECTED_TIMEOUT_MS = 60_000;

/**
 * The largest frame count `recvMessage` will believe from its peer.
 *
 * The header that carries it is ordinary framing, not authenticated bytes —
 * the AEAD only speaks once the frames are assembled — so a peer that lied
 * about the count could otherwise make this endpoint wait for, and accumulate,
 * an unbounded number of frames. 65,536 uniform chunk frames is over 4 GB of
 * plaintext, far past anything this prototype sends.
 */
const MAX_APP_FRAMES = 65_536;

/**
 * The app-lane header `[u32be rootLength][root][u32be frameCount]`, or what is
 * wrong with it. The root is the message's SHA-512 Merkle root, so its length
 * is fixed, and a message has at least one chunk frame.
 */
const parseMessageHeader = (
  header: Uint8Array,
): { readonly root: Uint8Array; readonly frameCount: number } | string => {
  if (header.length < 8)
    return "the application header is shorter than its two length fields";
  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength,
  );
  const rootLength = view.getUint32(0, false);
  if (header.length !== 4 + rootLength + 4)
    return "the application header length does not match its root length";
  if (rootLength !== crypto_hash_sha512_BYTES)
    return `the application header carries a ${String(rootLength)}-byte root, not a ${String(crypto_hash_sha512_BYTES)}-byte one`;
  const frameCount = view.getUint32(4 + rootLength, false);
  if (frameCount === 0) return "the application header announces no frames";
  if (frameCount > MAX_APP_FRAMES)
    return `the peer announced ${String(frameCount)} frames, past the ${String(MAX_APP_FRAMES)} this transport accepts`;
  return { root: header.slice(4, 4 + rootLength), frameCount };
};

/**
 * What is wrong with frame `index` of a message, or null: it must be a whole
 * protocol-v4 chunk frame, and every chunk of one message shares the first
 * one's ratchet header (one ratchet step per message), as the session itself
 * requires. A frame that fails is not this message's next frame, so the lane
 * is out of step.
 */
const chunkFrameViolation = (
  frame: Uint8Array,
  first: Uint8Array | undefined,
  index: number,
): string | null => {
  if (frame.length !== WIRE_CHUNK_FRAME_LEN)
    return `frame ${String(index)} is ${String(frame.length)} bytes, not a ${String(WIRE_CHUNK_FRAME_LEN)}-byte chunk frame`;
  if (frame[0] !== FRAME_TYPE_CHUNK)
    return `frame ${String(index)} has frame type ${String(frame[0])}, not a chunk frame's ${String(FRAME_TYPE_CHUNK)}`;
  if (first === undefined) return null;
  for (
    let offset = FRAME_TYPE_LEN;
    offset < CHUNK_RATCHET_HEADER_END;
    offset += 1
  )
    if (frame[offset] !== first[offset])
      return `frame ${String(index)} carries another ratchet header than frame 0: it belongs to another message`;
  return null;
};

export class PrototypeRunError extends Error {
  override readonly name: string = "PrototypeRunError";

  constructor(message: string, options?: { readonly cause?: unknown }) {
    super(`blindRendezvousPrototype: ${message}`, options);
  }
}

/**
 * A deadline passed before the awaited step finished: a phase that did not
 * arrive, a session that was not established, a handshake that stalled, a
 * message that did not come. Distinct from every other run failure, so a
 * caller can tell "the peer was too slow" from "the edge is broken". A call
 * that rejects with it has neither sent nor taken any part of a message.
 */
export class PrototypeRunTimeoutError extends PrototypeRunError {
  override readonly name = "PrototypeRunTimeoutError";
}

/**
 * Why this endpoint ended a session, for a caller to switch on:
 *   - `"send-deadline"`: a send's deadline passed with part of its message on
 *     the lane.
 *   - `"refused"`: the open data channel refused a frame.
 *   - `"receive-deadline"`: a receive's deadline passed with part of a
 *     message taken.
 *   - `"protocol"`: a received header or frame did not parse at its place in
 *     a message, so the lane's framing can no longer be trusted.
 */
export type PrototypeSessionEndReason =
  "send-deadline" | "refused" | "receive-deadline" | "protocol";

/**
 * This endpoint ended the session because its app lane can no longer be
 * framed (`reason` says how). Every call on the session from then on —
 * including one that overlapped the call that ended it — rejects with this
 * same error; `cause`, when there is one, is the failure that ended it.
 */
export class PrototypeSessionEndedError extends PrototypeRunError {
  override readonly name = "PrototypeSessionEndedError";
  readonly reason: PrototypeSessionEndReason;

  constructor(
    reason: PrototypeSessionEndReason,
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, options);
    this.reason = reason;
  }
}

/**
 * A `recvMessage` called while another is still reading. Reads are one at a
 * time — the app lane is positional — so the second call is refused at once
 * and takes nothing; the first goes on unaffected.
 */
export class PrototypeReadInProgressError extends PrototypeRunError {
  override readonly name = "PrototypeReadInProgressError";
}

const fail: (message: string) => never = (message) => {
  throw new PrototypeRunError(message);
};

const detailOf = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

/** One observable step of a run, in wall-clock time so two pages can be
 * interleaved into one timeline by a harness. */
export interface PrototypeRunEvent {
  readonly atMs: number;
  readonly kind: string;
  readonly detail?: string;
}

export interface PrototypeRunOptions {
  /** The 32-byte room capability both endpoints hold out of band. */
  readonly capability: Uint8Array;
  /**
   * One or more store origins, exactly as the store signed them into its route
   * locator. A store that cannot be reached or cannot be validated is skipped
   * with a `store-unreachable` event; zero usable stores is a failed run.
   */
  readonly storeOrigins: readonly string[];
  readonly wasmBinary: ArrayBuffer;
  readonly rtcConfig: RTCConfiguration;
  /**
   * Rescale the pinned delivery profile to a faster cadence. BOTH endpoints and
   * every store must use the same value: the profile hash is derived from the
   * geometry, and a store serving a different hash serves a different bucket.
   */
  readonly deliveryWindowMs?: bigint;
  /**
   * Admission tokens for stores that gate their allocation, append and
   * witness routes, handed to every store client this run connects
   * (`StoreClientOptions.admissionTokens`). Absent, every store is spoken to
   * under open admission.
   */
  readonly admissionTokens?: StoreAdmissionTokenProvider;
  readonly onEvent: (event: PrototypeRunEvent) => void;
}

/**
 * The room secrets a harness greps a store's wire log for, so it can state
 * — for that run — that the store never received them.
 *
 * This is the room capability itself and the exact SDP that carries both DTLS
 * fingerprints. The result must never be logged, persisted or sent anywhere.
 */
export interface PrototypeRunAudit {
  readonly capabilityHex: string;
  readonly roomContextIdHex: string;
  readonly stableKeyHex: string;
  readonly sdpLocalUtf8: string | null;
  readonly sdpRemoteUtf8: string | null;
}

export interface PrototypeRun {
  readonly driver: PairDriver;
  readonly runtime: CarrierRuntime;
  /**
   * Resolve when the pair driver reaches `phase`; reject if the edge fails,
   * the run is stopped, or the deadline passes.
   *
   * Phases are role-specific: only a rendezvous initiator ever reaches
   * `hello-sent` and `offer-sent`, only a responder `hello-opened`,
   * `offer-opened` and `answered`. Both reach `handoff`, which is the one a
   * caller that just wants to talk should wait for.
   */
  waitForPhase(phase: PairDriverPhase, timeoutMs: number): Promise<void>;
  /**
   * Send one message once the session exists. It resolves once every frame is
   * in the data channel's send buffer, which is not delivery: `stop()` is what
   * waits for that buffer to drain. Rejects with `PrototypeRunTimeoutError` if
   * it cannot start to leave within `timeoutMs` of the call — and then it has
   * not left at all — and with the failure itself if the session could not be
   * established. A deadline that passes while the message is leaving, or a
   * frame the channel refuses, ends the session and rejects with
   * `PrototypeSessionEndedError`; so does every later call, and an
   * overlapping one, on the session that ended.
   */
  sendMessage(bytes: Uint8Array, timeoutMs: number): Promise<void>;
  /**
   * Receive one message. Rejects with `PrototypeRunTimeoutError`, taking
   * nothing, if no frame of a message arrived within `timeoutMs`; a deadline
   * that passes part-way through a message, or a header or frame that does
   * not parse, ends the session and rejects with `PrototypeSessionEndedError`.
   * Reads are one at a time: a call made while another is still reading
   * rejects at once with `PrototypeReadInProgressError` and takes nothing.
   */
  recvMessage(timeoutMs: number): Promise<Uint8Array>;
  auditSecrets(): PrototypeRunAudit;
  storeTopology(): StoreTopology;
  faults(): readonly StoreFaultRecord[];
  /**
   * Stop the run. The schedule, the session and every pending wait end at
   * once; frames already in the data channel's send buffer are given up to
   * `PROTOTYPE_STOP_DRAIN_TIMEOUT_MS` to leave before the channel and the peer
   * connection close. Never rejects; see `PrototypeStopOutcome`.
   */
  stop(): Promise<PrototypeStopOutcome>;
}

/**
 * How a `stop()` left the frames this endpoint had queued:
 *   - `"drained"`: every frame left the data channel's send buffer before the
 *     channel closed, or the run never had frames to send.
 *   - `"undrained"`: the channel closed with frames possibly still queued —
 *     the buffer did not drain within `PROTOTYPE_STOP_DRAIN_TIMEOUT_MS`, the
 *     peer closed first, the channel refused a frame, or a session that had
 *     already ended (`PrototypeSessionEndedError`) took buffered frames with
 *     it. Those frames may never reach the peer.
 * "Left the buffer" is the browser's handover to its SCTP stack, not the
 * peer's receipt.
 */
export type PrototypeStopOutcome = "drained" | "undrained";

/* ------------------------------------------------------------------ *
 * Small async helpers
 * ------------------------------------------------------------------ */

const timedOut = (label: string, timeoutMs: number): PrototypeRunTimeoutError =>
  new PrototypeRunTimeoutError(
    `${label} did not complete within ${String(timeoutMs)}ms`,
  );

/** A deadline the caller supplies must be one `setTimeout` honours as given:
 * `undefined` would fire at once and read as a timeout that never happened. */
const requireDeadline = (timeoutMs: number, label: string): void => {
  if (
    typeof timeoutMs !== "number" ||
    !Number.isFinite(timeoutMs) ||
    timeoutMs < 0
  )
    fail(`${label} needs a finite, non-negative deadline in milliseconds`);
};

/**
 * Every deadline below runs on the run's own timers, the same injected pair
 * the carrier schedule uses, so a harness that drives the clock drives the
 * deadlines too.
 */
const withTimeout = async <T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
  timers: CarrierTimers,
): Promise<T> => {
  let timer: CarrierTimerHandle | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = timers.setTimeout(
          () => reject(timedOut(label, timeoutMs)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) timers.clearTimeout(timer);
  }
};

/**
 * One frame from a transport lane, under a deadline. Not `withTimeout`: that
 * would leave the receive registered on the lane, and the next frame to arrive
 * would settle a promise nobody reads any more. Here the deadline withdraws
 * the receive before it rejects, so a frame that arrives later waits for the
 * next read.
 */
const receiveWithin = async (
  receive: (signal: AbortSignal) => Promise<Uint8Array>,
  timeoutMs: number,
  label: string,
  timers: CarrierTimers,
): Promise<Uint8Array> => {
  const withdrawal = new AbortController();
  let timer: CarrierTimerHandle | undefined;
  try {
    return await Promise.race([
      receive(withdrawal.signal),
      new Promise<never>((_resolve, reject) => {
        timer = timers.setTimeout(() => {
          // The timeout settles the race first; the withdrawal right after,
          // in the same callback, rejects a receive nobody awaits any more.
          reject(timedOut(label, timeoutMs));
          withdrawal.abort();
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) timers.clearTimeout(timer);
  }
};

/**
 * Both waits below own their own deadline rather than being wrapped in
 * `withTimeout`. Wrapping settles the caller but leaves the listener and the
 * timer attached to a `RTCDataChannel` or `RTCPeerConnection` that outlives
 * them, so the timeout path has to be the one that unsubscribes.
 */
const waitChannelOpen = (
  channel: RTCDataChannel,
  timeoutMs: number,
  timers: CarrierTimers,
): Promise<void> =>
  channel.readyState === "open"
    ? Promise.resolve()
    : new Promise<void>((resolve, reject) => {
        // `settle` closes over `timer`, `onOpen` and `onClose`, all declared
        // below; nothing can call it before the executor finishes initializing
        // them, because the listeners and the timer are all attached after.
        const settle = (error?: PrototypeRunError): void => {
          timers.clearTimeout(timer);
          channel.removeEventListener("open", onOpen);
          channel.removeEventListener("close", onClose);
          if (error) reject(error);
          else resolve();
        };
        const onOpen = (): void => settle();
        const onClose = (): void =>
          settle(
            new PrototypeRunError(
              "the bootstrap data channel closed before it opened",
            ),
          );
        const timer = timers.setTimeout(
          () =>
            settle(
              new PrototypeRunTimeoutError(
                `the bootstrap data channel did not open within ${String(timeoutMs)}ms`,
              ),
            ),
          timeoutMs,
        );
        channel.addEventListener("open", onOpen);
        channel.addEventListener("close", onClose);
        if (channel.readyState === "open") settle();
        else if (
          channel.readyState === "closed" ||
          channel.readyState === "closing"
        )
          onClose();
      });

const waitConnected = (
  peerConnection: RTCPeerConnection,
  timeoutMs: number,
  timers: CarrierTimers,
): Promise<void> =>
  peerConnection.connectionState === "connected"
    ? Promise.resolve()
    : new Promise<void>((resolve, reject) => {
        const settle = (error?: PrototypeRunError): void => {
          timers.clearTimeout(timer);
          peerConnection.removeEventListener("connectionstatechange", onChange);
          if (error) reject(error);
          else resolve();
        };
        const onChange = (): void => {
          const state = peerConnection.connectionState;
          if (state === "connected") settle();
          else if (state === "failed" || state === "closed")
            settle(
              new PrototypeRunError(`the peer connection went to "${state}"`),
            );
        };
        const timer = timers.setTimeout(
          () =>
            settle(
              new PrototypeRunTimeoutError(
                `the peer connection did not connect within ${String(timeoutMs)}ms`,
              ),
            ),
          timeoutMs,
        );
        peerConnection.addEventListener("connectionstatechange", onChange);
        onChange();
      });

/* ------------------------------------------------------------------ *
 * The lazily-roled transport
 * ------------------------------------------------------------------ */

/**
 * The `TransportCandidateProvider` the driver is constructed with, which builds
 * the real `WebRtcCandidateProvider` on the driver's first call.
 *
 * The role is not a guess: `pairDriver.ts` calls `createOffer` only from the
 * rendezvous initiator's path and `acceptOffer` only from the responder's, so
 * the first call names the role the driver settled on when it compared the two
 * presence operation ids.
 */
class LazyWebRtcTransport implements TransportCandidateProvider {
  #provider: WebRtcCandidateProvider | null = null;
  #closed = false;

  constructor(
    private readonly rtcConfig: RTCConfiguration,
    private readonly onCreated: (role: "initiator" | "responder") => void,
  ) {}

  /** The concrete provider, or null while the driver has not needed one. */
  get provider(): WebRtcCandidateProvider | null {
    return this.#provider;
  }

  createOffer(): Promise<Uint8Array> {
    return this.#open("initiator").createOffer();
  }

  acceptOffer(remoteSdp: Uint8Array): Promise<Uint8Array> {
    return this.#open("responder").acceptOffer(remoteSdp);
  }

  acceptAnswer(remoteSdp: Uint8Array): Promise<void> {
    return this.#open("initiator").acceptAnswer(remoteSdp);
  }

  close(): void {
    this.#closed = true;
    this.#provider?.close();
  }

  #open(role: "initiator" | "responder"): WebRtcCandidateProvider {
    // The closed check precedes the memo: after `close()` the memoized provider
    // is a closed `RTCPeerConnection`, and handing it back would turn a stopped
    // run into a confusing failure inside the provider instead of a clear one
    // here.
    if (this.#closed) fail("the run was stopped before WebRTC was needed");
    if (this.#provider !== null) return this.#provider;
    const provider = new WebRtcCandidateProvider({
      rtcConfig: this.rtcConfig,
      role,
    });
    this.#provider = provider;
    this.onCreated(role);
    return provider;
  }
}

/* ------------------------------------------------------------------ *
 * The run
 * ------------------------------------------------------------------ */

interface EstablishedSession {
  readonly session: P2PartySession;
  readonly transport: DataChannelTransport;
}

interface PhaseWaiter {
  readonly phase: PairDriverPhase;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
}

/**
 * What a run needs from the WebRTC provider once the driver has opened one.
 *
 * @internal
 */
export type SessionTransportProvider = Pick<
  WebRtcCandidateProvider,
  "role" | "peerConnection" | "channel" | "verifyCertificates"
>;

/**
 * The run's handle on its WebRTC transport: the provider, once the driver
 * needed one, and teardown.
 *
 * @internal
 */
export interface RunTransport {
  readonly provider: SessionTransportProvider | null;
  close(): void;
}

/** @internal */
export interface RunParts {
  readonly driver: PairDriver;
  readonly runtime: CarrierRuntime;
  readonly transport: RunTransport;
  readonly identity: GeneratedSessionIdentity;
  readonly pqMode: RoomPqMode;
  readonly wasmBinary: ArrayBuffer;
  /** The deadline `createSession` runs under once the transport is up. */
  readonly handshakeTimeoutMs: number;
  /** The run's clock and timers: every deadline here runs on them. */
  readonly clock: { nowMs(): bigint };
  readonly timers: CarrierTimers;
  readonly emit: (kind: string, detail?: string) => void;
}

/**
 * One endpoint of a run. Exported for the composition tests only; a page gets
 * one from `runBlindRendezvousPrototype`.
 *
 * @internal
 */
export class BlindRendezvousRun implements PrototypeRun {
  readonly driver: PairDriver;
  readonly runtime: CarrierRuntime;

  readonly #transport: RunTransport;
  readonly #identity: GeneratedSessionIdentity;
  readonly #pqMode: RoomPqMode;
  readonly #wasmBinary: ArrayBuffer;
  readonly #handshakeTimeoutMs: number;
  readonly #clock: { nowMs(): bigint };
  readonly #timers: CarrierTimers;
  readonly #emit: (kind: string, detail?: string) => void;

  readonly #reached = new Set<PairDriverPhase>();
  #phaseWaiters: PhaseWaiter[] = [];
  #failure: PrototypeRunError | null = null;

  /**
   * Settles exactly once, when this endpoint has an authenticated session —
   * or when the edge fails or the run is stopped. It exists so `sendMessage`
   * and `recvMessage` can be called at any point after `run()` returns: the
   * pair exchange takes several delivery windows, and a caller that has to
   * poll for the right moment to speak would be re-implementing this gate.
   */
  readonly #sessionGate: Promise<EstablishedSession>;
  #openGate: ((session: Promise<EstablishedSession>) => void) | null = null;
  #closeGate: ((error: Error) => void) | null = null;

  #sessionPromise: Promise<EstablishedSession> | null = null;
  #session: P2PartySession | null = null;
  #appTransport: DataChannelTransport | null = null;
  #stopped = false;
  #stopping: Promise<PrototypeStopOutcome> | null = null;
  /** Set once, when a call ended the established session; see the class. */
  #sessionEnded: PrototypeSessionEndedError | null = null;
  /** Set when an ended session took frames with it that had not left. */
  #sessionLeftFrames = false;
  /** True while a `recvMessage` is reading: reads are one at a time. */
  #reading = false;

  constructor(parts: RunParts) {
    this.driver = parts.driver;
    this.runtime = parts.runtime;
    this.#transport = parts.transport;
    this.#identity = parts.identity;
    this.#pqMode = parts.pqMode;
    this.#wasmBinary = parts.wasmBinary;
    this.#handshakeTimeoutMs = parts.handshakeTimeoutMs;
    this.#clock = parts.clock;
    this.#timers = parts.timers;
    this.#emit = parts.emit;
    this.#sessionGate = new Promise<EstablishedSession>((resolve, reject) => {
      this.#openGate = resolve;
      this.#closeGate = reject;
    });
    // A run that is stopped before anyone asked for the session rejects this
    // gate with nobody listening; marking it handled keeps that from surfacing
    // in the page as an unhandled rejection.
    void this.#sessionGate.catch(() => undefined);
  }

  /**
   * The pair driver's phase callback. Every driver phase is emitted under its
   * own name — the harness's event vocabulary IS the driver's state machine,
   * deliberately, so there is no second one to drift from it.
   *
   * @internal
   */
  handlePhase(phase: PairDriverPhase, detail?: string): void {
    this.#reached.add(phase);
    this.#emit(phase, detail);

    if (phase === "failed") {
      this.#failure = new PrototypeRunError(
        `the pair edge failed: ${detail ?? "no detail"}`,
      );
      this.#closeGate?.(this.#failure);
      const waiters = this.#phaseWaiters.splice(0);
      for (const waiter of waiters) waiter.reject(this.#failure);
      return;
    }

    // Before the waiters, not after: a caller that awaited `handoff` must find
    // the session already under way when its continuation runs, so that
    // `sendMessage` can await it instead of failing on "no handoff yet".
    if (phase === "handoff") this.#startSession();

    const waiters = this.#phaseWaiters;
    this.#phaseWaiters = [];
    for (const waiter of waiters) {
      if (waiter.phase === phase) waiter.resolve();
      else this.#phaseWaiters.push(waiter);
    }
  }

  waitForPhase(phase: PairDriverPhase, timeoutMs: number): Promise<void> {
    if (this.#reached.has(phase)) return Promise.resolve();
    if (this.#failure !== null) return Promise.reject(this.#failure);
    // Not `withTimeout`: that settles the caller but leaves the waiter on the
    // list forever, and a long-lived run that polls for a phase it will never
    // reach would then accumulate one dead waiter per call.
    return new Promise<void>((resolve, reject) => {
      // `waiter` closes over `timer` and the timer's callback over `waiter`;
      // neither runs before both are initialized, because the waiter is only
      // published to `#phaseWaiters` after the timer exists.
      const waiter: PhaseWaiter = {
        phase,
        resolve: () => {
          this.#timers.clearTimeout(timer);
          resolve();
        },
        reject: (error) => {
          this.#timers.clearTimeout(timer);
          reject(error);
        },
      };
      const timer = this.#timers.setTimeout(() => {
        this.#dropWaiter(waiter);
        reject(
          new PrototypeRunTimeoutError(
            `phase "${phase}" did not arrive within ${String(timeoutMs)}ms`,
          ),
        );
      }, timeoutMs);
      this.#phaseWaiters.push(waiter);
    });
  }

  /**
   * One application message over the transport's app lane.
   *
   * FRAMING (both sides symmetric, this file is the only definition): one
   * header message `[u32be rootLength][root][u32be frameCount]` followed by
   * exactly `frameCount` messages, one uniform protocol-v4 chunk frame each.
   * The root is carried because `decrypt` authenticates it as additional data
   * and the frames alone do not contain it.
   *
   * OVERLAPPING CALLS. The framing is positional, so a message must reach the
   * lane whole. The session runs one `encrypt` at a time, and each call queues
   * all of its frames before it awaits any of them, so two overlapping calls
   * put two whole messages on the lane in the order they were encrypted. They
   * share one send buffer: a call's deadline also covers the wait behind the
   * other's frames. And they share the session: a deadline or a refused frame
   * that ends it ends it for both, so the other call rejects with the same
   * `PrototypeSessionEndedError` even if none of its own frames had left. The
   * prototype's harness awaits each call before the next.
   *
   * `timeoutMs` bounds the whole call: the wait for the session, the local
   * encryption, and the hand-off of every frame to the data channel, which
   * takes frames only as fast as it drains (`MAX_BUFFERED_AMOUNT`, see
   * `webrtcProvider.ts`). A call that rejects with `PrototypeRunTimeoutError`
   * sent nothing, so a caller may retry it without the peer receiving the
   * message twice. A deadline that passes once the hand-off has begun is a
   * different failure: part of the message may have left, the peer cannot
   * frame past a partial message, so the session is ended and the call
   * rejects with `PrototypeSessionEndedError`. So does a frame the open
   * channel refuses. A channel that closed is reported as the provider's
   * `WebRtcProviderError` and ends nothing here: frames it delivered stay
   * readable.
   */
  async sendMessage(bytes: Uint8Array, timeoutMs: number): Promise<void> {
    requireDeadline(timeoutMs, "sendMessage");
    const deadlineMs = this.#clock.nowMs() + BigInt(Math.ceil(timeoutMs));
    const established = await withTimeout(
      this.#requireSession(),
      timeoutMs,
      "session handoff",
      this.#timers,
    );
    this.#assertLive();
    let message: EncryptedSessionMessage;
    try {
      message = await established.session.encrypt(bytes);
    } catch (error) {
      throw this.#asCallFailure(error);
    }
    // A session that arrived just in time can still leave encryption to end
    // past the deadline; the message then stays unsent, as the rejection says.
    if (this.#clock.nowMs() > deadlineMs)
      throw timedOut("sendMessage", timeoutMs);

    const header = new Uint8Array(4 + message.root.length + 4);
    const view = new DataView(header.buffer);
    view.setUint32(0, message.root.length, false);
    header.set(message.root, 4);
    view.setUint32(4 + message.root.length, message.frames.length, false);

    // Every frame is queued before any is awaited, so the message enters the
    // app lane whole, in order, and nothing another call queues lands inside
    // it. The wait is for the channel to take all of them.
    const leaving = [header, ...message.frames].map((frame) =>
      established.transport.sendApp(frame),
    );
    const handedOff = Promise.all(leaving);
    try {
      await withTimeout(
        handedOff,
        Math.max(0, Number(deadlineMs - this.#clock.nowMs())),
        "sendMessage",
        this.#timers,
      );
    } catch (error) {
      void handedOff.catch(() => undefined);
      // Another call that met the same failure first has ended the session:
      // this one reports that end rather than a second one of its own.
      if (this.#sessionEnded !== null) throw this.#sessionEnded;
      const misframed: readonly [PrototypeSessionEndReason, string] | null =
        error instanceof PrototypeRunTimeoutError
          ? [
              "send-deadline",
              `the data channel did not take the message's ${String(leaving.length)} ` +
                `frames within ${String(timeoutMs)}ms of sendMessage`,
            ]
          : error instanceof WebRtcProviderError && error.reason === "refused"
            ? [
                "refused",
                `the data channel refused one of the message's ${String(leaving.length)} frames`,
              ]
            : null;
      if (misframed === null) throw this.#asCallFailure(error);
      const ended = new PrototypeSessionEndedError(
        misframed[0],
        `${misframed[1]}; part of it may have left, and the session was ended`,
        { cause: error },
      );
      // A local abort: what has not left is discarded and never leaves.
      this.#endSession(ended);
      throw ended;
    }
    this.#emit(
      "message-sent",
      `${String(bytes.length)} bytes in ${String(message.frames.length)} frames`,
    );
  }

  /**
   * One application message from the app lane (framing: see `sendMessage`).
   *
   * A deadline that passes before any frame of a message was taken rejects
   * with `PrototypeRunTimeoutError` and takes nothing: the next call reads
   * that message from its header. One that passes part-way through a message
   * ends the session and rejects with `PrototypeSessionEndedError`, since
   * what remains of the message can no longer be told from the next one.
   *
   * So does anything that does not parse at its place in a message (reason
   * `"protocol"`): a header whose lengths disagree, whose root is not a
   * SHA-512 digest or whose frame count is zero or too large, and a frame
   * that is not a whole protocol-v4 chunk frame or carries another message's
   * ratchet header. Each means the lane's positions can no longer be trusted,
   * so nothing more is read from it. These are the session's own structural
   * checks, made as each frame arrives instead of after the last one.
   *
   * ONE READ AT A TIME. The lane is positional, so two overlapping reads
   * would split one message's frames between them. A call made while another
   * is still reading is refused at once with `PrototypeReadInProgressError`
   * and takes nothing.
   */
  async recvMessage(timeoutMs: number): Promise<Uint8Array> {
    requireDeadline(timeoutMs, "recvMessage");
    if (this.#reading)
      throw new PrototypeReadInProgressError(
        "recvMessage was called while another recvMessage is still reading; reads are one at a time",
      );
    this.#reading = true;
    try {
      return await this.#readMessage(timeoutMs);
    } finally {
      this.#reading = false;
    }
  }

  async #readMessage(timeoutMs: number): Promise<Uint8Array> {
    const deadlineMs = this.#clock.nowMs() + BigInt(Math.ceil(timeoutMs));
    const remaining = (): number =>
      Math.max(1, Number(deadlineMs - this.#clock.nowMs()));

    const established = await withTimeout(
      this.#requireSession(),
      remaining(),
      "session handoff",
      this.#timers,
    );
    this.#assertLive();
    const lane = (signal: AbortSignal): Promise<Uint8Array> =>
      established.transport.recvApp(signal);
    let header: Uint8Array;
    try {
      header = await receiveWithin(
        lane,
        remaining(),
        "application message header",
        this.#timers,
      );
    } catch (error) {
      throw this.#asCallFailure(error);
    }
    const parsed = parseMessageHeader(header);
    if (typeof parsed === "string") this.#endMisframed(parsed);
    const { root, frameCount } = parsed;

    const frames: Uint8Array[] = [];
    for (let index = 0; index < frameCount; index += 1) {
      let frame: Uint8Array;
      try {
        frame = await receiveWithin(
          lane,
          remaining(),
          `application frame ${String(index)}`,
          this.#timers,
        );
      } catch (error) {
        if (this.#sessionEnded !== null) throw this.#sessionEnded;
        if (!(error instanceof PrototypeRunTimeoutError))
          throw this.#asCallFailure(error);
        const ended = new PrototypeSessionEndedError(
          "receive-deadline",
          `recvMessage's ${String(timeoutMs)}ms passed with ${String(index + 1)} ` +
            `of the message's ${String(frameCount + 1)} frames taken; the rest ` +
            "cannot be framed, and the session was ended",
          { cause: error },
        );
        this.#endSession(ended);
        throw ended;
      }
      const violation = chunkFrameViolation(frame, frames[0], index);
      if (violation !== null) this.#endMisframed(violation);
      frames.push(frame);
    }

    const message: EncryptedSessionMessage = {
      protocolVersion: 4,
      root,
      frames,
    };
    let plaintext: Uint8Array;
    try {
      plaintext = await established.session.decrypt(message);
    } catch (error) {
      throw this.#asCallFailure(error);
    }
    this.#emit(
      "message-verified",
      `${String(plaintext.length)} bytes from ${String(frameCount)} frames`,
    );
    return plaintext;
  }

  auditSecrets(): PrototypeRunAudit {
    const audit = this.driver.auditSecrets();
    return {
      capabilityHex: audit.capabilityHex,
      roomContextIdHex: audit.roomContextIdHex,
      stableKeyHex: audit.stableKeyHex,
      sdpLocalUtf8: audit.sdpLocal,
      sdpRemoteUtf8: audit.sdpRemote,
    };
  }

  storeTopology(): StoreTopology {
    return this.runtime.storeTopology;
  }

  faults(): readonly StoreFaultRecord[] {
    return this.runtime.faults;
  }

  /**
   * Idempotent teardown of the session, the WebRTC provider and the schedule;
   * every call returns the same promise.
   *
   * At once: the carrier schedule is disarmed, so nothing further is
   * published to any store; the session is destroyed; pending receives and
   * phase waits reject; new sends are refused. It emits `run-stopped` then, so
   * an observer can tell an endpoint that went quiet from one that is merely
   * between windows.
   *
   * Then, gracefully: frames already queued on the data channel are given
   * `PROTOTYPE_STOP_DRAIN_TIMEOUT_MS` to leave its send buffer, because closing
   * the peer connection over them would lose what a caller was told was sent.
   * The channel and the peer connection close when the buffer is empty, or
   * when the time is up; the latter resolves `"undrained"` and emits
   * `stop-undrained`. A failed session does not come through here: it ends
   * the session at once (`#endSession`).
   *
   * The driver's own secrets are deliberately NOT wiped here: `auditSecrets`
   * is the harness's proof obligation and has to stay answerable after a run
   * has been stopped. Call `driver.destroy()` once the audit is done.
   *
   * `detail` is the internal teardown reason (a presence that could not be
   * published); a caller stopping its own run leaves it out.
   */
  stop(detail?: string): Promise<PrototypeStopOutcome> {
    if (this.#stopping !== null) return this.#stopping;
    // Published before anything below runs: an observer that calls stop()
    // from one of the events this teardown emits gets this same promise, not
    // a second teardown.
    let settle!: (outcome: PrototypeStopOutcome) => void;
    const stopping = new Promise<PrototypeStopOutcome>((resolve) => {
      settle = resolve;
    });
    this.#stopping = stopping;
    this.#stopped = true;

    const session = this.#session;
    if (session !== null) void session.destroy().catch(() => undefined);
    this.runtime.stop();
    // Receiving and new sends end now; what is already queued may still leave.
    const leaving = this.#appTransport?.closeAfterSending() ?? null;

    const stopped = new PrototypeRunError("the run was stopped");
    // A no-op once the gate has settled, which is the point: stopping after a
    // session exists must not retract it.
    this.#closeGate?.(stopped);
    const waiters = this.#phaseWaiters.splice(0);
    for (const waiter of waiters) waiter.reject(stopped);
    this.#emit("run-stopped", detail);

    void this.#closeWhenSent(leaving).then(settle, () => settle("undrained"));
    return stopping;
  }

  /** The graceful half of `stop()`; synchronous when nothing is to drain. */
  async #closeWhenSent(
    leaving: Promise<void> | null,
  ): Promise<PrototypeStopOutcome> {
    let outcome: PrototypeStopOutcome = "drained";
    if (this.#sessionLeftFrames) {
      // There is no session to drain any more, but the one that ended took
      // frames with it that callers had been told were sent.
      outcome = "undrained";
      this.#emit(
        "stop-undrained",
        "the session had ended with frames still in the send buffer",
      );
    }
    if (leaving !== null) {
      try {
        await withTimeout(
          leaving,
          PROTOTYPE_STOP_DRAIN_TIMEOUT_MS,
          "the send buffer's drain at stop",
          this.#timers,
        );
      } catch (error) {
        void leaving.catch(() => undefined);
        outcome = "undrained";
        this.#emit("stop-undrained", detailOf(error));
      }
    }
    // A local abort of whatever is left, then the peer connection.
    this.#appTransport?.close();
    this.#transport.close();
    return outcome;
  }

  #dropWaiter(waiter: PhaseWaiter): void {
    const index = this.#phaseWaiters.indexOf(waiter);
    if (index >= 0) this.#phaseWaiters.splice(index, 1);
  }

  #requireSession(): Promise<EstablishedSession> {
    return this.#sessionGate;
  }

  /** A call on a session this endpoint ended, or on a stopped run, fails here. */
  #assertLive(): void {
    if (this.#sessionEnded !== null) throw this.#sessionEnded;
    if (this.#stopped) fail("the run was stopped");
  }

  /**
   * What a call reports for a failure it met: once a call has ended the
   * session, every other call's failure — a transport this endpoint aborted, a
   * destroyed session — stands for that, and reports the error that ended it.
   */
  #asCallFailure(error: unknown): unknown {
    if (this.#sessionEnded !== null) return this.#sessionEnded;
    if (this.#stopped)
      return new PrototypeRunError("the run was stopped", { cause: error });
    return error;
  }

  /**
   * A received header or frame that does not parse at its place: the lane is
   * out of step, so the session ends, as the provider ends its transport on a
   * frame that breaks its own framing.
   */
  #endMisframed(detail: string): never {
    if (this.#sessionEnded !== null) throw this.#sessionEnded;
    const ended = new PrototypeSessionEndedError(
      "protocol",
      `recvMessage: ${detail}; the app lane cannot be framed past it, and the session was ended`,
    );
    this.#endSession(ended);
    throw ended;
  }

  #startSession(): void {
    if (this.#sessionPromise !== null) return;
    const handoff = this.driver.handoff;
    if (handoff === null) {
      const missing = new PrototypeRunError(
        "the driver reported handoff without handoff facts",
      );
      this.#sessionPromise = Promise.reject(missing);
      void this.#sessionPromise.catch(() => undefined);
      this.#endSession(missing);
      return;
    }
    const started = this.#establishSession(handoff);
    // The gate adopts it, so everything already waiting to speak resolves with
    // this session; the `catch` reports the failure once and marks the
    // rejection handled, so it is one event rather than an unhandled rejection
    // too.
    this.#sessionPromise = started;
    this.#openGate?.(started);
    void started.catch((error: unknown) => {
      this.#endSession(error);
    });
  }

  /**
   * A handoff that did not become a session: report it, and take down what
   * belonged to that session and nothing else.
   *
   * This prototype's driver does not retry a dead edge, so the peer connection
   * and any half-built session go. The carrier schedule stays: both ends of a
   * pair reach their handoff together, and a schedule that stopped with the
   * session would put both of them silent at an instant their handshake chose
   * — an instant a store can join across its log. The schedule's lifetime is
   * the run's, which the caller ends with `stop()`.
   */
  #endSession(error: unknown): void {
    if (error instanceof PrototypeSessionEndedError)
      this.#sessionEnded ??= error;
    this.#emit("session-failed", detailOf(error));
    // Already settled when the gate adopted a failed establishment; settles
    // it for a handoff that never got that far.
    this.#closeGate?.(
      error instanceof Error ? error : new PrototypeRunError(detailOf(error)),
    );
    const session = this.#session;
    this.#session = null;
    if (session !== null) void session.destroy().catch(() => undefined);
    const appTransport = this.#appTransport;
    appTransport?.close();
    if (appTransport?.hasUnsentFrames() === true)
      this.#sessionLeftFrames = true;
    this.#appTransport = null;
    this.#transport.close();
  }

  async #establishSession(handoff: HandoffFacts): Promise<EstablishedSession> {
    const provider = this.#transport.provider;
    if (provider === null)
      fail("the driver reached handoff without ever opening a WebRTC provider");

    const channel = await withTimeout(
      provider.channel(),
      CHANNEL_TIMEOUT_MS,
      "bootstrap data channel",
      this.#timers,
    );
    await waitChannelOpen(channel, CHANNEL_TIMEOUT_MS, this.#timers);
    await waitConnected(
      provider.peerConnection,
      CONNECTED_TIMEOUT_MS,
      this.#timers,
    );
    this.#emit("webrtc-connected", provider.role);

    // The tripwire runs before the handshake, and a throw here ends the
    // session: `#startSession` hands any rejection from this method to
    // `#endSession`, which closes the peer connection. The fingerprints below
    // are the ones the pair transcript signed, so a live certificate that
    // disagrees means the SDP was rewritten after both peers authenticated it.
    // The provider already buffers bounded raw input, since a faster peer may
    // send its HELLO while getStats() is pending. Session processing still
    // begins only after this verdict; a mismatch discards the buffered input.
    const verdict = await provider.verifyCertificates(
      handoff.localFingerprint,
      handoff.remoteFingerprint,
    );
    if (this.#stopped) fail("the run stopped during certificate verification");
    this.#emit(verdict === "verified" ? "dtls-verified" : "dtls-unsupported");

    const transport = dataChannelTransport(channel);
    this.#appTransport = transport;
    const handshake = createSession({
      transport,
      role: handoff.sessionRole,
      identity: this.#identity,
      peerIdentityEd25519PublicKey: handoff.peerStableEd25519PublicKey,
      channel: {
        channelId: handoff.rendezvousChannelId,
        localFingerprint: handoff.localFingerprint,
        remoteFingerprint: handoff.remoteFingerprint,
      },
      pqMode: this.#pqMode,
      mode: "nopin",
      crypto: { wasmBinary: this.#wasmBinary },
    });
    // A peer that stops answering mid-handshake would otherwise hold this
    // await, and every caller waiting on the session gate, forever. At the
    // deadline `#endSession` closes the transport, which unblocks the
    // handshake's pending receive; one that completes anyway after its
    // deadline is destroyed rather than kept.
    let session: P2PartySession;
    try {
      session = await withTimeout(
        handshake,
        this.#handshakeTimeoutMs,
        "session handshake",
        this.#timers,
      );
    } catch (error) {
      void handshake.then(
        (late) => late.destroy().catch(() => undefined),
        () => undefined,
      );
      throw error;
    }
    // stop() closes pending receives, but a handshake that already consumed
    // its last frame can finish async cryptography afterwards. It must never
    // publish an authenticated session or retain its keys after teardown.
    if (this.#stopped) {
      await session.destroy();
      fail("the run stopped during session authentication");
    }
    this.#session = session;
    this.#emit("session-authenticated", handoff.sessionRole);
    return { session, transport };
  }
}

/* ------------------------------------------------------------------ *
 * Assembly
 * ------------------------------------------------------------------ */

const loadModule = async (wasmBinary: ArrayBuffer): Promise<LibCrypto> =>
  (await libcrypto({
    // A copy: the session API instantiates its own modules from the same
    // buffer afterwards, and an engine that detached this one would take
    // those with it.
    wasmBinary: wasmBinary.slice(0),
    wasmMemory: new WebAssembly.Memory({
      initial: WASM_PAGES,
      maximum: WASM_PAGES,
    }),
  })) as unknown as LibCrypto;

/**
 * Connect every store origin. A store that cannot be reached, whose descriptor
 * does not validate, or which serves another delivery profile is skipped: the
 * whole point of two stores is that one of them may be missing.
 */
const connectStores = async (
  options: PrototypeRunOptions,
  profile: DeliveryProfileV1,
  profileHash: Uint8Array,
  module: LibCrypto,
  emit: (kind: string, detail?: string) => void,
): Promise<readonly PrototypeStoreClient[]> => {
  const connected: PrototypeStoreClient[] = [];
  for (const origin of options.storeOrigins) {
    try {
      const client = await PrototypeStoreClient.connect({
        origin,
        profile,
        profileHash,
        module,
        nowMs: () => BigInt(Date.now()),
        admissionTokens: options.admissionTokens,
      });
      connected.push(client);
      emit("store-connected", `${origin} storeId=${client.storeIdHex}`);
    } catch (error) {
      emit("store-unreachable", `${origin}: ${detailOf(error)}`);
    }
  }
  if (connected.length === 0) fail("no usable store");
  return connected;
};

/**
 * Compose one endpoint of the two-store rendezvous and start it.
 *
 * The returned run is live: its schedule is armed, its PRESENCE is published,
 * and it will proceed to a WebRTC session on its own as soon as it observes a
 * peer holding the same capability. The caller only waits and then speaks.
 */
export const runBlindRendezvousPrototype = async (
  options: PrototypeRunOptions,
): Promise<PrototypeRun> => {
  const emit = (kind: string, detail?: string): void => {
    // A caller's observer must not be able to break the rendezvous.
    try {
      options.onEvent({ atMs: Date.now(), kind, detail });
    } catch {
      /* Observation is best effort. */
    }
  };

  const profile =
    options.deliveryWindowMs === undefined
      ? PROTOTYPE_DELIVERY_PROFILE_V0
      : withDeliveryWindowMs(
          PROTOTYPE_DELIVERY_PROFILE_V0,
          options.deliveryWindowMs,
        );
  const profileHash = await deliveryProfileHash(profile);

  const module = await loadModule(options.wasmBinary);
  const identity = await generateSessionIdentity({
    wasmBinary: options.wasmBinary,
  });
  const stores = await connectStores(
    options,
    profile,
    profileHash,
    module,
    emit,
  );

  const transport = new LazyWebRtcTransport(options.rtcConfig, (role) => {
    emit("webrtc-role", role);
  });

  return assembleRun({
    module,
    capability: options.capability,
    identity,
    stores,
    profile,
    profileHash,
    transport,
    wasmBinary: options.wasmBinary,
    handshakeTimeoutMs: CONNECTED_TIMEOUT_MS,
    clock: { nowMs: () => BigInt(Date.now()) },
    // Wrapped, not the bare globals: a WebIDL operation called as a method of
    // anything but `window` throws "Illegal invocation" in Chromium. The cast
    // is on the opaque handle the runtime hands back, never on the runtime.
    timers: {
      setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
      clearTimeout: (handle) =>
        clearTimeout(handle as ReturnType<typeof setTimeout>),
    },
    emit,
  });
};

/**
 * Everything `assembleRun` wires together. A page never builds one: it is
 * what `runBlindRendezvousPrototype` has once the module, the identity and
 * the stores are in hand, and what a test supplies with its own clock.
 *
 * @internal
 */
export interface RunAssembly {
  readonly module: LibCrypto;
  readonly capability: Uint8Array;
  readonly identity: GeneratedSessionIdentity;
  readonly stores: readonly PrototypeStoreClient[];
  readonly profile: DeliveryProfileV1;
  readonly profileHash: Uint8Array;
  /** Both what the driver negotiates through and what the run tears down. */
  readonly transport: TransportCandidateProvider & RunTransport;
  readonly wasmBinary: ArrayBuffer;
  readonly handshakeTimeoutMs: number;
  readonly clock: { nowMs(): bigint };
  readonly timers: CarrierTimers;
  readonly emit: (kind: string, detail?: string) => void;
}

/**
 * Wire one driver to one carrier runtime and start both: the presence first,
 * then the schedule.
 *
 * @internal
 */
export const assembleRun = async (
  assembly: RunAssembly,
): Promise<BlindRendezvousRun> => {
  const { identity, emit } = assembly;
  let runtime: CarrierRuntime | null = null;
  let run: BlindRendezvousRun | null = null;

  const driver = new PairDriver({
    module: assembly.module,
    capability: assembly.capability,
    // The driver signs with the stable Ed25519 identity and proves the X25519
    // binding with its cross-signature; the X25519 SECRET belongs to the
    // protocol-v4 3DH alone and is never handed to the rendezvous layer.
    identity: {
      ed25519PublicKey: identity.ed25519PublicKey,
      ed25519SecretKey: identity.ed25519SecretKey,
      x25519PublicKey: identity.x25519PublicKey,
      x25519CrossSignature: identity.x25519CrossSignature,
    },
    publish: (operation, workKind) => {
      if (runtime === null) fail("the carrier runtime is not built yet");
      runtime.publish(operation, workKind);
    },
    transport: assembly.transport,
    clock: assembly.clock,
    random: (length) => crypto.getRandomValues(new Uint8Array(length)),
    onPhase: (phase, detail) => run?.handlePhase(phase, detail),
  });

  /*
   * The driver derives RoomContextId and RoomRoot lazily, on its first awaited
   * call, and the runtime below needs RoomRoot at construction. An empty
   * ingest is that first call: it initializes the room identity and returns
   * without reducing, publishing or observing anything.
   */
  await driver.ingest([]);

  let lastTopology: StoreTopology | null = null;
  runtime = new CarrierRuntime({
    module: assembly.module,
    roomRoot: driver.roomRoot,
    profile: assembly.profile,
    profileHash: assembly.profileHash,
    stores: assembly.stores,
    validationContextAt: (referenceLogicalWindow) =>
      driver.validationContextAt(referenceLogicalWindow),
    logicalWindowMs: driver.roomPolicy.protocolLimits.logicalWindowMs,
    clock: assembly.clock,
    timers: assembly.timers,
    // The runtime calls this one batch at a time and never awaits it from a
    // scheduled event, which is what keeps the non-reentrant `ingest` from
    // overlapping itself when an ICE wait outlives a delivery window.
    onOperations: (fresh) => driver.ingest(fresh),
    onEvent: (event) => {
      const where = event.storeIdHex ?? "runtime";
      const detail = `${where} w${String(event.window)}${
        event.detail === undefined ? "" : `: ${event.detail}`
      }${event.count === undefined ? "" : ` (${String(event.count)})`}`;
      if (event.kind === "fault") emit("store-fault", detail);
      else if (event.kind === "missed") emit("store-missed", detail);
      if (runtime === null) return;
      const topology = runtime.storeTopology;
      if (topology !== lastTopology) {
        lastTopology = topology;
        emit("topology", topology);
      }
    },
  });

  run = new BlindRendezvousRun({
    driver,
    runtime,
    transport: assembly.transport,
    identity,
    pqMode: decodeRoomPolicyV1(driver.roomPolicy.sessionPolicyV1).pqMode,
    wasmBinary: assembly.wasmBinary,
    handshakeTimeoutMs: assembly.handshakeTimeoutMs,
    clock: assembly.clock,
    timers: assembly.timers,
    emit,
  });

  // The presence first, the schedule after. `start()` and `ingest()` must not
  // overlap, and the runtime's first read can deliver operations before a
  // presence still being built would be ready for them; publishing only
  // queues, so nothing leaves before the schedule's own slot either way.
  try {
    await driver.start();
  } catch (error) {
    // A caller that never got a run cannot stop one, so the half-built one is
    // stopped here and its schedule is never armed.
    // No session exists yet, so this stop has nothing to drain.
    void run.stop(
      `the local presence could not be published: ${detailOf(error)}`,
    );
    throw error;
  }
  runtime.start();
  return run;
};
