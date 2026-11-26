/**
 * Real WebRTC transport for the flagged two-store rendezvous prototype.
 *
 * This is the piece that turns the pair driver's abstract offer/answer exchange
 * (`TransportCandidateProvider`, `pairDriver.ts`) into an actual
 * `RTCPeerConnection` carrying one bootstrap `RTCDataChannel`, and then hands
 * that channel to the store-free protocol-v4 session API as a
 * `HandshakeTransport`.
 *
 * BROWSER ONLY. Nothing here may import the Redux store, `src/api/**`,
 * `src/reducers/**` or anything under `prototype/store/`: the prototype's
 * browser bundle is built from this module and must stay free of the app's
 * state machinery. `verifyCertificates` therefore *copies* the certificate
 * comparison of `src/handlers/handleHandshake.ts` (`verifyDtlsFingerprints`)
 * rather than importing it — that function reaches the store through its
 * `IRTCPeerConnection` wrappers. The only import in this file is a type, which
 * `verbatimModuleSyntax` erases entirely at build time.
 *
 * Three properties of this file are load-bearing, and each one has cost a
 * debugging session before:
 *
 *   1. THE INITIATOR CREATES ITS DATA CHANNEL BEFORE THE OFFER. An SDP offer
 *      produced by a peer connection with no data channel negotiates no SCTP
 *      transport at all, so no channel can ever open afterwards — the peers
 *      connect at ICE/DTLS level and then sit there forever. The channel is
 *      therefore created in the constructor, before `createOffer()` can be
 *      called (see `docs/e2e/README.md`).
 *   2. COMPLETE GATHERING, NEVER TRICKLE. The blind profile carries one SDP
 *      blob inside a pair-encrypted, class-padded operation; there is no
 *      channel to trickle candidates over afterwards. Both `createOffer` and
 *      `acceptOffer` therefore wait for `iceGatheringState === "complete"`
 *      before reading the local description.
 *   3. EXACT BYTES. The SDP bytes returned here are what the peer signs over
 *      inside the pair transcript, and the DTLS fingerprint parsed out of them
 *      is bound into the protocol-v4 channel input. They are the UTF-8 encoding
 *      of `localDescription.sdp` verbatim — never re-serialized, never
 *      normalized — and remote SDP is decoded with a fatal UTF-8 decoder and
 *      handed to `setRemoteDescription` as-is.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte.
 */

import type { TransportCandidateProvider } from "./pairDriver";
import type { HandshakeTransport } from "../../session";

/** Label of the bootstrap channel that must exist before the first offer. */
const BOOTSTRAP_CHANNEL_LABEL = "p2party-blind";

/**
 * Complete-gathering deadline. Loopback host candidates land in milliseconds;
 * a STUN-configured connection behind a slow resolver can take seconds. 15 s is
 * long enough that a real network is never cut short and short enough that a
 * misconfigured `rtcConfig` fails visibly instead of hanging the rendezvous.
 */
const DEFAULT_GATHERING_TIMEOUT_MS = 15_000;

/** Lane tags of the one-byte framing on the single bootstrap channel. */
const TAG_CONTROL = 0;
const TAG_APP = 1;

const SHA256_FINGERPRINT_BYTES = 32;

// A remote endpoint may speak before local certificate verification or session
// startup completes. Retain that traffic, but cap both bytes and tiny frames.
const MAX_QUEUED_BYTES = 16 * 1024 * 1024;
const MAX_QUEUED_FRAMES = 1024;
const channelTransports = new WeakMap<RTCDataChannel, DataChannelTransport>();

const utf8Encoder = new TextEncoder();
/** Fatal: silently substituting U+FFFD would change the bytes the peer signed. */
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

/** Every failure raised by this module, so callers can tell it apart. */
export class WebRtcProviderError extends Error {
  constructor(message: string) {
    super(`webrtcProvider: ${message}`);
    this.name = "WebRtcProviderError";
  }
}

export interface WebRtcProviderOptions {
  readonly rtcConfig: RTCConfiguration;
  readonly role: "initiator" | "responder";
  /** Complete-ICE-gathering deadline; defaults to 15,000 ms. */
  readonly gatheringTimeoutMs?: number;
}

/**
 * Shape of the entries `RTCStatsReport.forEach` hands back that this file
 * reads. `RTCStatsReport`'s DOM typing declares its `forEach` value as `any`
 * (there is no per-type stats union in `lib.dom.d.ts`), so this local interface
 * is what keeps `verifyCertificates` free of `any`.
 */
interface RTCStatEntry {
  type: string;
  id?: string;
  localCertificateId?: string;
  remoteCertificateId?: string;
  fingerprint?: string;
  fingerprintAlgorithm?: string;
}

const toHex = (bytes: Uint8Array): string => {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
};

const normalizeFingerprintHex = (fingerprint: string): string =>
  fingerprint.replace(/:/g, "").toLowerCase();

const expectedFingerprintHex = (
  fingerprint: Uint8Array,
  label: string,
): string => {
  if (!(fingerprint instanceof Uint8Array))
    throw new WebRtcProviderError(`${label} must be a Uint8Array`);
  if (fingerprint.length !== SHA256_FINGERPRINT_BYTES)
    throw new WebRtcProviderError(
      `${label} must be ${SHA256_FINGERPRINT_BYTES} bytes, got ${fingerprint.length}`,
    );
  return toHex(fingerprint);
};

const decodeSdp = (bytes: Uint8Array, label: string): string => {
  if (!(bytes instanceof Uint8Array))
    throw new WebRtcProviderError(`remote ${label} SDP must be a Uint8Array`);
  if (bytes.length === 0)
    throw new WebRtcProviderError(`remote ${label} SDP is empty`);
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    throw new WebRtcProviderError(`remote ${label} SDP is not valid UTF-8`);
  }
};

/**
 * One `RTCPeerConnection` plus its bootstrap data channel, driven by the pair
 * driver's complete-ICE offer/answer contract.
 */
export class WebRtcCandidateProvider implements TransportCandidateProvider {
  readonly peerConnection: RTCPeerConnection;
  readonly role: "initiator" | "responder";

  readonly #gatheringTimeoutMs: number;
  readonly #channelWaiters: Array<{
    resolve: (channel: RTCDataChannel) => void;
    reject: (error: Error) => void;
  }> = [];
  /** Aborts armed by in-flight gathering waits, so `close()` unblocks them. */
  readonly #gatheringAborts = new Set<() => void>();

  #channel: RTCDataChannel | null = null;
  #closed = false;
  #offerCreated = false;
  #offerAccepted = false;
  #answerAccepted = false;

  constructor(options: WebRtcProviderOptions) {
    if (!options || typeof options !== "object")
      throw new WebRtcProviderError("options are required");
    if (options.role !== "initiator" && options.role !== "responder")
      throw new WebRtcProviderError('role must be "initiator" or "responder"');
    const gatheringTimeoutMs =
      options.gatheringTimeoutMs ?? DEFAULT_GATHERING_TIMEOUT_MS;
    if (!Number.isFinite(gatheringTimeoutMs) || gatheringTimeoutMs <= 0)
      throw new WebRtcProviderError(
        "gatheringTimeoutMs must be a positive finite number of milliseconds",
      );

    this.role = options.role;
    this.#gatheringTimeoutMs = gatheringTimeoutMs;
    this.peerConnection = new RTCPeerConnection(options.rtcConfig);

    if (options.role === "initiator") {
      // MUST happen before createOffer(): an offer generated with no data
      // channel negotiates no SCTP transport, and then no channel can ever
      // open on this connection.
      const channel = this.peerConnection.createDataChannel(
        BOOTSTRAP_CHANNEL_LABEL,
        { ordered: true },
      );
      this.#adopt(channel);
    } else {
      this.peerConnection.ondatachannel = (event: RTCDataChannelEvent) => {
        // First channel wins: the pair exchange negotiates exactly one edge,
        // and a second inbound channel would race the first for the handshake.
        if (this.#channel || this.#closed) {
          event.channel.close();
          return;
        }
        this.#adopt(event.channel);
      };
    }
  }

  #adopt(channel: RTCDataChannel): void {
    channel.binaryType = "arraybuffer";
    // Capture messages immediately. The peer can finish getStats() and send
    // its HELLO before this endpoint has even entered certificate verification.
    // Buffering bytes does not authenticate them or start a session.
    dataChannelTransport(channel);
    this.#channel = channel;
    const waiters = this.#channelWaiters.splice(0);
    for (const waiter of waiters) waiter.resolve(channel);
  }

  #assertOpen(): void {
    if (this.#closed) throw new WebRtcProviderError("provider is closed");
  }

  /**
   * The one bootstrap data channel of this edge: for the initiator the channel
   * it created in the constructor (resolved immediately, before it opens); for
   * the responder the channel `ondatachannel` delivers. Rejects if the provider
   * is closed. The caller waits for `readyState`.
   */
  channel(): Promise<RTCDataChannel> {
    if (this.#closed)
      return Promise.reject(new WebRtcProviderError("provider is closed"));
    if (this.#channel) return Promise.resolve(this.#channel);
    return new Promise<RTCDataChannel>((resolve, reject) => {
      this.#channelWaiters.push({ resolve, reject });
    });
  }

  /** Complete-ICE offer, bootstrap data channel already created. */
  async createOffer(): Promise<Uint8Array> {
    this.#assertOpen();
    if (this.role !== "initiator")
      throw new WebRtcProviderError("only the initiator may create an offer");
    if (this.#offerCreated)
      throw new WebRtcProviderError("createOffer() may only be called once");
    if (!this.#channel)
      throw new WebRtcProviderError(
        "the bootstrap data channel must exist before the offer",
      );
    this.#offerCreated = true;

    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);
    await this.#awaitCompleteGathering();
    return this.#localSdpBytes("offer");
  }

  /** Set the remote offer and return the complete-ICE answer. */
  async acceptOffer(remoteSdp: Uint8Array): Promise<Uint8Array> {
    this.#assertOpen();
    if (this.role !== "responder")
      throw new WebRtcProviderError("only the responder may accept an offer");
    if (this.#offerAccepted)
      throw new WebRtcProviderError("acceptOffer() may only be called once");
    const sdp = decodeSdp(remoteSdp, "offer");
    this.#offerAccepted = true;

    await this.peerConnection.setRemoteDescription({ type: "offer", sdp });
    const answer = await this.peerConnection.createAnswer();
    await this.peerConnection.setLocalDescription(answer);
    await this.#awaitCompleteGathering();
    return this.#localSdpBytes("answer");
  }

  /** Set the remote answer; completes the initiator's negotiation. */
  async acceptAnswer(remoteSdp: Uint8Array): Promise<void> {
    this.#assertOpen();
    if (this.role !== "initiator")
      throw new WebRtcProviderError("only the initiator may accept an answer");
    if (this.#answerAccepted)
      throw new WebRtcProviderError("acceptAnswer() may only be called once");
    const sdp = decodeSdp(remoteSdp, "answer");
    this.#answerAccepted = true;

    await this.peerConnection.setRemoteDescription({ type: "answer", sdp });
  }

  /**
   * Post-connect DTLS binding check, copied in substance from
   * `handleHandshake.ts`'s `verifyDtlsFingerprints`: the fingerprints the two
   * SDP blobs declared (and that the handshake transcript is bound to) must
   * equal the live certificates `getStats()` reports. A disagreement means the
   * DTLS transport terminates on a different certificate than the one that was
   * authenticated — i.e. someone rewrote SDP after the transcript was bound —
   * so it throws.
   *
   * Returns `"unsupported"` (not a failure) when the engine reports neither a
   * `transport` stat nor any `certificate` rows: that is Firefox, which
   * implements neither, and treating it as a mismatch would make every
   * rendezvous fail there. What survives without the check is what the
   * transcript already binds — both SDP fingerprints — so an attacker who
   * rewrites SDP still produces a transcript both peers reject. Where the
   * engine can answer, a disagreement stays fatal, and so does a certificate
   * that cannot be located at all: a tripwire that cannot confirm must abort.
   */
  async verifyCertificates(
    localFingerprint: Uint8Array,
    remoteFingerprint: Uint8Array,
  ): Promise<"verified" | "unsupported"> {
    // getStats() on a closed connection rejects with a DOMException; failing
    // here keeps every error out of this module shaped like this module's.
    this.#assertOpen();
    const expectedLocal = expectedFingerprintHex(
      localFingerprint,
      "localFingerprint",
    );
    const expectedRemote = expectedFingerprintHex(
      remoteFingerprint,
      "remoteFingerprint",
    );

    const stats = await this.peerConnection.getStats();

    // RTCStatsReport only exposes forEach (no `.get` in the DOM typings), and
    // per the webrtc-stats spec the Map key IS each report's own id — report.id
    // itself is not guaranteed to be echoed back on every implementation — so
    // matching is done against the forEach key, falling back to report.id.
    let localCertificateId: string | undefined;
    let remoteCertificateId: string | undefined;
    let reportsCertificates = false;
    stats.forEach((report: RTCStatEntry) => {
      if (report.type === "transport") {
        localCertificateId = report.localCertificateId ?? localCertificateId;
        remoteCertificateId = report.remoteCertificateId ?? remoteCertificateId;
      }
      if (report.type === "certificate") reportsCertificates = true;
    });

    if (!reportsCertificates && localCertificateId === undefined)
      return "unsupported";

    const liveFingerprint = (id: string | undefined): string | null => {
      if (!id) return null;
      let found: string | null = null;
      stats.forEach((report: RTCStatEntry, key: string) => {
        if (
          report.type === "certificate" &&
          (key === id || report.id === id) &&
          report.fingerprint &&
          // A certificate row that declares another digest cannot be compared
          // against a SHA-256 SDP fingerprint; skipping it fails closed below.
          (report.fingerprintAlgorithm === undefined ||
            report.fingerprintAlgorithm.toLowerCase() === "sha-256")
        )
          found = normalizeFingerprintHex(report.fingerprint);
      });
      return found;
    };

    const liveLocal = liveFingerprint(localCertificateId);
    const liveRemote = liveFingerprint(remoteCertificateId);

    if (liveLocal === null || liveLocal !== expectedLocal)
      throw new WebRtcProviderError(
        "DTLS fingerprint mismatch: the local certificate was not found in the " +
          "stats report or does not match the local SDP fingerprint",
      );
    if (liveRemote === null || liveRemote !== expectedRemote)
      throw new WebRtcProviderError(
        "DTLS fingerprint mismatch: the remote certificate was not found in the " +
          "stats report or does not match the remote SDP fingerprint (possible MITM)",
      );
    return "verified";
  }

  /** Idempotent teardown: unblocks every waiter, then closes channel and pc. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;

    const aborts = [...this.#gatheringAborts];
    this.#gatheringAborts.clear();
    for (const abort of aborts) abort();

    const waiters = this.#channelWaiters.splice(0);
    for (const waiter of waiters)
      waiter.reject(
        new WebRtcProviderError(
          "provider closed before a data channel arrived",
        ),
      );

    // RTCDataChannel.close() may deliver its close event later. Reject pending
    // receives and discard buffered pre-verification bytes synchronously.
    if (this.#channel) dataChannelTransport(this.#channel).close();
    this.peerConnection.ondatachannel = null;
    this.peerConnection.close();
  }

  #localSdpBytes(label: string): Uint8Array {
    const sdp = this.peerConnection.localDescription?.sdp;
    if (!sdp)
      throw new WebRtcProviderError(
        `no local ${label} SDP after ICE gathering completed`,
      );
    // Exactly what the peer signs over: the description's own UTF-8 bytes.
    return utf8Encoder.encode(sdp);
  }

  /**
   * Resolve once this connection has gathered every candidate it will gather.
   * `icegatheringstatechange` can fire between the synchronous state read and
   * the listener registration, so the state is re-checked once immediately
   * after subscribing rather than only on the next event.
   */
  #awaitCompleteGathering(): Promise<void> {
    const pc = this.peerConnection;
    if (pc.iceGatheringState === "complete") return Promise.resolve();

    return new Promise<void>((resolve, reject) => {
      let settled = false;

      // `settle` closes over `timer`, `onStateChange` and `abort`, all declared
      // below: nothing can call it before the executor finishes initializing
      // them (the listener, the timer and `close()` all run later).
      const settle = (error?: WebRtcProviderError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        pc.removeEventListener("icegatheringstatechange", onStateChange);
        this.#gatheringAborts.delete(abort);
        if (error) reject(error);
        else resolve();
      };
      const onStateChange = (): void => {
        if (pc.iceGatheringState === "complete") settle();
      };
      const abort = (): void =>
        settle(new WebRtcProviderError("provider closed while gathering ICE"));

      const timer = setTimeout(
        () =>
          settle(
            new WebRtcProviderError(
              `ICE gathering did not complete within ${this.#gatheringTimeoutMs}ms`,
            ),
          ),
        this.#gatheringTimeoutMs,
      );
      this.#gatheringAborts.add(abort);
      pc.addEventListener("icegatheringstatechange", onStateChange);
      onStateChange();
    });
  }
}

/**
 * The two logical streams a rendezvous edge carries over its one data channel:
 * the protocol-v4 handshake / sparse-PQ control lane (`send` / `recv`, the
 * `HandshakeTransport` the session API consumes) and the application lane
 * (`sendApp` / `recvApp`) that carries encrypted chunk frames.
 */
export interface DataChannelTransport extends HandshakeTransport {
  sendApp(bytes: Uint8Array): void;
  recvApp(): Promise<Uint8Array>;
  /** Rejects every pending receive and closes the underlying channel. */
  close(): void;
}

interface Lane {
  queue: Uint8Array[];
  waiters: Array<{
    resolve: (bytes: Uint8Array) => void;
    reject: (error: Error) => void;
  }>;
}

/**
 * Frame the two lanes over one `RTCDataChannel` as `[tag(1)][payload]`, the
 * same framing `docs/e2e/webrtc-e2e/entry.ts` proved against real Chromium.
 *
 * Anything that arrives with no waiter is queued, and waiters are served FIFO.
 * A close — of the channel, or through this transport's own `close()` — rejects
 * every pending receive with a `WebRtcProviderError` instead of leaving it
 * pending. Failure discards queued bytes, so shutdown cannot later continue a
 * handshake from stale input. The combined queues are capped at 16 MiB and
 * 1,024 frames. A peer exceeding either budget closes the channel.
 *
 * A channel has exactly one transport. The provider installs it at channel
 * adoption; later callers receive that same transport and its buffered bytes.
 */
export const dataChannelTransport = (
  channel: RTCDataChannel,
): DataChannelTransport => {
  const existing = channelTransports.get(channel);
  if (existing) return existing;
  channel.binaryType = "arraybuffer";

  const control: Lane = { queue: [], waiters: [] };
  const app: Lane = { queue: [], waiters: [] };
  let failure: WebRtcProviderError | null = null;
  let queuedBytes = 0;
  let queuedFrames = 0;

  const fail = (error: WebRtcProviderError): void => {
    if (failure) return;
    failure = error;
    channel.removeEventListener("message", onMessage);
    channel.removeEventListener("close", onClose);
    channel.removeEventListener("error", onError);
    for (const lane of [control, app]) {
      lane.queue.length = 0;
      const waiters = lane.waiters.splice(0);
      for (const waiter of waiters) waiter.reject(error);
    }
    queuedBytes = 0;
    queuedFrames = 0;
    if (channel.readyState !== "closed" && channel.readyState !== "closing")
      channel.close();
  };

  const deliver = (lane: Lane, payload: Uint8Array): void => {
    const waiter = lane.waiters.shift();
    if (waiter) waiter.resolve(payload);
    else {
      if (
        queuedBytes + payload.length > MAX_QUEUED_BYTES ||
        queuedFrames >= MAX_QUEUED_FRAMES
      ) {
        fail(
          new WebRtcProviderError("data channel receive queue budget exceeded"),
        );
        return;
      }
      lane.queue.push(payload);
      queuedBytes += payload.length;
      queuedFrames += 1;
    }
  };

  const onMessage = (event: MessageEvent): void => {
    if (!(event.data instanceof ArrayBuffer)) {
      fail(
        new WebRtcProviderError(
          "data channel delivered a non-binary frame; the lane framing is binary only",
        ),
      );
      return;
    }
    const bytes = new Uint8Array(event.data);
    if (bytes.length === 0) {
      fail(new WebRtcProviderError("data channel delivered an empty frame"));
      return;
    }
    if (bytes.length - 1 > MAX_QUEUED_BYTES) {
      fail(
        new WebRtcProviderError(
          "data channel frame exceeds the receive byte budget",
        ),
      );
      return;
    }
    const payload = bytes.slice(1);
    if (bytes[0] === TAG_CONTROL) deliver(control, payload);
    else if (bytes[0] === TAG_APP) deliver(app, payload);
    else
      fail(
        new WebRtcProviderError(
          `data channel frame carried unknown lane tag ${bytes[0]}`,
        ),
      );
  };

  const onClose = (): void => {
    fail(new WebRtcProviderError("data channel closed"));
  };
  const onError = (): void => {
    fail(new WebRtcProviderError("data channel errored"));
  };

  channel.addEventListener("message", onMessage);
  channel.addEventListener("close", onClose);
  channel.addEventListener("error", onError);
  if (channel.readyState === "closed" || channel.readyState === "closing")
    fail(new WebRtcProviderError("data channel already closed"));

  const sendTagged = (tag: number, bytes: Uint8Array): void => {
    if (failure) throw failure;
    if (channel.readyState !== "open")
      throw new WebRtcProviderError(
        `data channel is "${channel.readyState}", not "open"`,
      );
    const framed = new Uint8Array(1 + bytes.length);
    framed[0] = tag;
    framed.set(bytes, 1);
    channel.send(framed);
  };

  const receive = (lane: Lane): Promise<Uint8Array> => {
    const queued = lane.queue.shift();
    if (queued) {
      queuedBytes -= queued.length;
      queuedFrames -= 1;
      return Promise.resolve(queued);
    }
    if (failure) return Promise.reject(failure);
    return new Promise<Uint8Array>((resolve, reject) => {
      lane.waiters.push({ resolve, reject });
    });
  };

  const transport: DataChannelTransport = {
    send: (bytes: Uint8Array): void => sendTagged(TAG_CONTROL, bytes),
    recv: (): Promise<Uint8Array> => receive(control),
    sendApp: (bytes: Uint8Array): void => sendTagged(TAG_APP, bytes),
    recvApp: (): Promise<Uint8Array> => receive(app),
    close: (): void => {
      fail(new WebRtcProviderError("transport closed"));
    },
  };
  channelTransports.set(channel, transport);
  return transport;
};
