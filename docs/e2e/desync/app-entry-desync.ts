// Desync probe entry: the REAL p2party API (Redux + IndexedDB worker + WebRTC)
// plus a store-subscription timeline recorder and a full state dump used by
// desync-driver.mjs. Bundled with bun build (see driver header).
import {
  p2party,
  setWasmSourceUrl,
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
} from "~/Desktop/@p2party/p2party-js/src/index";
import { setChannel } from "~/Desktop/@p2party/p2party-js/src/reducers/roomSlice";
import { getDBPeerIsBlacklisted } from "~/Desktop/@p2party/p2party-js/src/db/api";
import {
  hasRoomPeerMutex,
  getRoomPeerMutex,
  roomPeerMutexCount,
} from "~/Desktop/@p2party/p2party-js/src/api/webrtc/negotiationLock";
import { unnegotiatedTransportRebuilds, MAX_UNNEGOTIATED_TRANSPORT_REBUILDS } from "~/Desktop/@p2party/p2party-js/src/api/webrtc/unnegotiatedTransport";
import type { RoomPolicyV1 } from "~/Desktop/@p2party/p2party-js/src/roomPolicy";

const LOOPBACK_RTC: RTCConfiguration = { iceServers: [], iceCandidatePoolSize: 2 };

declare global {
  interface Window {
    __app: typeof api;
    __timeline: Array<Record<string, unknown>>;
    __pcs: () => Array<Record<string, unknown>>;
    __pcEvents: () => Array<Record<string, unknown>>;
  }
}

const store = p2party.store;
p2party.setDebugLogging(true);
window.__timeline = [];
const t0 = Date.now();
const log = (entry: Record<string, unknown>): void => {
  window.__timeline.push({ t: Date.now() - t0, ...entry });
};

const roomIdFor = (roomUrlHex: string): string => {
  const st = store.getState();
  const room = st.rooms.find((r) => r.url === roomUrlHex);
  return room?.id ?? "";
};

/** Compact snapshot for the change timeline (short ids). */
const snapshot = (roomUrlHex: string): Record<string, unknown> => {
  const st = store.getState();
  const room = st.rooms.find((r) => r.url === roomUrlHex);
  const hs: Record<string, string> = {};
  for (const [pid, v] of Object.entries(room?.handshakeStatusByPeer ?? {}))
    hs[pid.slice(0, 8)] = v.status + (v.reason ? "/" + v.reason : "");
  const cover: Record<string, string> = {};
  for (const [pid, v] of Object.entries(room?.coverStatusByPeer ?? {}))
    cover[pid.slice(0, 8)] = v;
  const channels: Record<string, string[]> = {};
  for (const c of room?.channels ?? [])
    channels[c.label.slice(0, 8)] = c.peerIds.map((p) => p.slice(0, 8));
  return {
    me: st.keyPair.peerId.slice(0, 8),
    roomId: room?.id?.slice(0, 8) ?? "",
    ws: `${st.signalingServer.isEstablishingConnection ? "connecting" : st.signalingServer.isConnected ? "up" : "down"}${st.signalingServer.isVerified ? "+verified" : ""}`,
    peers: (room?.peers ?? []).map((p) => p.peerId.slice(0, 8) + "/" + p.peerPublicKey.slice(0, 6)),
    hs,
    cover,
    channels,
    connecting: room?.connectingToPeers ?? false,
    connected: room?.connectedToPeers ?? false,
    pcs: window.__pcs
      ? window.__pcs().map((p) => `#${String(p.id)}:${String(p.withPeerId).slice(0, 8)}:${String(p.connectionState)}/${String(p.iceConnectionState)}`)
      : [],
  };
};

/** Full state dump (item 3 of the harness spec). */
const dump = (roomUrlHex: string): Record<string, unknown> => {
  const st = store.getState();
  const room = st.rooms.find((r) => r.url === roomUrlHex);
  return {
    t: Date.now(),
    keyPair: { peerId: st.keyPair.peerId, publicKey: st.keyPair.publicKey },
    signalingServer: {
      isConnected: st.signalingServer.isConnected,
      isVerified: st.signalingServer.isVerified,
      isEstablishingConnection: st.signalingServer.isEstablishingConnection,
      peerId: st.keyPair.peerId,
    },
    room: room
      ? {
          id: room.id,
          url: room.url,
          signalingActive: room.signalingActive,
          peers: room.peers.map((p) => ({ peerId: p.peerId, peerPublicKey: p.peerPublicKey })),
          handshakeStatusByPeer: room.handshakeStatusByPeer ?? {},
          coverStatusByPeer: room.coverStatusByPeer ?? {},
          connectedToPeers: room.connectedToPeers,
          connectingToPeers: room.connectingToPeers,
          channels: room.channels.map((c) => ({ label: c.label, peerIds: c.peerIds })),
          messages: room.messages.length,
        }
      : null,
    pcs: window.__pcs ? window.__pcs() : [],
  };
};

let lastSnap = "";
let unsubscribe: (() => void) | undefined;

// ------------------------------------------------------------------ big transfers
// A multi-MiB sendMessage(File, ...) started right before the fault: the payload
// is generated + SHA-256'd ahead of time (prepareTransfer) so that startTransfer
// costs only a File copy, and handle.done is kept, never awaited, so the driver
// can SIGSTOP the page with the transfer still in flight.
interface TransferRec {
  id: string;
  bytes: number;
  sha256: string;
  filename: string;
  startedAt: number | null;
  settledAt: number | null;
  outcome: string | null;
  error?: string;
  merkleRootHex: string;
  transferId?: string;
  outcomes: Array<Record<string, unknown>>;
}
const transfers: Record<string, TransferRec> = {};
const preparedPayloads: Record<string, Uint8Array> = {};
const toHex = (b: ArrayBuffer): string =>
  Array.from(new Uint8Array(b))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
const sha256Hex = async (data: ArrayBuffer | Uint8Array): Promise<string> =>
  toHex(await crypto.subtle.digest("SHA-256", data as ArrayBuffer));
const shapeOutcomes = (
  outcomes: Array<Record<string, unknown>> | undefined,
): Array<Record<string, unknown>> =>
  (outcomes ?? []).map((o) => ({
    peer: String(o.peerId).slice(0, 8),
    status: o.status,
    reason: o.reason instanceof Error ? o.reason.message : o.reason,
    phase: o.phase,
  }));
/** The per-message data-channel label is <32-byte name hex>~<merkle root hex>. */
const isMessageChannel = (label: string): boolean => label.includes("~");
const shortLabel = (label: string): string =>
  isMessageChannel(label)
    ? "MSG:" + label.split("~")[1].slice(0, 12)
    : label.slice(0, 16);

const api = {
  boot(wasmUrl: string): void {
    setWasmSourceUrl(wasmUrl);
  },

  async connect(
    roomUrlHex: string,
    wsUrl: string,
    opts: {
      mode?: "immediate" | "scheduled" | "pin";
      pinHex?: string;
      /**
       * Cover cadence for the scheduled preset. The slot spacing is
       * cadence / (lanes x frames), and the runtime's drift tolerance is
       * min(floor(spacing) - 1, 500) ms — so a scenario that wants to stall
       * past a boundary picks the cadence that makes that tolerance small
       * enough to overrun deliberately.
       */
      coverCadenceMs?: number;
    } = {},
  ): Promise<void> {
    let policy: RoomPolicyV1 = canonicalizeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1);
    if (opts.mode === "scheduled") {
      policy = canonicalizeRoomPolicyV1({
        ...DEFAULT_ROOM_POLICY_V1,
        coverMode: "scheduled",
        coverCadenceMs: opts.coverCadenceMs ?? 2000,
        coverLanes: 2,
        coverFramesPerCell: 16,
        coverDurationEpochs: 1,
      });
    } else if (opts.mode === "pin") {
      policy = canonicalizeRoomPolicyV1({ ...DEFAULT_ROOM_POLICY_V1, authMode: "pin" });
    }
    const pin =
      opts.mode === "pin" && opts.pinHex
        ? Uint8Array.from(opts.pinHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)))
        : undefined;
    log({ event: "connect()", room: roomUrlHex.slice(0, 8) });
    await p2party.connect(roomUrlHex, wsUrl, LOOPBACK_RTC, { policy, pin });
  },

  /**
   * Emulates p2party.com's window "focus" handler (ChatLayout.tsx:93-107 +
   * useRoom.tsx connectToRoom): when the socket is neither connected nor
   * connecting, call p2party.connect(roomUrl, signalingUrl, rtcConfig,
   * { policy: <the room's current policy> }).
   */
  async focusReconnect(roomUrlHex: string, wsUrl: string): Promise<string> {
    const st = store.getState();
    if (st.signalingServer.isConnected) return "skipped: isConnected";
    if (st.signalingServer.isEstablishingConnection) return "skipped: isEstablishingConnection";
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    const policy = room?.policy ?? canonicalizeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1);
    log({ event: "focusReconnect()", room: roomUrlHex.slice(0, 8) });
    try {
      await p2party.connect(roomUrlHex, wsUrl, LOOPBACK_RTC, { policy });
      return "connect() resolved";
    } catch (error) {
      log({ event: "focusReconnect-error", error: String(error) });
      return "connect() threw: " + String(error);
    }
  },

  /**
   * Block the main thread for `ms`, the way a long GC pause or a huge paint
   * does. Every timer the cover scheduler holds fires late by roughly this
   * much, which is the C5 trigger: a boundary timer that overruns the
   * runtime's drift tolerance used to park the scheduler in "suspended" with
   * nothing armed to leave it.
   */
  stallMainThread(ms: number): number {
    const until = Date.now() + ms;
    let spins = 0;
    while (Date.now() < until) spins++;
    log({ event: "stallMainThread", ms, spins });
    return spins;
  },

  /** Live per-peer CoverSchedulerStatus for a room: the C5 liveness signal. */
  coverStatus(roomUrlHex: string): Record<string, string> {
    const room = store.getState().rooms.find((r) => r.url === roomUrlHex);
    return { ...(room?.coverStatusByPeer ?? {}) } as Record<string, string>;
  },

  /** Record every change of the room's peer/handshake/pc view. */
  watch(roomUrlHex: string): void {
    unsubscribe?.();
    lastSnap = "";
    const inspect = (): void => {
      const snap = snapshot(roomUrlHex);
      const json = JSON.stringify(snap);
      if (json !== lastSnap) {
        lastSnap = json;
        log({ event: "state", ...snap });
      }
    };
    unsubscribe = store.subscribe(inspect);
    // PC states change without a Redux action; sample them too.
    setInterval(inspect, 500);
    inspect();
  },

  timeline(): Array<Record<string, unknown>> {
    return window.__timeline;
  },
  snapshot(roomUrlHex: string): Record<string, unknown> {
    return snapshot(roomUrlHex);
  },
  dump(roomUrlHex: string): Record<string, unknown> {
    return dump(roomUrlHex);
  },
  pcEvents(): Array<Record<string, unknown>> {
    return window.__pcEvents ? window.__pcEvents() : [];
  },

  /**
   * Harness-only diagnostics (read-only): RTK Query mutation cache entries
   * still "pending" (a queryFn that never resolved), the room/peer negotiation
   * mutex registry, and a timed IndexedDB round trip.
   */
  async diag(roomUrlHex: string): Promise<Record<string, unknown>> {
    const st = store.getState() as unknown as Record<
      string,
      { mutations?: Record<string, Record<string, unknown>> }
    >;
    const roomId = roomIdFor(roomUrlHex);
    const room = store.getState().rooms.find((r) => r.id === roomId);
    const pending: Array<Record<string, unknown>> = [];
    const counts: Record<string, Record<string, number>> = {};
    for (const slice of ["webrtcApi", "signalingServerApi"]) {
      const muts = st[slice]?.mutations ?? {};
      counts[slice] = {};
      for (const [requestId, m] of Object.entries(muts)) {
        const status = String(m.status);
        counts[slice][status] = (counts[slice][status] ?? 0) + 1;
        if (status === "pending") {
          const args = m.originalArgs as Record<string, unknown> | undefined;
          const content = (args?.content ?? {}) as Record<string, unknown>;
          pending.push({
            slice,
            requestId,
            endpointName: m.endpointName,
            startedTimeStamp: m.startedTimeStamp,
            ageMs: Date.now() - Number(m.startedTimeStamp ?? Date.now()),
            args: {
              peerId: String(args?.peerId ?? "").slice(0, 8),
              type: content.type,
              descriptionType: (args?.description as { type?: string } | undefined)?.type,
              label: args?.label,
            },
          });
        }
      }
    }
    const peerIds = new Set<string>();
    for (const p of room?.peers ?? []) peerIds.add(p.peerId);
    for (const k of Object.keys(room?.handshakeStatusByPeer ?? {})) peerIds.add(k);
    for (const p of window.__pcs ? window.__pcs() : [])
      if (typeof p.withPeerId === "string" && p.withPeerId) peerIds.add(p.withPeerId);
    const mutexes: Record<string, boolean> = {};
    for (const pid of peerIds) {
      // Check existence before retrieving: diagnostics must not create a mutex.
      mutexes[pid] = hasRoomPeerMutex(roomId, pid) && !getRoomPeerMutex(roomId, pid).isIdle();
    }
    const dbStart = Date.now();
    const dbProbe = await Promise.race([
      getDBPeerIsBlacklisted([...peerIds][0]).then((v) => `resolved:${String(v)}`),
      new Promise<string>((r) => setTimeout(() => r("TIMEOUT 3000ms"), 3000)),
    ]);
    return {
      t: Date.now(),
      pendingMutations: pending,
      mutationCounts: counts,
      roomPeerMutexes: mutexes,
      roomPeerMutexCount: roomPeerMutexCount(),
      unnegotiatedTransportRebuilds: Object.fromEntries([...peerIds].map((pid) => [pid, unnegotiatedTransportRebuilds(roomId, pid)])),
      maxUnnegotiatedTransportRebuilds: MAX_UNNEGOTIATED_TRANSPORT_REBUILDS,
      dbProbe,
      dbProbeMs: Date.now() - dbStart,
    };
  },

  myPeerId(): string {
    return store.getState().keyPair.peerId;
  },
  myPublicKey(): string {
    return store.getState().keyPair.publicKey;
  },
  isConnected(): boolean {
    return store.getState().signalingServer.isConnected;
  },
  isVerified(): boolean {
    return store.getState().signalingServer.isVerified;
  },
  peerCount(roomUrlHex: string): number {
    const st = store.getState();
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    return room?.peers.length ?? 0;
  },
  authenticatedCount(roomUrlHex: string): number {
    const st = store.getState();
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    const hs = room?.handshakeStatusByPeer ?? {};
    return (room?.peers ?? []).filter((p) => hs[p.peerId]?.status === "authenticated").length;
  },

  async send(
    roomUrlHex: string,
    channel: string,
    text: string,
  ): Promise<Record<string, unknown>> {
    const roomId = roomIdFor(roomUrlHex);
    const started = Date.now();
    log({ event: "send()", channel });
    try {
      const handle = p2party.sendMessage(text, channel, roomId);
      const result = await handle.done;
      const outcomes = (result?.outcomes ?? []) as Array<Record<string, unknown>>;
      const out = {
        ok: outcomes.some((o) => o.status === "delivered"),
        ms: Date.now() - started,
        merkleRootHex: result?.merkleRootHex ?? "",
        outcomes: outcomes.map((o) => ({
          peer: String(o.peerId).slice(0, 8),
          status: o.status,
          reason: o.reason instanceof Error ? o.reason.message : o.reason,
          phase: o.phase,
        })),
      };
      log({ event: "send-result", ...out });
      return out;
    } catch (error) {
      const e = error as Error & { result?: { outcomes?: Array<Record<string, unknown>> } };
      const out = {
        ok: false,
        ms: Date.now() - started,
        error: e.message,
        outcomes: (e.result?.outcomes ?? []).map((o) => ({
          peer: String(o.peerId).slice(0, 8),
          status: o.status,
          reason: o.reason instanceof Error ? o.reason.message : o.reason,
          phase: o.phase,
        })),
      };
      log({ event: "send-error", ...out });
      return out;
    }
  },

  /** Add every roster peer to a channel so a send has targets (mirrors the app). */
  joinChannel(roomUrlHex: string, channel: string): void {
    const roomId = roomIdFor(roomUrlHex);
    const st = store.getState();
    const room = st.rooms.find((r) => r.id === roomId);
    if (!room) return;
    for (const peer of room.peers)
      store.dispatch(setChannel({ roomId, label: channel, peerId: peer.peerId }));
  },

  /** Most recent complete message authored by another peer. */
  latestIncoming(roomUrlHex: string): { merkleRootHex: string; from: string } | null {
    const st = store.getState();
    const me = st.keyPair.peerId;
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    if (!room) return null;
    for (let i = room.messages.length - 1; i >= 0; i--) {
      const m = room.messages[i];
      if (m.fromPeerId !== me && m.merkleRootHex && m.totalSize > 0 && m.savedSize >= m.totalSize)
        return { merkleRootHex: m.merkleRootHex, from: m.fromPeerId };
    }
    return null;
  },
  async read(merkleRootHex: string): Promise<string> {
    const res = await p2party.readMessage(merkleRootHex);
    return typeof res.message === "string" ? res.message : "[blob]";
  },

  // ---------------------------------------------------------------- big transfer
  /** Generate + hash the payload ahead of the fault (no network, no SDK call). */
  async prepareTransfer(id: string, mib: number): Promise<Record<string, unknown>> {
    const bytes = Math.round(mib * 1024 * 1024);
    const buf = new Uint8Array(bytes);
    for (let off = 0; off < bytes; off += 65536)
      crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, bytes)));
    const sha256 = await sha256Hex(buf);
    const filename = `xfer-${id}.bin`;
    preparedPayloads[id] = buf;
    transfers[id] = {
      id,
      bytes,
      sha256,
      filename,
      startedAt: null,
      settledAt: null,
      outcome: null,
      merkleRootHex: "",
      outcomes: [],
    };
    log({ event: "prepareTransfer", id, bytes, sha256: sha256.slice(0, 16) });
    return { id, bytes, sha256, filename };
  },

  /**
   * The real p2party.sendMessage the app uses, on the app's "main" channel.
   * handle.done is retained and settled into the record; it is NEVER awaited
   * here, so the caller can freeze the page microseconds later.
   */
  startTransfer(roomUrlHex: string, channel: string, id: string): Record<string, unknown> {
    const rec = transfers[id];
    const data = preparedPayloads[id];
    if (!rec || !data) return { started: false, error: "payload not prepared: " + id };
    const roomId = roomIdFor(roomUrlHex);
    if (!roomId) return { started: false, error: "no room for " + roomUrlHex.slice(0, 8) };
    const file = new File([data as BlobPart], rec.filename, {
      type: "application/octet-stream",
    });
    delete preparedPayloads[id]; // the File owns the bytes now
    rec.startedAt = Date.now();
    log({ event: "startTransfer", id, bytes: rec.bytes, channel });
    const handle = p2party.sendMessage(file, channel, roomId);
    rec.transferId = handle.transferId;
    handle.done
      .then((result) => {
        rec.settledAt = Date.now();
        rec.outcome = "resolved";
        rec.merkleRootHex = result?.merkleRootHex ?? "";
        rec.outcomes = shapeOutcomes(
          result?.outcomes as Array<Record<string, unknown>> | undefined,
        );
        log({
          event: "transfer-resolved",
          id,
          ms: rec.settledAt - (rec.startedAt ?? rec.settledAt),
          outcomes: rec.outcomes,
        });
      })
      .catch((error: unknown) => {
        const e = error as Error & {
          result?: { outcomes?: Array<Record<string, unknown>>; merkleRootHex?: string };
        };
        rec.settledAt = Date.now();
        rec.outcome = "rejected";
        rec.error = e.message;
        rec.merkleRootHex = e.result?.merkleRootHex ?? "";
        rec.outcomes = shapeOutcomes(e.result?.outcomes);
        log({
          event: "transfer-rejected",
          id,
          ms: rec.settledAt - (rec.startedAt ?? rec.settledAt),
          error: e.message,
          outcomes: rec.outcomes,
        });
      });
    return { started: true, transferId: rec.transferId, at: rec.startedAt };
  },

  /** Sender view: has handle.done settled, and with what. */
  transferState(id: string): Record<string, unknown> {
    const rec = transfers[id];
    if (!rec) return { known: false };
    return {
      known: true,
      id: rec.id,
      bytes: rec.bytes,
      sha256: rec.sha256,
      filename: rec.filename,
      startedAt: rec.startedAt,
      settledAt: rec.settledAt,
      settled: rec.settledAt !== null,
      ms: rec.settledAt && rec.startedAt ? rec.settledAt - rec.startedAt : null,
      outcome: rec.outcome,
      error: rec.error,
      merkleRootHex: rec.merkleRootHex,
      transferId: rec.transferId,
      outcomes: rec.outcomes,
    };
  },

  /** Sender's own history row for the big message (carries `retransmits`). */
  outgoingBig(roomUrlHex: string, minBytes: number): Record<string, unknown> | null {
    const st = store.getState();
    const me = st.keyPair.peerId;
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    if (!room) return null;
    for (let i = room.messages.length - 1; i >= 0; i--) {
      const m = room.messages[i];
      if (m.fromPeerId === me && m.totalSize >= minBytes)
        return {
          merkleRootHex: m.merkleRootHex,
          filename: m.filename,
          savedSize: m.savedSize,
          totalSize: m.totalSize,
          chunksCreated: m.chunksCreated,
          totalChunks: m.totalChunks,
          chunksReceivedTotal: m.chunksReceivedTotal,
          chunksReceivedReal: m.chunksReceivedReal,
          retransmits: m.retransmits,
        };
    }
    return null;
  },

  /** Receiver view: progress + telemetry of the big inbound message. */
  incomingBig(roomUrlHex: string, minBytes: number): Record<string, unknown> | null {
    const st = store.getState();
    const me = st.keyPair.peerId;
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    if (!room) return null;
    for (let i = room.messages.length - 1; i >= 0; i--) {
      const m = room.messages[i];
      if (m.fromPeerId !== me && m.totalSize >= minBytes)
        return {
          merkleRootHex: m.merkleRootHex,
          from: m.fromPeerId.slice(0, 8),
          filename: m.filename,
          savedSize: m.savedSize,
          totalSize: m.totalSize,
          percent:
            m.totalSize > 0 ? Math.floor((m.savedSize / m.totalSize) * 100) : 0,
          complete: m.totalSize > 0 && m.savedSize >= m.totalSize,
          chunksCreated: m.chunksCreated,
          totalChunks: m.totalChunks,
          chunksReceivedTotal: m.chunksReceivedTotal,
          chunksReceivedReal: m.chunksReceivedReal,
          retransmits: m.retransmits,
        };
    }
    return null;
  },

  /** Materialize the received message and hash it (byte-exactness check). */
  async verifyReceived(merkleRootHex: string): Promise<Record<string, unknown>> {
    const res = await p2party.readMessage(merkleRootHex);
    const body = res.message;
    let sha256 = "";
    let size = 0;
    let kind = "";
    if (typeof body === "string") {
      kind = "string";
      const bytes = new TextEncoder().encode(body);
      size = bytes.length;
      sha256 = await sha256Hex(bytes);
    } else {
      kind = "blob";
      const ab = await body.arrayBuffer();
      size = ab.byteLength;
      sha256 = await sha256Hex(ab);
    }
    return {
      kind,
      size,
      sha256,
      filename: res.filename,
      percentage: res.percentage,
      reportedSize: res.size,
      category: res.category,
      chunksReceivedTotal: res.chunksReceivedTotal,
      chunksReceivedReal: res.chunksReceivedReal,
      retransmits: res.retransmits,
    };
  },

  /** Every data channel this page ever created/received, per RTCPeerConnection. */
  dcStats(): Record<string, unknown> {
    const pcs = window.__pcs ? window.__pcs() : [];
    const perPc = pcs.map((p) => {
      const channels = (p.channels ?? []) as Array<{ label: string; readyState: string }>;
      return {
        pc: p.id,
        connectionState: p.connectionState,
        withPeerId: String(p.withPeerId ?? "").slice(0, 8),
        created: channels.length,
        perMessage: channels.filter((c) => isMessageChannel(c.label)).length,
        plain: channels.filter((c) => !isMessageChannel(c.label)).length,
        open: channels.filter((c) => c.readyState === "open").length,
        labels: channels.map((c) => shortLabel(c.label) + ":" + c.readyState),
      };
    });
    const events = (window.__pcEvents ? window.__pcEvents() : []) as Array<
      Record<string, unknown>
    >;
    const opened = new Set<string>();
    const closed = new Set<string>();
    let dcErrors = 0;
    for (const e of events) {
      const label = typeof e.label === "string" ? e.label : "";
      if (!label || !isMessageChannel(label)) continue;
      const key = `#${String(e.pc)}|${label}`;
      if (e.ev === "dc-open") opened.add(key);
      if (e.ev === "dc-close") closed.add(key);
      if (e.ev === "dc-error") dcErrors++;
    }
    return {
      perPc,
      createdTotal: perPc.reduce((a, p) => a + p.created, 0),
      perMessageTotal: perPc.reduce((a, p) => a + p.perMessage, 0),
      perMessageOpened: opened.size,
      perMessageClosed: closed.size,
      dcErrors,
    };
  },

  async disconnectPeer(peerId: string): Promise<void> {
    await p2party.disconnectFromPeer(peerId);
  },
  async disconnectSignaling(): Promise<void> {
    await p2party.disconnectFromSignalingServer();
  },
  async disconnectAll(): Promise<void> {
    await p2party.disconnectFromAllRooms();
  },
};

window.__app = api;
