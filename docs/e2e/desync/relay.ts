// Desync-probe signaling relay (Bun). Mirrors the message flow of the real
// p2party-server 0.1.1 (src/utils/*.ts) closely enough to reproduce the
// reconnect path, with control hooks for fault injection:
//
//   * peerId assignment: RELAY_PEERID_MODE=stable (default; mirrors the real
//     server, whose handleConnection does prisma.peer.upsert({where:{publicKey}})
//     so the SAME peerId is reissued to a reconnecting identity) or
//     RELAY_PEERID_MODE=fresh (a NEW uuid per socket, the orchestrator's H1
//     assumption).
//   * registry: verified sockets keyed by peerId; a successor socket for the
//     same peerId replaces + closes the predecessor (socketAuth.registerVerifiedSocket).
//   * join flow: "room" -> roomId; "peers" from X -> every OTHER live member
//     gets {peerConnection, peer:X}; "peerConnection"{from:M,to:X} -> X gets
//     {peers:[M]}; "connection"/"description"/"candidate" routed by toPeerId.
//   * room membership is durable (DB semantics): a closed socket never leaves
//     the room; only leaveRoom does.
//   * heartbeat: {type:"ping"} every 10 s, close if no pong within 5 s
//     (handleInterval.ts PING_INTERVAL/PONG_TIMEOUT). idleTimeout 60 s.
//   * close: the server never tells other members that a peer left.
//
// Control hooks (plain HTTP on the same port):
//   POST /ctl/close?peerId=<uuid>|pub=<hex-prefix>        close that client's socket server-side
//   POST /ctl/blackhole?peerId=..|pub=..&ms=<N>          drop every frame to/from that client for N ms
//   POST /ctl/keepalive?peerId=..|pub=..&ms=<N>          suppress the pong-timeout eviction for
//                                                         that client for N ms (Android-style: JS
//                                                         throttled but the socket still answers pings)
//   GET  /ctl/registry                                    dump the peerId registry + rooms
//   GET  /ctl/log                                         the frame log
// Every routed frame is logged as "t=+s.s type from->to".
const PORT = Number(process.env.RELAY_PORT ?? "5811");
const PEERID_MODE = process.env.RELAY_PEERID_MODE === "fresh" ? "fresh" : "stable";
const PROTO = 4;
const PING_INTERVAL = 10000;
const PONG_TIMEOUT = 5000;

interface WsData {
  sock: number;
  peerId: string;
  publicKey: string;
  challengeNonce: string;
  isVerified: boolean;
  isAlive: boolean;
  pingInterval?: ReturnType<typeof setInterval>;
  pongTimeout?: ReturnType<typeof setTimeout>;
  blackholeUntil: number;
  keepaliveUntil: number;
  rooms: Set<string>;
}
type Sock = Bun.ServerWebSocket<WsData>;

const T0 = Date.now();
const ts = () => `+${((Date.now() - T0) / 1000).toFixed(1)}`;
const frameLog: string[] = [];
const log = (line: string) => {
  const full = `[relay] t=${ts()} ${line}`;
  frameLog.push(full);
  console.log(full);
};
const short = (id: string) => (id ? id.slice(0, 8) : "?");

// "DB" state (durable, survives socket close)
const peerIdByPublicKey = new Map<string, string>();
const publicKeyByPeerId = new Map<string, string>();
const roomIdByUrl = new Map<string, string>();
const roomUrlById = new Map<string, string>();
const roomMembers = new Map<string, Set<string>>(); // roomId -> peerIds (durable)
// live registry (verified sockets)
const clients = new Map<string, Sock>();
const allSockets = new Set<Sock>();
let sockSeq = 0;
const blackholeByPub = new Map<string, number>(); // pub prefix -> until
const socketByPeerIdHistory: Array<{ sock: number; peerId: string; publicKey: string; at: number }> = [];

const isCurrentVerified = (ws: Sock) =>
  ws.readyState === 1 && ws.data.isVerified && clients.get(ws.data.peerId) === ws;

const blackholed = (ws: Sock) => ws.data.blackholeUntil > Date.now();

const sendTo = (ws: Sock, obj: Record<string, unknown>, from: string) => {
  const type = String(obj.type);
  if (blackholed(ws)) {
    log(`${type} ${from}->${short(ws.data.peerId)} DROPPED(blackhole sock#${ws.data.sock})`);
    return;
  }
  if (ws.readyState !== 1) {
    log(`${type} ${from}->${short(ws.data.peerId)} UNDELIVERABLE(socket not open sock#${ws.data.sock})`);
    return;
  }
  ws.send(JSON.stringify(obj));
  log(`${type} ${from}->${short(ws.data.peerId)} (sock#${ws.data.sock})`);
};

const route = (toPeerId: string, obj: Record<string, unknown>, from: string) => {
  const target = clients.get(toPeerId);
  if (!target) {
    log(`${String(obj.type)} ${from}->${short(toPeerId)} UNDELIVERABLE(peerId not in registry)`);
    return;
  }
  if (!isCurrentVerified(target)) {
    log(`${String(obj.type)} ${from}->${short(toPeerId)} UNDELIVERABLE(target not current/verified)`);
    return;
  }
  sendTo(target, obj, from);
};

const bothInRoom = (roomId: string, a: string, b: string) => {
  const m = roomMembers.get(roomId);
  return !!m && m.has(a) && m.has(b);
};

const startHeartbeat = (ws: Sock) => {
  ws.data.isAlive = true;
  ws.data.pingInterval = setInterval(() => {
    if (!ws.data.isAlive && ws.data.keepaliveUntil > Date.now()) {
      log(`KEEPALIVE ${short(ws.data.peerId)} sock#${ws.data.sock}: no pong but eviction suppressed (${ws.data.keepaliveUntil - Date.now()}ms left)`);
      ws.data.isAlive = true;
    }
    if (!ws.data.isAlive) {
      log(`EVICT ${short(ws.data.peerId)} sock#${ws.data.sock}: no pong before next ping`);
      clearInterval(ws.data.pingInterval);
      ws.close();
      return;
    }
    if (ws.readyState !== 1) return;
    // The heartbeat goes through the same drop gate as routed frames. A real
    // network fault does not spare pings, and sparing them here made the
    // client's own liveness watchdog untestable: it kept measuring a live
    // socket because the server's pings arrived throughout the fault.
    if (blackholed(ws)) {
      log(`ping srv->${short(ws.data.peerId)} DROPPED(blackhole sock#${ws.data.sock})`);
    } else {
      ws.send(JSON.stringify({ type: "ping" }));
      log(`ping srv->${short(ws.data.peerId)} (sock#${ws.data.sock})`);
    }
    ws.data.isAlive = false;
    ws.data.pongTimeout = setTimeout(() => {
      if (!ws.data.isAlive && ws.data.keepaliveUntil > Date.now()) {
        log(`KEEPALIVE ${short(ws.data.peerId)} sock#${ws.data.sock}: pong timeout but eviction suppressed (${ws.data.keepaliveUntil - Date.now()}ms left)`);
        return;
      }
      if (!ws.data.isAlive) {
        log(`EVICT ${short(ws.data.peerId)} sock#${ws.data.sock}: pong timeout ${PONG_TIMEOUT}ms`);
        clearInterval(ws.data.pingInterval);
        ws.close();
      }
    }, PONG_TIMEOUT);
  }, PING_INTERVAL);
};

const registry = () => ({
  mode: PEERID_MODE,
  now: ts(),
  clients: [...clients.values()].map((ws) => ({
    peerId: ws.data.peerId,
    publicKey: ws.data.publicKey,
    sock: ws.data.sock,
    verified: ws.data.isVerified,
    readyState: ws.readyState,
    isAlive: ws.data.isAlive,
    blackholedMs: Math.max(0, ws.data.blackholeUntil - Date.now()),
    keepaliveMs: Math.max(0, ws.data.keepaliveUntil - Date.now()),
    rooms: [...ws.data.rooms],
  })),
  openSockets: [...allSockets].map((ws) => ({
    sock: ws.data.sock,
    peerId: ws.data.peerId,
    publicKey: ws.data.publicKey.slice(0, 8),
    verified: ws.data.isVerified,
    readyState: ws.readyState,
    current: clients.get(ws.data.peerId) === ws,
  })),
  peerIdByPublicKey: Object.fromEntries(peerIdByPublicKey),
  rooms: Object.fromEntries(
    [...roomMembers].map(([roomId, members]) => [
      roomId,
      { url: roomUrlById.get(roomId), members: [...members] },
    ]),
  ),
  history: socketByPeerIdHistory,
});

const findSocket = (url: URL): Sock | undefined => {
  const peerId = url.searchParams.get("peerId");
  const pub = url.searchParams.get("pub");
  for (const ws of allSockets) {
    if (peerId && ws.data.peerId === peerId) return ws;
    if (pub && ws.data.publicKey.startsWith(pub)) return ws;
  }
  return undefined;
};

Bun.serve<WsData, undefined>({
  port: PORT,
  idleTimeout: 60,
  fetch(req, server) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/ctl/")) {
      const json = (o: unknown, status = 200) =>
        new Response(JSON.stringify(o, null, 1), {
          status,
          headers: { "content-type": "application/json" },
        });
      if (url.pathname === "/ctl/registry") return json(registry());
      if (url.pathname === "/ctl/log") return json(frameLog);
      if (url.pathname === "/ctl/close") {
        const ws = findSocket(url);
        if (!ws) return json({ ok: false, error: "no such socket" }, 404);
        log(`CTL close ${short(ws.data.peerId)} sock#${ws.data.sock} (server-side close)`);
        ws.close(1001, "ctl-close");
        return json({ ok: true, peerId: ws.data.peerId, sock: ws.data.sock });
      }
      if (url.pathname === "/ctl/keepalive") {
        const ms = Number(url.searchParams.get("ms") ?? "0");
        const ws = findSocket(url);
        if (!ws) return json({ ok: false, error: "no such socket" }, 404);
        ws.data.keepaliveUntil = Date.now() + ms;
        log(`CTL keepalive ${short(ws.data.peerId)} sock#${ws.data.sock} for ${ms}ms (pong-timeout eviction suppressed)`);
        return json({ ok: true, peerId: ws.data.peerId, sock: ws.data.sock, ms });
      }
      if (url.pathname === "/ctl/blackhole") {
        const ms = Number(url.searchParams.get("ms") ?? "0");
        const pub = url.searchParams.get("pub");
        let n = 0;
        // Apply to every socket of that identity now AND to sockets that show
        // up later with the same public key while the window is open.
        for (const ws of allSockets) {
          const match =
            (url.searchParams.get("peerId") && ws.data.peerId === url.searchParams.get("peerId")) ||
            (pub && ws.data.publicKey.startsWith(pub));
          if (match) {
            ws.data.blackholeUntil = Date.now() + ms;
            n++;
            log(`CTL blackhole ${short(ws.data.peerId)} sock#${ws.data.sock} for ${ms}ms`);
          }
        }
        if (pub) blackholeByPub.set(pub, Date.now() + ms);
        return json({ ok: true, sockets: n, ms });
      }
      return json({ ok: false, error: "unknown ctl" }, 404);
    }
    if (url.pathname !== "/ws") return new Response("nope", { status: 404 });
    const publicKey = url.searchParams.get("publickey") ?? "";
    if (!/^[0-9a-f]{64}$/.test(publicKey)) return new Response("Forbidden", { status: 403 });
    const ok = server.upgrade(req, {
      data: {
        sock: ++sockSeq,
        peerId: "",
        publicKey,
        challengeNonce: "",
        isVerified: false,
        isAlive: true,
        blackholeUntil: 0,
        keepaliveUntil: 0,
        rooms: new Set<string>(),
      },
    });
    return ok ? undefined : new Response("upgrade failed", { status: 500 });
  },
  websocket: {
    open(ws) {
      allSockets.add(ws);
      // handleConnection: DB upsert by publicKey -> stable id (or fresh per socket).
      let peerId: string;
      let reused = false;
      if (PEERID_MODE === "stable" && peerIdByPublicKey.has(ws.data.publicKey)) {
        peerId = peerIdByPublicKey.get(ws.data.publicKey)!;
        reused = true;
      } else {
        peerId = crypto.randomUUID();
        peerIdByPublicKey.set(ws.data.publicKey, peerId);
        publicKeyByPeerId.set(peerId, ws.data.publicKey);
      }
      ws.data.peerId = peerId;
      socketByPeerIdHistory.push({ sock: ws.data.sock, peerId, publicKey: ws.data.publicKey, at: Date.now() - T0 });
      for (const [pub, until] of blackholeByPub)
        if (ws.data.publicKey.startsWith(pub) && until > Date.now()) ws.data.blackholeUntil = until;
      const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
      ws.data.challengeNonce = nonce;
      log(
        `OPEN sock#${ws.data.sock} pub=${ws.data.publicKey.slice(0, 8)} -> peerId=${short(peerId)} (${reused ? "REUSED same peerId" : "fresh peerId"}, mode=${PEERID_MODE})`,
      );
      sendTo(ws, { type: "peerId", peerId, challenge: nonce, protocolVersion: PROTO, message: "relay challenge" }, "srv");
      startHeartbeat(ws);
    },
    message(ws, raw) {
      if (blackholed(ws)) {
        let t = "?";
        try { t = String(JSON.parse(String(raw)).type); } catch { t = String(raw).slice(0, 8); }
        log(`${t} ${short(ws.data.peerId)}->srv DROPPED(blackhole inbound sock#${ws.data.sock})`);
        return;
      }
      if (raw === "PONG") { ws.data.isAlive = true; return; }
      let msg: Record<string, any>;
      try { msg = JSON.parse(String(raw)); } catch { return; }
      const from = short(ws.data.peerId);
      if (msg.type === "pong") {
        if (msg.fromPeerId !== ws.data.peerId || clients.get(ws.data.peerId) !== ws) {
          log(`pong ${from}->srv IGNORED(not current owner sock#${ws.data.sock})`);
          return;
        }
        ws.data.isAlive = true;
        if (ws.data.pongTimeout) clearTimeout(ws.data.pongTimeout);
        ws.data.pongTimeout = undefined;
        log(`pong ${from}->srv (sock#${ws.data.sock})`);
        return;
      }
      if (msg.fromPeerId !== ws.data.peerId) {
        log(`${String(msg.type)} ${from}->srv REJECT(fromPeerId ${short(String(msg.fromPeerId))} != socket peerId) closing sock#${ws.data.sock}`);
        ws.close();
        return;
      }
      if (msg.type !== "challenge" && !isCurrentVerified(ws)) {
        log(`${String(msg.type)} ${from}->srv REJECT(socket not verified/current) closing sock#${ws.data.sock}`);
        ws.close();
        return;
      }
      switch (msg.type) {
        case "challenge": {
          if (msg.challenge !== ws.data.challengeNonce || ws.data.isVerified) {
            log(`challenge ${from}->srv REJECT(nonce mismatch) sock#${ws.data.sock}`);
            ws.close();
            return;
          }
          // Signature not verified (test relay). registerVerifiedSocket:
          ws.data.isVerified = true;
          const predecessor = clients.get(ws.data.peerId);
          clients.set(ws.data.peerId, ws);
          if (predecessor && predecessor !== ws) {
            log(`REGISTER ${from} sock#${ws.data.sock} REPLACES sock#${predecessor.data.sock} (predecessor closed)`);
            predecessor.data.isVerified = false;
            predecessor.close();
          } else log(`REGISTER ${from} sock#${ws.data.sock} verified`);
          sendTo(ws, { type: "challenge", challengeId: crypto.randomUUID(), protocolVersion: PROTO }, "srv");
          return;
        }
        case "room": {
          if (typeof msg.roomUrl !== "string" || typeof msg.roomRequestId !== "string") return;
          let roomId = roomIdByUrl.get(msg.roomUrl);
          if (!roomId) {
            roomId = crypto.randomUUID();
            roomIdByUrl.set(msg.roomUrl, roomId);
            roomUrlById.set(roomId, msg.roomUrl);
            roomMembers.set(roomId, new Set());
          }
          const wasMember = roomMembers.get(roomId)!.has(ws.data.peerId);
          roomMembers.get(roomId)!.add(ws.data.peerId);
          ws.data.rooms.add(roomId);
          log(`room ${from}->srv url=${msg.roomUrl.slice(0, 8)} -> roomId=${short(roomId)} (${wasMember ? "already member" : "joined"}, members=${roomMembers.get(roomId)!.size})`);
          sendTo(ws, { type: "roomId", roomId, roomUrl: msg.roomUrl, roomRequestId: msg.roomRequestId, protocolVersion: PROTO }, "srv");
          return;
        }
        case "peers": {
          const roomId = String(msg.roomId);
          const members = roomMembers.get(roomId);
          if (!members || !members.has(ws.data.peerId)) {
            log(`peers ${from}->srv REJECT(not a member of ${short(roomId)})`);
            ws.close();
            return;
          }
          log(`peers ${from}->srv room=${short(roomId)} members=[${[...members].map(short).join(",")}]`);
          for (const memberId of members) {
            if (memberId === ws.data.peerId) continue;
            const target = clients.get(memberId);
            const intro = { type: "peerConnection", roomId, peer: { id: ws.data.peerId, publicKey: ws.data.publicKey }, protocolVersion: PROTO };
            // Mirrors p2party-server handlePeers.ts: no isAlive conjunct. That
            // flag is false for the whole round trip of every ping, and route()
            // never checked it either, so it was never a transport requirement.
            if (target && isCurrentVerified(target)) sendTo(target, intro, from);
            else log(`peerConnection ${from}->${short(memberId)} UNDELIVERABLE(member has no current verified socket)`);
          }
          return;
        }
        case "peerConnection": {
          const roomId = String(msg.roomId);
          const toPeerId = String(msg.toPeerId);
          if (!bothInRoom(roomId, ws.data.peerId, toPeerId)) {
            log(`peerConnection ${from}->${short(toPeerId)} REJECT(not both in room)`);
            ws.close();
            return;
          }
          route(toPeerId, { type: "peers", roomId, peers: [{ id: ws.data.peerId, publicKey: ws.data.publicKey }], protocolVersion: PROTO }, from);
          return;
        }
        case "connection": {
          const roomId = String(msg.roomId);
          const toPeerId = String(msg.toPeerId);
          if (!bothInRoom(roomId, ws.data.peerId, toPeerId)) { log(`connection ${from}->${short(toPeerId)} REJECT(not both in room)`); return; }
          route(toPeerId, { type: "connection", roomId, fromPeerId: ws.data.peerId, fromPeerPublicKey: ws.data.publicKey, labels: msg.labels, protocolVersion: PROTO }, from);
          return;
        }
        case "description": {
          const roomId = String(msg.roomId);
          const toPeerId = String(msg.toPeerId);
          if (!bothInRoom(roomId, ws.data.peerId, toPeerId)) { log(`description ${from}->${short(toPeerId)} REJECT(not both in room)`); return; }
          route(toPeerId, { type: "description", description: msg.description, fromPeerId: ws.data.peerId, fromPeerPublicKey: ws.data.publicKey, roomId, protocolVersion: PROTO }, `${from}(${msg.description?.type})`);
          return;
        }
        case "candidate": {
          const roomId = String(msg.roomId);
          const toPeerId = String(msg.toPeerId);
          if (!bothInRoom(roomId, ws.data.peerId, toPeerId)) { log(`candidate ${from}->${short(toPeerId)} REJECT(not both in room)`); return; }
          route(toPeerId, { type: "candidate", candidate: msg.candidate, fromPeerId: ws.data.peerId, roomId, protocolVersion: PROTO }, from);
          return;
        }
        case "leaveRoom": {
          const roomId = roomIdByUrl.get(String(msg.roomUrl));
          if (roomId) { roomMembers.get(roomId)?.delete(ws.data.peerId); ws.data.rooms.delete(roomId); }
          log(`leaveRoom ${from}->srv room=${short(roomId ?? "")}`);
          sendTo(ws, { type: "roomLeft", roomUrl: msg.roomUrl, roomLeaveId: msg.roomLeaveId, protocolVersion: PROTO }, "srv");
          return;
        }
        default:
          log(`${String(msg.type)} ${from}->srv IGNORED(unknown type)`);
          return;
      }
    },
    close(ws, code, reason) {
      allSockets.delete(ws);
      if (ws.data.pongTimeout) clearTimeout(ws.data.pongTimeout);
      if (ws.data.pingInterval) clearInterval(ws.data.pingInterval);
      const wasCurrent = clients.get(ws.data.peerId) === ws;
      if (wasCurrent) clients.delete(ws.data.peerId);
      // Membership is durable: nothing is told to the other room members.
      log(`CLOSE sock#${ws.data.sock} peerId=${short(ws.data.peerId)} code=${code} reason=${JSON.stringify(reason)} ${wasCurrent ? "(unregistered; room members NOT notified)" : "(stale socket, registry untouched)"}`);
    },
  },
});

log(`signaling relay listening on ws://localhost:${PORT}/ws (peerId mode=${PEERID_MODE}, ping ${PING_INTERVAL}ms/pong ${PONG_TIMEOUT}ms)`);
