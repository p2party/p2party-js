// Minimal in-Node signaling relay (Bun) implementing just enough of the
// p2party signaling protocol for two+ peers to discover each other and
// exchange SDP/ICE. It does NOT persist anything and does NOT verify the
// Ed25519 challenge (test relay) — it only routes. Replaces the real
// Postgres-backed server for a self-contained browser E2E.
const PORT = Number(process.env.RELAY_PORT ?? "8830");
const PROTO = 4;

interface WsData {
  peerId: string;
  publicKey: string;
  roomId: string | null;
}

const peers = new Map<string, Bun.ServerWebSocket<WsData>>(); // peerId → ws
const roomIdByUrl = new Map<string, string>();
const roomMembers = new Map<string, Set<string>>(); // roomId → peerIds
const pubKeyByPeer = new Map<string, string>();

const log = (...a: unknown[]) => console.log("[relay]", ...a);

const send = (ws: Bun.ServerWebSocket<WsData>, obj: unknown) =>
  ws.send(JSON.stringify(obj));

const roster = (roomId: string, exceptPeerId: string) =>
  [...(roomMembers.get(roomId) ?? [])]
    .filter((id) => id !== exceptPeerId)
    .map((id) => ({ id, publicKey: pubKeyByPeer.get(id) ?? "" }));

const pushPeers = (toPeerId: string, roomId: string) => {
  const ws = peers.get(toPeerId);
  if (!ws) return;
  send(ws, {
    type: "peers",
    roomId,
    peers: roster(roomId, toPeerId),
    protocolVersion: PROTO,
  });
};

Bun.serve<WsData, undefined>({
  port: PORT,
  fetch(req, server) {
    const url = new URL(req.url);
    if (url.pathname !== "/ws") return new Response("nope", { status: 404 });
    const publicKey = url.searchParams.get("publickey") ?? "";
    if (publicKey.length !== 64)
      return new Response("bad publickey", { status: 400 });
    const ok = server.upgrade(req, {
      data: { peerId: crypto.randomUUID(), publicKey, roomId: null },
    });
    return ok ? undefined : new Response("upgrade failed", { status: 400 });
  },
  websocket: {
    open(ws) {
      pubKeyByPeer.set(ws.data.peerId, ws.data.publicKey);
      peers.set(ws.data.peerId, ws);
      // Server issues the peerId + a fresh challenge nonce.
      const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
      send(ws, {
        type: "peerId",
        peerId: ws.data.peerId,
        challenge: nonce,
        protocolVersion: PROTO,
        message: "relay challenge",
      });
      log("open", ws.data.peerId.slice(0, 8), "pub", ws.data.publicKey.slice(0, 8));
    },
    message(ws, raw) {
      if (raw === "PONG") return;
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(String(raw));
      } catch {
        return;
      }
      switch (msg.type) {
        case "pong":
          return;
        case "challenge": {
          // Accept without cryptographic verification (test relay).
          send(ws, { type: "challenge", challengeId: crypto.randomUUID(), protocolVersion: PROTO });
          return;
        }
        case "room": {
          const roomUrl = String(msg.roomUrl);
          let roomId = roomIdByUrl.get(roomUrl);
          if (!roomId) {
            roomId = crypto.randomUUID();
            roomIdByUrl.set(roomUrl, roomId);
            roomMembers.set(roomId, new Set());
          }
          ws.data.roomId = roomId;
          roomMembers.get(roomId)!.add(ws.data.peerId);
          send(ws, { type: "roomId", roomId, roomUrl, protocolVersion: PROTO });
          // Introduce this peer to existing members and vice versa.
          for (const memberId of roomMembers.get(roomId)!) {
            pushPeers(memberId, roomId);
          }
          log("room", roomUrl.slice(0, 8), "→", roomId.slice(0, 8), "members", roomMembers.get(roomId)!.size);
          return;
        }
        case "peers": {
          const roomId = String(msg.roomId);
          pushPeers(ws.data.peerId, roomId);
          return;
        }
        case "connection": {
          // A→B "I want to connect" (labels). Route as a connection response.
          const to = peers.get(String(msg.toPeerId));
          if (!to) return;
          send(to, {
            type: "connection",
            roomId: msg.roomId,
            fromPeerId: msg.fromPeerId,
            fromPeerPublicKey: ws.data.publicKey,
            labels: msg.labels,
            protocolVersion: PROTO,
          });
          return;
        }
        case "description": {
          const to = peers.get(String(msg.toPeerId));
          if (!to) return;
          send(to, {
            type: "description",
            description: msg.description,
            fromPeerId: msg.fromPeerId,
            fromPeerPublicKey: msg.fromPeerPublicKey,
            roomId: msg.roomId,
            protocolVersion: PROTO,
          });
          return;
        }
        case "candidate": {
          const to = peers.get(String(msg.toPeerId));
          if (!to) return;
          send(to, {
            type: "candidate",
            candidate: msg.candidate,
            fromPeerId: msg.fromPeerId,
            roomId: msg.roomId,
            protocolVersion: PROTO,
          });
          return;
        }
        default:
          return;
      }
    },
    close(ws) {
      peers.delete(ws.data.peerId);
      if (ws.data.roomId) roomMembers.get(ws.data.roomId)?.delete(ws.data.peerId);
      log("close", ws.data.peerId.slice(0, 8));
    },
  },
});

log(`signaling relay listening on ws://localhost:${PORT}/ws`);
