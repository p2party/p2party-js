// Desync probe driver: real p2party app stack (Redux + IndexedDB + WebRTC) in
// two headless-Chromium INSTANCES (one chromium.launch() per page, each its own
// process tree), a Bun signaling relay with fault-injection hooks. One command
// per scenario:
//
//   PLAYWRIGHT_BROWSERS_PATH=$HOME/Library/Caches/ms-playwright \
//   node desync-driver.mjs <scenario> <role> [--peerid=stable|fresh] [--n=1] [--observe=120] [--socket=evict|close2s] [--refocus=0]
//
//   scenario: baseline | ws-drop | freeze-ws-90 | offline-60 | freeze-20 | proc-freeze-<seconds>
//   role:     initiator | responder   (which identity role the FAULTED page A has;
//             Ed25519 role = lexically lower hex pubkey is the initiator)
//   --peerid: relay peerId policy on reconnect. "stable" (default) mirrors the
//             real server (Peer.publicKey is @unique; handleConnection upserts by
//             publicKey, so the same peerId is reissued); "fresh" issues a new
//             peerId per socket (the H1 assumption).
//   --socket: proc-freeze only. "evict" (default): nothing but the freeze; the
//             relay's 10 s ping / 5 s pong timer evicts A. "close2s": ALSO
//             POST /ctl/close for A 2 s into the freeze (iOS tears the socket
//             down when the app is suspended). "keep": POST /ctl/keepalive for A
//             for the whole freeze (+15 s), so the relay does NOT evict A even though
//             no pong arrives (Android-style: JS throttled but the socket survives;
//             the frontend focus handler then sees isConnected=true and does nothing).
// Probe sends: whenever A says "authenticated" for B but B does not say so for A
//             (the asymmetric window), ONE sendMessage on "main" from A and ONE from B
//             at ~10 s and again at ~60 s after t=0, recording exactly what the
//             sender's handle.done resolves/rejects with and whether the other side
//             ever stored the message (results.probeSends).
//   --refocus=N: proc-freeze only. After the single focus-handler emulation at
//             thaw+1 s, re-run the focus handler every N s (0 = off, default).
//   --udpflood=1: proc-freeze only. "radio off": right after the SIGSTOP, fill
//             the kernel receive buffer of every UDP host-candidate socket of
//             A's live PC(s) with junk datagrams (net.inet.udp.recvspace is
//             786896 B here), so every datagram B sends to A for the rest of
//             the freeze (consent checks, ICE-restart STUN, the DTLS/SCTP
//             close at B's teardown) is DROPPED by A's kernel instead of being
//             queued for A to read at thaw. Without it, loopback delivers B's
//             close into the frozen A and A's stale PC closes at thaw.
//   --transfer=<A2B|B2A>:<MiB>: a REAL multi-MiB file transfer across the fault.
//             The payload (random bytes, SHA-256 recorded) is generated on the
//             sender page while the link is healthy; the actual
//             p2party.sendMessage(File, "main", roomId) is fired in the last
//             instant BEFORE the fault (for proc-freeze: immediately before the
//             SIGSTOP) and its handle.done is kept, never awaited, so the
//             transfer is genuinely in flight when the page freezes. A2B sends
//             from the FAULTED page A, B2A from the untouched page B. After the
//             thaw + focus emulation the receiver is polled every second until
//             its message is complete; it is then materialized with
//             p2party.readMessage and SHA-256 compared against the sender's
//             payload. Recorded in results.transfer: when handle.done settled
//             and with what per-peer outcomes, receiver progress over time,
//             chunksReceivedReal/Total + retransmits on both sides, and the
//             per-message data channels each side created. While the transfer is
//             unfinished the I4 round trips and the asymmetric probe sends are
//             held back so they cannot confound it.
//
// proc-freeze-<s> = "phone asleep": A's WHOLE Chromium process tree (browser
// pid + every descendant) is SIGSTOPped for <s> seconds, so JS, the WebSocket
// AND WebRTC ICE all stop, exactly like a backgrounded phone. The driver never
// touches A while frozen (no evaluate, no CDP); only B and the relay are polled
// (every 1 s). Thaw = SIGCONT (browser first, then children; the tree is
// re-enumerated at thaw). The observation clock (t=0) is the thaw instant.
// 1 s after thaw the p2party.com focus handler is emulated on A
// (ChatLayout.tsx:93-107: connect(roomUrl) iff !isConnected).
//
// Output: ../runs/<scenario>-<role>-<n>.{json,log}
import http from "node:http";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { spawn, execSync } from "node:child_process";
import dgram from "node:dgram";
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";

process.env.PLAYWRIGHT_BROWSERS_PATH ??= path.join(os.homedir(), "Library/Caches/ms-playwright");
const pw = await import("~/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js");
const { chromium } = pw.default ?? pw;

// ---------------------------------------------------------------- args
const argv = process.argv.slice(2);
const positional = argv.filter((a) => !a.startsWith("--"));
const flags = Object.fromEntries(argv.filter((a) => a.startsWith("--")).map((a) => { const [k, v] = a.slice(2).split("="); return [k, v ?? "1"]; }));
const scenario = positional[0] ?? "baseline";
const role = positional[1] ?? "initiator";
const PEERID_MODE = flags.peerid === "fresh" ? "fresh" : "stable";
const OBSERVE_S = Number(flags.observe ?? 120);
const SOCKET_MODE = flags.socket === "close2s" ? "close2s" : flags.socket === "keep" ? "keep" : "evict";
const REFOCUS_S = Number(flags.refocus ?? 0);
const UDP_FLOOD = flags.udpflood === "1" || flags.udpflood === "true";
const TRANSFER = (() => {
  if (!flags.transfer) return null;
  const m = String(flags.transfer).match(/^(A2B|B2A):([0-9]+(?:\.[0-9]+)?)$/i);
  if (!m) { console.error(`--transfer must be <A2B|B2A>:<MiB>, got "${flags.transfer}"`); process.exit(2); }
  return { spec: String(flags.transfer), dir: m[1].toUpperCase(), mib: Number(m[2]) };
})();
// Verification budget for the big transfer, measured from t=0 (thaw / fault cleared).
const TRANSFER_DEADLINE_S = Number(flags.transferdeadline ?? 90);
const SCENARIOS = ["baseline", "ws-drop", "freeze-ws-90", "offline-60", "freeze-20"];
const procFreezeMatch = scenario.match(/^proc-freeze-(\d+)$/);
const PROC_FREEZE_S = procFreezeMatch ? Number(procFreezeMatch[1]) : 0;
if (!SCENARIOS.includes(scenario) && !procFreezeMatch) { console.error(`unknown scenario ${scenario}; one of ${SCENARIOS.join("|")}|proc-freeze-<seconds>`); process.exit(2); }
if (!["initiator", "responder"].includes(role)) { console.error("role must be initiator|responder"); process.exit(2); }

const dir = path.dirname(fileURLToPath(import.meta.url));
const runsDir = path.join(dir, "..", "runs");
mkdirSync(runsDir, { recursive: true });
let n = Number(flags.n ?? 0);
if (!n) { n = 1; while (existsSync(path.join(runsDir, `${scenario}-${role}-${n}.json`))) n++; }
const outBase = path.join(runsDir, `${scenario}-${role}-${n}`);

const HTTP_PORT = 5810;
const RELAY_PORT = 5811;
const wsUrl = `ws://localhost:${RELAY_PORT}/ws`;
const ctlUrl = `http://localhost:${RELAY_PORT}/ctl`;
const wasmUrl = `http://localhost:${HTTP_PORT}/libcrypto.wasm`;
const ROOM = "de".repeat(32);

// ---------------------------------------------------------------- logging
const T0 = Date.now();
const rel = (t = Date.now()) => `+${((t - T0) / 1000).toFixed(1)}`;
const logLines = [];
const say = (...a) => { const line = `t=${rel()} ${a.join(" ")}`; logLines.push(line); process.stdout.write(line + "\n"); };
const relayLog = [];
const pageConsoles = new Map(); // page name -> array (driver-side timestamps)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const withTimeout = (p, ms, label) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`TIMEOUT ${label} (${ms}ms)`)), ms))]);

// ---------------------------------------------------------------- process-tree freeze (the "phone asleep" fault)
const sh = (cmd) => { try { return execSync(cmd, { stdio: ["ignore", "pipe", "ignore"] }).toString(); } catch { return ""; } };
const psTable = () => sh("ps -axo pid=,ppid=,stat=,comm=").trim().split("\n").filter(Boolean).map((l) => { const [pid, ppid, stat, ...comm] = l.trim().split(/\s+/); return { pid: +pid, ppid: +ppid, stat, comm: comm.join(" ") }; });
/** Every descendant of root (depth-first, parents before children). */
const descendants = (root) => {
  const rows = psTable();
  const kids = new Map();
  for (const r of rows) { if (!kids.has(r.ppid)) kids.set(r.ppid, []); kids.get(r.ppid).push(r); }
  const out = [];
  const walk = (p, depth) => { for (const k of kids.get(p) ?? []) { out.push({ ...k, depth }); walk(k.pid, depth + 1); } };
  walk(root, 1);
  return out;
};
const psStates = (pids) => pids.length ? sh(`ps -o pid=,stat=,comm= -p ${pids.join(",")}`).trim().split("\n").filter(Boolean).map((l) => { const [pid, stat, ...comm] = l.trim().split(/\s+/); return { pid: +pid, stat, comm: comm.join(" ").replace(/^.*\//, "") }; }) : [];
const myChromiumChildren = () => psTable().filter((r) => r.ppid === process.pid && /chrom/i.test(r.comm)).map((r) => r.pid);
const frozenPids = new Set(); // for emergency cleanup
const launched = []; // browser root pids we launched (for cleanup by pid, never by name)
const emergencyCleanup = () => {
  for (const p of frozenPids) { try { process.kill(p, "SIGCONT"); } catch {} }
  for (const p of launched) { for (const d of descendants(p)) { try { process.kill(d.pid, "SIGKILL"); } catch {} } try { process.kill(p, "SIGKILL"); } catch {} }
};
process.on("SIGINT", () => { emergencyCleanup(); process.exit(130); });
process.on("SIGTERM", () => { emergencyCleanup(); process.exit(143); });

/** SIGSTOP root + every descendant (children first, then the browser). */
const freezeTree = (root) => {
  const tree = descendants(root);
  const pids = tree.map((t) => t.pid);
  for (const p of [...pids].reverse()) { try { process.kill(p, "SIGSTOP"); frozenPids.add(p); } catch (e) { say(`  STOP ${p} failed: ${e.message}`); } }
  try { process.kill(root, "SIGSTOP"); frozenPids.add(root); } catch (e) { say(`  STOP root ${root} failed: ${e.message}`); }
  const states = psStates([root, ...pids]);
  return { root, pids, tree: tree.map((t) => ({ pid: t.pid, ppid: t.ppid, depth: t.depth, comm: t.comm.replace(/^.*\//, "") })), states };
};
/** SIGCONT root first, then every descendant; re-enumerates so a pid missed at freeze time is continued too. */
const thawTree = (root, knownPids) => {
  const now = descendants(root).map((t) => t.pid);
  const extra = now.filter((p) => !knownPids.includes(p));
  const all = [...new Set([...knownPids, ...now])];
  try { process.kill(root, "SIGCONT"); } catch (e) { say(`  CONT root ${root} failed: ${e.message}`); }
  for (const p of all) { try { process.kill(p, "SIGCONT"); } catch {} }
  frozenPids.clear();
  return { extraPidsAtThaw: extra, states: psStates([root, ...all]) };
};

/** Fill the receive buffer of a UDP socket (ip:port) with junk so later datagrams are dropped. */
const udpFlood = async (targets, bytesPerTarget = 1_400_000) => {
  const report = [];
  for (const t of targets) {
    const sock = dgram.createSocket(t.ip.includes(":") ? "udp6" : "udp4");
    const junk = Buffer.alloc(1400, 0x5a); // not STUN (first byte 0x5a), not DTLS (>= 20..63), not RTP
    let sent = 0, errors = 0, lastErr = null;
    for (let i = 0; i < Math.ceil(bytesPerTarget / junk.length); i++) {
      await new Promise((r) => sock.send(junk, t.port, t.ip, (e) => { if (e) { errors++; lastErr = e.code ?? e.message; } else sent++; r(); }));
    }
    sock.close();
    report.push({ ip: t.ip, port: t.port, datagrams: sent, bytes: sent * junk.length, errors, lastErr });
  }
  return report;
};

// ---------------------------------------------------------------- static server
const mime = (p) => p.endsWith(".js") ? "text/javascript" : p.endsWith(".wasm") ? "application/wasm" : "text/html";
const server = http.createServer((req, res) => {
  const name = req.url === "/" ? "/app.html" : req.url.split("?")[0];
  try { res.writeHead(200, { "content-type": mime(name), "cache-control": "no-store" }); res.end(readFileSync(path.join(dir, name))); }
  catch { res.writeHead(404); res.end("nf"); }
});
await new Promise((r) => server.listen(HTTP_PORT, r));

// ---------------------------------------------------------------- relay
const relay = spawn("bun", [path.join(dir, "relay.ts")], {
  env: { ...process.env, RELAY_PORT: String(RELAY_PORT), RELAY_PEERID_MODE: PEERID_MODE },
  stdio: ["ignore", "pipe", "pipe"],
});
const onRelayData = (d) => { for (const l of String(d).split("\n")) if (l.trim()) { relayLog.push(`t=${rel()} ${l}`); process.stdout.write("  " + l + "\n"); } };
relay.stdout.on("data", onRelayData);
relay.stderr.on("data", (d) => onRelayData("[relay-err] " + String(d)));
await sleep(900);
const ctl = async (p) => { const r = await fetch(`${ctlUrl}/${p}`, { method: p.startsWith("registry") || p.startsWith("log") ? "GET" : "POST" }); return r.json(); };
const registry = () => ctl("registry");

// ---------------------------------------------------------------- browsers (one Chromium instance per page)
const CHROMIUM_ARGS = ["--no-sandbox", "--disable-features=WebRtcHideLocalIpsWithMdns"];
const launchBrowser = async (name) => {
  const before = new Set(myChromiumChildren());
  const browser = await chromium.launch({ headless: true, args: CHROMIUM_ARGS });
  const fresh = myChromiumChildren().filter((p) => !before.has(p));
  const pid = fresh[0] ?? null;
  if (pid) launched.push(pid);
  const tree = pid ? descendants(pid) : [];
  say(`  launched Chromium for ${name}: root pid=${pid} (${tree.length} descendants: ${tree.map((t) => t.pid).join(",")})`);
  return { browser, pid };
};

const bootPage = async (name) => {
  const { browser, pid } = await launchBrowser(name);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const lines = [];
  pageConsoles.set(name, lines);
  const rec = (kind, text) => { const l = `t=${rel()} [${name} ${kind}] ${text}`; lines.push(l); };
  page.on("pageerror", (e) => { rec("pageerror", e.message); say(`  [${name} pageerror] ${e.message.slice(0, 200)}`); });
  page.on("console", (m) => {
    const t = m.text();
    rec(m.type(), t);
    if (/Error encountered handling the endpoint/.test(t)) return; // RTK Query dev-mode shape warning: noise, kept in the log file
    if (m.type() === "error" || m.type() === "warning" || /handshake|disconnect|Rejected|failed|not-connected|transport|closed|peers|peerConnection|connectWithPeer|WebSocket|restart|ICE/i.test(t))
      say(`  [${name} console.${m.type()}] ${t.slice(0, 220)}`);
  });
  page.on("websocket", (ws) => {
    rec("websocket", `open ${ws.url()}`); say(`  [${name} ws] open ${ws.url().slice(0, 40)}...`);
    ws.on("close", () => { rec("websocket", "close"); say(`  [${name} ws] close`); });
    ws.on("socketerror", (e) => { rec("websocket", `error ${e}`); say(`  [${name} ws] error ${e}`); });
  });
  await page.goto(`http://localhost:${HTTP_PORT}/`);
  await page.waitForFunction("window.__app !== undefined", null, { timeout: 15000 });
  await page.evaluate((u) => window.__app.boot(u), wasmUrl);
  const P = { name, browser, pid, ctx, page, lines, cdp: null, frozen: false };
  P.eval = (fn, arg, ms = 4000) => { if (P.frozen) return Promise.reject(new Error(`${name} is frozen: refusing to evaluate`)); return withTimeout(page.evaluate(fn, arg), ms, `${name}.eval`); };
  // A page chunking/hashing a multi-MiB payload can block its main thread for
  // seconds, so the state dump gets a wider budget when a big transfer is armed.
  P.dump = async () => { try { return await P.eval((r) => window.__app.dump(r), ROOM, TRANSFER ? 15000 : 3000); } catch (e) { return { unreachable: e.message }; } };
  return P;
};

const poll = async (P, fn, arg, ms, label) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) { const v = await P.eval(fn, arg); if (v) return v; await sleep(200); }
  throw new Error(`poll timeout: ${label}`);
};

// A message round trip from -> to, byte-exact, or a failure description.
const roundTrip = async (from, to, tag, ms = 30000) => {
  const text = `${tag} ${from.name}->${to.name} ${Date.now()} ` + "z".repeat(300);
  const started = Date.now();
  try {
    // The app sends on "main" (p2party.com useRoom.tsx:87 selectedChannel default), a channel the SDK
    // itself populates per peer; a harness-only label would be wiped by deletePeer/deleteChannel.
    const sent = await withTimeout(from.eval(([r, t]) => window.__app.send(r, "main", t), [ROOM, text], ms + 1000), ms, `${tag} send`);
    if (!sent.ok) return { ok: false, ms: Date.now() - started, stage: "send", sent };
    const got = await withTimeout(poll(to, ([r, root]) => { const m = window.__app.latestIncoming(r); return m && m.merkleRootHex === root ? m : null; }, [ROOM, sent.merkleRootHex], ms, `${tag} receive`), ms, `${tag} receive`);
    const body = await to.eval((root) => window.__app.read(root), got.merkleRootHex, 10000);
    return { ok: body === text, ms: Date.now() - started, stage: body === text ? "done" : "mismatch", sent };
  } catch (e) { return { ok: false, ms: Date.now() - started, stage: "error", error: e.message }; }
};

// ---------------------------------------------------------------- invariants
const pcTag = (p) => `#${p.id}:${p.withPeerId.slice(0, 8)}:${p.connectionState}/${p.iceConnectionState}/${p.signalingState}:L${p.localFingerprint ?? "-"}:R${p.remoteFingerprint ?? "-"}`;
const evalInvariants = (dA, dB, reg, preFault) => {
  const unknown = { unknown: true };
  if (!dA || !dB || dA.unreachable || dB.unreachable || !dA.room || !dB.room) return { ...unknown, aUnreachable: dA?.unreachable, bUnreachable: dB?.unreachable };
  const side = (dX, dY) => {
    const other = dY.keyPair.publicKey;
    const roster = dX.room.peers.filter((p) => p.peerPublicKey === other);
    const hs = dX.room.handshakeStatusByPeer;
    const cover = dX.room.coverStatusByPeer;
    const ids = new Set(dX.room.peers.map((p) => p.peerId));
    const pcs = dX.pcs.filter((p) => p.withPeerPublicKey === other);
    const live = pcs.filter((p) => p.connectionState !== "closed");
    return {
      roster: roster.map((p) => p.peerId.slice(0, 8)),
      rosterCount: roster.length,
      hsOfRoster: roster.map((p) => hs[p.peerId]?.status ?? "none"),
      authenticated: roster.length === 1 && hs[roster[0].peerId]?.status === "authenticated",
      absent: roster.length === 0,
      hsKeys: Object.keys(hs).map((k) => k.slice(0, 8) + ":" + hs[k].status),
      staleHs: Object.keys(hs).filter((k) => !ids.has(k)).map((k) => k.slice(0, 8)),
      staleCover: Object.keys(cover).filter((k) => !ids.has(k)).map((k) => k.slice(0, 8)),
      livePcs: live.map(pcTag),
      livePcIds: live.map((p) => p.id),
      livePcCount: live.length,
      allPcs: pcs.map((p) => `#${p.id}:${p.connectionState}`),
      rosterInRegistry: dX.room.peers.map((p) => reg.clients.some((c) => c.peerId === p.peerId)),
      ws: `${dX.signalingServer.isConnected ? "up" : "down"}${dX.signalingServer.isVerified ? "+v" : ""}`,
      peerId: dX.keyPair.peerId.slice(0, 8),
      // what p2party.com shows: useRoom.reachablePeers = roster entries whose handshake is authenticated; room.connectedToPeers
      connectedToPeers: dX.room.connectedToPeers,
      reachablePeers: dX.room.peers.filter((p) => hs[p.peerId]?.status === "authenticated").map((p) => p.peerId.slice(0, 8)),
      mainChannelPeerIds: (dX.room.channels.find((c) => c.label === "main")?.peerIds ?? []).map((p) => p.slice(0, 8)),
      liveChannels: live.flatMap((p) => (p.channels ?? []).map((c) => `#${p.id}:${c.label.slice(0, 12)}:${c.readyState}`)),
    };
  };
  const a = side(dA, dB), b = side(dB, dA);
  // DTLS fingerprint agreement between the two live transports (if one each)
  const liveA = dA.pcs.filter((p) => p.withPeerPublicKey === dB.keyPair.publicKey && p.connectionState !== "closed");
  const liveB = dB.pcs.filter((p) => p.withPeerPublicKey === dA.keyPair.publicKey && p.connectionState !== "closed");
  const fpAgree = liveA.length === 1 && liveB.length === 1
    ? liveA[0].localFingerprint === liveB[0].remoteFingerprint && liveB[0].localFingerprint === liveA[0].remoteFingerprint
    : null;
  // I7: pre-fault PC instances are kept or replaced SYMMETRICALLY. A holding its
  // pre-fault instance while B has replaced/dropped its own is the stale-transport reuse.
  const aHoldsPreFault = !!preFault && liveA.length === 1 && liveA[0].id === preFault.A;
  const bHoldsPreFault = !!preFault && liveB.length === 1 && liveB[0].id === preFault.B;
  const I7 = preFault ? !(aHoldsPreFault && !bHoldsPreFault) : true;
  return {
    I1: a.rosterCount === 1 && b.rosterCount === 1,
    I2: (a.authenticated && b.authenticated) || (a.absent && b.absent),
    I3: a.livePcCount === 1 && b.livePcCount === 1,
    I5: a.staleHs.length === 0 && a.staleCover.length === 0 && b.staleHs.length === 0 && b.staleCover.length === 0,
    I6: a.rosterInRegistry.every(Boolean) && b.rosterInRegistry.every(Boolean),
    I7,
    aHoldsPreFault, bHoldsPreFault,
    bothAuthenticated: a.authenticated && b.authenticated,
    fpAgree,
    A: a, B: b,
  };
};

// ---------------------------------------------------------------- run
const results = { scenario, role, n, peerIdMode: PEERID_MODE, socketMode: SOCKET_MODE, procFreezeS: PROC_FREEZE_S, udpFlood: UDP_FLOOD, transferSpec: TRANSFER?.spec ?? null, startedAt: new Date(T0).toISOString(), driverPid: process.pid, browsers: {}, baseline: {}, fault: {}, invariants: {}, samples: [], sends: [], probeSends: [], transfer: null, problems: [] };
let failed = false;
let P1, P2, A, B;

try {
  say(`=== desync probe: scenario=${scenario} role=${role} peerIdMode=${PEERID_MODE}${procFreezeMatch ? ` socket=${SOCKET_MODE} freeze=${PROC_FREEZE_S}s refocus=${REFOCUS_S} udpflood=${UDP_FLOOD}` : ""} run=${n} (two Chromium instances) ===`);
  P1 = await bootPage("P1");
  P2 = await bootPage("P2");
  results.browsers = { P1: { pid: P1.pid, tree: descendants(P1.pid).map((t) => t.pid) }, P2: { pid: P2.pid, tree: descendants(P2.pid).map((t) => t.pid) } };
  for (const P of [P1, P2]) await P.eval((r) => window.__app.watch(r), ROOM);

  // ---- 6. baseline
  say("--- baseline: both connect(), wait mutual authenticated, round trip both ways");
  await P1.eval(([r, w]) => window.__app.connect(r, w, {}), [ROOM, wsUrl], 20000);
  await P2.eval(([r, w]) => window.__app.connect(r, w, {}), [ROOM, wsUrl], 20000);
  await poll(P1, () => window.__app.isVerified(), null, 15000, "P1 verified");
  await poll(P2, () => window.__app.isVerified(), null, 15000, "P2 verified");
  say(`  verified: P1=${(await P1.eval(() => window.__app.myPeerId())).slice(0, 8)} P2=${(await P2.eval(() => window.__app.myPeerId())).slice(0, 8)}`);
  await poll(P1, (r) => window.__app.authenticatedCount(r) >= 1, ROOM, 60000, "P1 sees P2 authenticated");
  await poll(P2, (r) => window.__app.authenticatedCount(r) >= 1, ROOM, 60000, "P2 sees P1 authenticated");
  say("  both sides authenticated");
  const rt12 = await roundTrip(P1, P2, "baseline");
  say(`  round trip P1->P2: ${JSON.stringify(rt12)}`);
  const rt21 = await roundTrip(P2, P1, "baseline");
  say(`  round trip P2->P1: ${JSON.stringify(rt21)}`);
  const d1 = await P1.dump(), d2 = await P2.dump();
  results.baseline = { rt12, rt21, passed: rt12.ok && rt21.ok, P1: { peerId: d1.keyPair.peerId, publicKey: d1.keyPair.publicKey }, P2: { peerId: d2.keyPair.peerId, publicKey: d2.keyPair.publicKey }, invariants: evalInvariants(d1, d2, await registry(), null) };
  if (!results.baseline.passed) throw new Error("baseline round trip failed");
  say(`  BASELINE PASSED (I1=${results.baseline.invariants.I1} I2=${results.baseline.invariants.I2} I3=${results.baseline.invariants.I3} I5=${results.baseline.invariants.I5} I6=${results.baseline.invariants.I6} fpAgree=${results.baseline.invariants.fpAgree})`);

  // ---- 4. role control: A = faulted page
  const initiatorIsP1 = d1.keyPair.publicKey < d2.keyPair.publicKey;
  const initiator = initiatorIsP1 ? P1 : P2;
  const responder = initiatorIsP1 ? P2 : P1;
  A = role === "initiator" ? initiator : responder;
  B = A === P1 ? P2 : P1;
  A.role = role; B.role = role === "initiator" ? "responder" : "initiator";
  const dA0 = A === P1 ? d1 : d2, dB0 = B === P1 ? d1 : d2;
  const preLiveA = dA0.pcs.filter((p) => p.withPeerPublicKey === dB0.keyPair.publicKey && p.connectionState !== "closed");
  const preLiveB = dB0.pcs.filter((p) => p.withPeerPublicKey === dA0.keyPair.publicKey && p.connectionState !== "closed");
  const preFault = { A: preLiveA[0]?.id ?? -1, B: preLiveB[0]?.id ?? -1, Atoken: preLiveA[0]?.token, Btoken: preLiveB[0]?.token, Afp: { local: preLiveA[0]?.localFingerprint, remote: preLiveA[0]?.remoteFingerprint }, Bfp: { local: preLiveB[0]?.localFingerprint, remote: preLiveB[0]?.remoteFingerprint } };
  results.A = { page: A.name, role: A.role, peerId: dA0.keyPair.peerId, publicKey: dA0.keyPair.publicKey, browserPid: A.pid, preFaultPc: preLiveA[0] ? pcTag(preLiveA[0]) : null };
  results.B = { page: B.name, role: B.role, peerId: dB0.keyPair.peerId, publicKey: dB0.keyPair.publicKey, browserPid: B.pid, preFaultPc: preLiveB[0] ? pcTag(preLiveB[0]) : null };
  results.preFault = preFault;
  say(`--- roles: identity initiator=${initiator.name} (pub ${initiator === P1 ? d1.keyPair.publicKey.slice(0, 8) : d2.keyPair.publicKey.slice(0, 8)}); faulted A=${A.name} (${A.role}) peerId=${dA0.keyPair.peerId.slice(0, 8)} browserPid=${A.pid}; untouched B=${B.name} (${B.role}) peerId=${dB0.keyPair.peerId.slice(0, 8)} browserPid=${B.pid}`);
  say(`  pre-fault PC instances: A holds #${preFault.A} (${results.A.preFaultPc}); B holds #${preFault.B} (${results.B.preFaultPc})`);

  // ---- big transfer across the fault: generate + hash the payload now, fire it at the last instant.
  let XF = null;
  if (TRANSFER) {
    const sender = TRANSFER.dir === "A2B" ? A : B;
    const receiver = sender === A ? B : A;
    const id = `${TRANSFER.dir.toLowerCase()}${n}`;
    const t0prep = Date.now();
    const prep = await sender.eval(([i, mib]) => window.__app.prepareTransfer(i, mib), [id, TRANSFER.mib], 180000);
    XF = { id, sender, receiver, bytes: prep.bytes, sha256: prep.sha256, filename: prep.filename, minBytes: Math.floor(prep.bytes * 0.5), verified: null, firstSeen: null, completeAt: null, senderSettled: null, progress: [] };
    results.transfer = {
      spec: TRANSFER.spec, dir: TRANSFER.dir, mib: TRANSFER.mib, id,
      sender: sender.name, senderRole: sender.role, senderIsFaulted: sender === A,
      receiver: receiver.name, receiverRole: receiver.role,
      bytes: prep.bytes, sha256: prep.sha256, filename: prep.filename,
      prepMs: Date.now() - t0prep,
      deadlineS: TRANSFER_DEADLINE_S,
      progress: XF.progress, problems: [],
    };
    say(`--- transfer: prepared ${prep.bytes} B (${TRANSFER.mib} MiB) on ${sender.name}=${sender === A ? "A(faulted)" : "B(untouched)"} ${sender.role} -> ${receiver.name} ${receiver.role}; sha256=${String(prep.sha256).slice(0, 16)}… file=${prep.filename} (prep ${Date.now() - t0prep}ms)`);
  }
  // One transfer sample from whichever side is not frozen.
  const xfSample = async (label) => {
    if (!XF) return null;
    const s = { t: rel(), label };
    if (!XF.sender.frozen) { try { s.sender = await XF.sender.eval((i) => window.__app.transferState(i), XF.id, 8000); } catch (e) { s.sender = { err: e.message }; } }
    if (!XF.receiver.frozen) { try { s.receiver = await XF.receiver.eval(([r, mb]) => window.__app.incomingBig(r, mb), [ROOM, XF.minBytes], 8000); } catch (e) { s.receiver = { err: e.message }; } }
    XF.progress.push(s);
    return s;
  };
  const xfLine = (s) => s ? `xfer[send settled=${s.sender ? s.sender.settled : "?"}${s.sender?.outcome ? "/" + s.sender.outcome : ""}${s.sender?.error ? "(" + String(s.sender.error).slice(0, 60) + ")" : ""} recv=${s.receiver ? (s.receiver.err ? "err" : `${s.receiver.percent}% ${s.receiver.savedSize}/${s.receiver.totalSize} real=${s.receiver.chunksReceivedReal}/${s.receiver.chunksReceivedTotal} rtx=${s.receiver.retransmits}`) : "n/a"}]` : "";

  // ---- 5. fault
  const freeze = async (P, state) => { P.cdp ??= await P.ctx.newCDPSession(P.page); await P.cdp.send("Page.setWebLifecycleState", { state }); P.frozen = state === "frozen"; say(`  CDP Page.setWebLifecycleState(${P.name}, ${state})`); };
  const closeSocket = async (P, peerId) => { const r = await ctl(`close?peerId=${peerId}`); say(`  relay ctl close ${P.name} (${peerId.slice(0, 8)}): ${JSON.stringify(r)}`); return r; };
  const focusReconnect = async (P, firstEvalMs = 15000) => {
    const st = await P.eval(() => ({ c: window.__app.isConnected(), v: window.__app.isVerified() }), null, firstEvalMs);
    say(`  focus-handler emulation on ${P.name}: isConnected=${st.c} isVerified=${st.v}`);
    if (st.c) return `skipped by driver: isConnected=true at focus time (ChatLayout focus handler would not call connect)`;
    const r = await P.eval(([room, w]) => window.__app.focusReconnect(room, w), [ROOM, wsUrl], 30000);
    say(`  ${P.name}.focusReconnect -> ${r}`);
    return r;
  };
  const faultStart = Date.now();
  results.fault.startedAt = rel(faultStart);
  const pcStateOf = async (P, otherPub) => { const d = await P.dump(); return d.pcs ? d.pcs.filter((p) => p.withPeerPublicKey === otherPub).map((p) => `#${p.id}:${p.connectionState}/${p.iceConnectionState}`) : [`unreachable: ${d.unreachable}`]; };
  const bPcCompact = (dB) => (dB.pcs ?? []).filter((p) => p.withPeerPublicKey === dA0.keyPair.publicKey).map((p) => ({ id: p.id, cs: p.connectionState, ics: p.iceConnectionState, ss: p.signalingState, lfp: p.localFingerprint, rfp: p.remoteFingerprint, lufrag: p.localUfrag, rufrag: p.remoteUfrag, channels: p.channels.map((c) => `${c.label.slice(0, 4)}:${c.readyState}`) }));
  const probeDuring = async (label, seconds, { skipA = false, intervalMs = 5000, onSample } = {}) => {
    // While the fault is in effect, sample B (and A unless skipA) every intervalMs.
    const end = Date.now() + seconds * 1000;
    let lastLine = "";
    while (Date.now() < end) {
      const tick = Date.now();
      const bd = await B.dump();
      const b = bPcCompact(bd).map((p) => `#${p.id}:${p.cs}/${p.ics}/${p.ss}`);
      let a = ["(not probed: frozen)"];
      if (!skipA) {
        a = await pcStateOf(A, dB0.keyPair.publicKey);
        if (A.frozen) { results.fault.frozenProbes ??= []; results.fault.frozenProbes.push({ t: rel(), aAnswered: !String(a[0] ?? "").startsWith("unreachable") }); }
      }
      const reg = await registry().catch(() => ({ clients: [] }));
      const sample = { t: rel(tick), sinceFault: +((tick - faultStart) / 1000).toFixed(1), label, B: { ws: bd.signalingServer?.isConnected, roster: bd.room?.peers.map((p) => p.peerId), hs: Object.fromEntries(Object.entries(bd.room?.handshakeStatusByPeer ?? {}).map(([k, v]) => [k.slice(0, 8), v.status])), connecting: bd.room?.connectingToPeers, pcs: bPcCompact(bd) }, A: a, registry: reg.clients?.map((c) => `${c.peerId.slice(0, 8)}:sock${c.sock}:${c.isAlive ? "alive" : "noPong"}`) };
      results.fault.probes ??= []; results.fault.probes.push(sample);
      onSample?.(sample);
      let xf = null;
      if (XF && XF.startedAt) { xf = await xfSample(`${label} +${sample.sinceFault}s`); sample.transfer = xf; }
      const line = `B.pcs(with A)=${JSON.stringify(b)} B.ws=${bd.signalingServer?.isConnected ? "up" : "down"} B.roster=${JSON.stringify(bd.room?.peers.map((p) => p.peerId.slice(0, 8)))} B.hs=${JSON.stringify(sample.B.hs)} relay=${JSON.stringify(sample.registry)} | A.pcs(with B)=${JSON.stringify(a)}`;
      if (line !== lastLine) { lastLine = line; say(`  [${label} +${sample.sinceFault}s] ${line} ${xfLine(xf)}`); }
      await sleep(Math.max(0, Math.min(intervalMs - (Date.now() - tick), end - Date.now())));
    }
  };

  // The transfer is fired HERE: the very next statement of the proc-freeze branch
  // is the SIGSTOP, so handle.done is unsettled and the payload in flight.
  if (XF) {
    const st = await XF.sender.eval(([r, i]) => window.__app.startTransfer(r, "main", i), [ROOM, XF.id], 30000);
    XF.startedAt = Date.now();
    results.transfer.started = { at: rel(XF.startedAt), sinceFaultStart: +((XF.startedAt - faultStart) / 1000).toFixed(2), ...st };
    say(`--- transfer: STARTED on ${XF.sender.name} -> ${XF.receiver.name} ${JSON.stringify(st)}`);
    if (!st.started) { results.transfer.problems.push("startTransfer refused: " + st.error); results.problems.push("transfer never started: " + st.error); }
  }

  say(`--- fault: ${scenario} on ${A.name}`);
  let thawAt = null;
  if (scenario === "baseline") {
    say("  (no fault) observing for stability");
  } else if (scenario === "ws-drop") {
    await closeSocket(A, dA0.keyPair.peerId);
    await probeDuring("ws-drop wait 5s", 5);
  } else if (scenario === "freeze-ws-90") {
    await freeze(A, "frozen");
    await sleep(2000);
    await closeSocket(A, dA0.keyPair.peerId);
    const bh = await ctl(`blackhole?pub=${dA0.keyPair.publicKey.slice(0, 16)}&ms=${88000}`);
    say(`  relay ctl blackhole A identity for 88s (freeze not honoured for WS in headless Chromium): ${JSON.stringify(bh)}`);
    results.fault.note = "freeze-ws-90: CDP frozen, socket closed at +2s, A's identity black-holed at the relay for the remaining 88 s";
    await probeDuring("frozen", 88);
    await freeze(A, "active");
    await sleep(500);
  } else if (scenario === "offline-60") {
    await A.ctx.setOffline(true); say(`  ${A.name}.context.setOffline(true)`);
    await probeDuring("offline", 60);
    await A.ctx.setOffline(false); say(`  ${A.name}.context.setOffline(false)`);
    await sleep(500);
  } else if (scenario === "freeze-20") {
    await freeze(A, "frozen");
    const bh = await ctl(`blackhole?peerId=${dA0.keyPair.peerId}&ms=${20000}`);
    say(`  relay ctl blackhole A for 20s (freeze not honoured for WS in headless Chromium; relay ping/pong must evict): ${JSON.stringify(bh)}`);
    results.fault.note = "freeze-20: CDP frozen + relay black-hole of A for 20 s; eviction comes from the relay's 10s ping/5s pong timer";
    await probeDuring("frozen+blackholed (relay ping/pong must evict)", 20);
    await freeze(A, "active");
    await sleep(500);
  } else if (procFreezeMatch) {
    // ---- "phone asleep": SIGSTOP A's entire Chromium process tree.
    A.frozen = true; // P.eval refuses to touch A from here until thaw
    const fz = freezeTree(A.pid);
    const freezeAt = Date.now();
    results.fault.freeze = { at: rel(freezeAt), browserPid: fz.root, pids: fz.pids, tree: fz.tree, statesAtFreeze: fz.states, seconds: PROC_FREEZE_S, socketMode: SOCKET_MODE };
    const allT = fz.states.every((s) => s.stat.startsWith("T"));
    say(`  SIGSTOP sent to A's tree: root=${fz.root} descendants=[${fz.pids.join(",")}] -> ps stat: ${fz.states.map((s) => `${s.pid}=${s.stat}`).join(" ")} ${allT ? "(ALL STOPPED)" : "(WARNING: not all T)"}`);
    if (!allT) results.problems.push("not every pid of A's tree showed stat T right after SIGSTOP: " + JSON.stringify(fz.states));
    results.fault.note = `proc-freeze-${PROC_FREEZE_S}: A's whole Chromium process tree SIGSTOPped for ${PROC_FREEZE_S} s (JS + WebSocket + ICE all stop); socket=${SOCKET_MODE}${UDP_FLOOD ? "; udpflood (A's UDP receive buffers filled: B's datagrams to A dropped)" : ""}`;
    if (SOCKET_MODE === "keep") {
      const ka = await ctl(`keepalive?peerId=${dA0.keyPair.peerId}&ms=${PROC_FREEZE_S * 1000 + 15000}`);
      results.fault.keepalive = { at: rel(), ...ka };
      say(`  relay ctl keepalive for A (${PROC_FREEZE_S + 15}s: pong-timeout eviction suppressed): ${JSON.stringify(ka)}`);
    }
    if (UDP_FLOOD) {
      const targets = [];
      for (const p of dA0.pcs) if (p.connectionState !== "closed") for (const c of p.localHostCandidates ?? []) if (!targets.some((t) => t.ip === c.ip && t.port === c.port)) targets.push(c);
      const rep = await udpFlood(targets);
      results.fault.udpFlood = { at: rel(), sinceFreeze: +((Date.now() - freezeAt) / 1000).toFixed(1), targets: rep };
      say(`  UDP flood of A's host-candidate sockets (radio-off emulation): ${JSON.stringify(rep)}`);
    }
    const detections = { bDisconnected: null, bFailed: null, bClosed: null, bDeletePeer: null, relayEvict: null, bIceRestartOffer: null };
    const onSample = (s) => {
      const pc = s.B.pcs.find((p) => p.id === preFault.B) ?? s.B.pcs[0];
      if (pc) {
        if (pc.cs === "disconnected" && !detections.bDisconnected) { detections.bDisconnected = s.sinceFault; say(`  >>> B's PC #${pc.id} is DISCONNECTED at freeze+${s.sinceFault}s`); }
        if (pc.cs === "failed" && !detections.bFailed) { detections.bFailed = s.sinceFault; say(`  >>> B's PC #${pc.id} is FAILED at freeze+${s.sinceFault}s`); }
        if (pc.cs === "closed" && !detections.bClosed) { detections.bClosed = s.sinceFault; say(`  >>> B's PC #${pc.id} is CLOSED at freeze+${s.sinceFault}s`); }
        if (pc.ss === "have-local-offer" && !detections.bIceRestartOffer) { detections.bIceRestartOffer = s.sinceFault; say(`  >>> B's PC #${pc.id} has-local-offer (repairIce/ICE restart) at freeze+${s.sinceFault}s`); }
      }
      if (!s.B.roster.includes(dA0.keyPair.peerId) && !detections.bDeletePeer) { detections.bDeletePeer = s.sinceFault; say(`  >>> B's roster no longer lists A (deletePeer) at freeze+${s.sinceFault}s`); }
      const aInRegistry = (s.registry ?? []).some((r) => r.startsWith(dA0.keyPair.peerId.slice(0, 8)));
      if (!aInRegistry && !detections.relayEvict) { detections.relayEvict = s.sinceFault; say(`  >>> relay registry no longer lists A at freeze+${s.sinceFault}s`); }
    };
    const psCheck = () => { const st = psStates([fz.root, ...fz.pids]); results.fault.freeze.psChecks ??= []; results.fault.freeze.psChecks.push({ t: rel(), sinceFreeze: +((Date.now() - freezeAt) / 1000).toFixed(1), states: st.map((s) => `${s.pid}=${s.stat}`) }); return st; };
    if (SOCKET_MODE === "close2s") {
      await probeDuring("frozen(before close2s)", 2, { skipA: true, intervalMs: 1000, onSample });
      results.fault.close2s = await closeSocket(A, dA0.keyPair.peerId);
      psCheck();
      await probeDuring("frozen(socket closed)", Math.max(0, PROC_FREEZE_S - 2 - (Date.now() - freezeAt) / 1000 + 2), { skipA: true, intervalMs: 1000, onSample });
    } else {
      // Mid-freeze ps verification at ~1 s and ~half-way, plus the continuous 1 s B-side sampling.
      await probeDuring("frozen", 1, { skipA: true, intervalMs: 1000, onSample });
      const mid = psCheck(); say(`  ps stat during freeze (+${((Date.now() - freezeAt) / 1000).toFixed(1)}s): ${mid.map((s) => `${s.pid}=${s.stat}`).join(" ")}`);
      const half = Math.max(0, PROC_FREEZE_S / 2 - (Date.now() - freezeAt) / 1000);
      await probeDuring("frozen", half, { skipA: true, intervalMs: 1000, onSample });
      const mid2 = psCheck(); say(`  ps stat during freeze (+${((Date.now() - freezeAt) / 1000).toFixed(1)}s): ${mid2.map((s) => `${s.pid}=${s.stat}`).join(" ")}`);
      await probeDuring("frozen", Math.max(0, PROC_FREEZE_S - (Date.now() - freezeAt) / 1000), { skipA: true, intervalMs: 1000, onSample });
    }
    const lastPs = psCheck();
    const stillT = lastPs.every((s) => s.stat.startsWith("T"));
    say(`  ps stat right before thaw (+${((Date.now() - freezeAt) / 1000).toFixed(1)}s): ${lastPs.map((s) => `${s.pid}=${s.stat}`).join(" ")} ${stillT ? "(ALL STILL STOPPED)" : "(WARNING: something resumed)"}`);
    if (!stillT) results.problems.push("a pid of A's tree was not in stat T right before thaw: " + JSON.stringify(lastPs));
    const th = thawTree(A.pid, fz.pids);
    thawAt = Date.now();
    A.frozen = false;
    results.fault.thaw = { at: rel(thawAt), frozenForS: +((thawAt - freezeAt) / 1000).toFixed(1), extraPidsAtThaw: th.extraPidsAtThaw, statesAtThaw: th.states };
    results.fault.detections = detections;
    say(`  SIGCONT sent (root first, then ${fz.pids.length + th.extraPidsAtThaw.length} descendants; new pids at thaw: ${JSON.stringify(th.extraPidsAtThaw)}) -> ps stat: ${th.states.map((s) => `${s.pid}=${s.stat}`).join(" ")}`);
    say(`  THAW at ${rel(thawAt)} after ${results.fault.thaw.frozenForS}s frozen; B-side detections (s after freeze): ${JSON.stringify(detections)}`);
  }
  if (results.fault.frozenProbes) {
    const answered = results.fault.frozenProbes.filter((p) => p.aAnswered).length;
    results.fault.freezeHonouredForJs = answered === 0;
    say(`  freeze honoured for page JS? ${answered === 0 ? "yes (A never answered while frozen)" : `NO (A answered ${answered}/${results.fault.frozenProbes.length} probes while frozen)`}`);
  }
  results.fault.endedAt = rel();
  // Observation clock: for proc-freeze t=0 is the THAW instant (before the focus emulation).
  const tClear = thawAt ?? Date.now();
  results.fault.clearedAt = rel(tClear);
  const sinceClear = (t = Date.now()) => +((t - tClear) / 1000).toFixed(1);

  if (procFreezeMatch) {
    // Emulate the frontend after thaw: wait 1 s, then the focus handler (connect iff !isConnected).
    await sleep(1000);
    const dAfter = await A.dump();
    results.fault.aAtThawPlus1s = { reachable: !dAfter.unreachable, ws: dAfter.signalingServer ? `${dAfter.signalingServer.isConnected ? "up" : "down"}${dAfter.signalingServer.isVerified ? "+v" : ""}` : dAfter.unreachable, pcs: (dAfter.pcs ?? []).filter((p) => p.withPeerPublicKey === dB0.keyPair.publicKey).map(pcTag), roster: dAfter.room?.peers.map((p) => p.peerId.slice(0, 8)) };
    say(`  [thaw+${sinceClear()}s] A after thaw: ws=${results.fault.aAtThawPlus1s.ws} roster=${JSON.stringify(results.fault.aAtThawPlus1s.roster)} pcs=${JSON.stringify(results.fault.aAtThawPlus1s.pcs)}`);
    results.fault.focusReconnect = { at: sinceClear(), result: await focusReconnect(A) };
    results.fault.pcsAfterFault = { A: await pcStateOf(A, dB0.keyPair.publicKey), B: await pcStateOf(B, dA0.keyPair.publicKey) };
  } else {
    results.fault.aReachableAfter = !(await A.dump()).unreachable;
    results.fault.pcsAfterFault = { A: await pcStateOf(A, dB0.keyPair.publicKey), B: await pcStateOf(B, dA0.keyPair.publicKey) };
    say(`  fault cleared at ${results.fault.endedAt}; PCs now A=${JSON.stringify(results.fault.pcsAfterFault.A)} B=${JSON.stringify(results.fault.pcsAfterFault.B)}`);
    if (scenario !== "baseline") results.fault.focusReconnect = await focusReconnect(A);
  }

  // ---- 7. observe, evaluate invariants every 1 s
  say(`--- observing ${OBSERVE_S}s from t=0=${procFreezeMatch ? "thaw" : "fault cleared"} (invariants every 1s; I4 send attempted once I2 holds${REFOCUS_S ? `; focus handler re-run every ${REFOCUS_S}s` : ""})`);
  const first = { I1: null, I2: null, I3: null, I4: null, I5: null, I6: null, I7: null };
  const last = {};
  let sendInFlight = null, sendAttempts = 0, lastSendAt = 0, i4ok = false;
  let xfDone = !XF; // while a big transfer is unfinished, I4/probe sends are held back
  const PROBE_SEND_AT_S = [10, 60];
  const probeDone = new Set();
  let probeInFlight = null;
  const uiOf = (x) => ({ ws: x.ws, roster: x.roster, hs: x.hsOfRoster, connectedToPeers: x.connectedToPeers, reachablePeers: x.reachablePeers, mainChannelPeerIds: x.mainChannelPeerIds, livePcs: x.livePcs, dcs: x.liveChannels });
  // ONE sendMessage(text, "main", roomId) exactly as useRoom.sendMessage does; report handle.done's outcome
  // (what the sender's UI gets) and whether the receiver ever stored a complete message (polled 8 s).
  const probeSend = async (from, to, tag) => {
    const text = `${tag} ${from.name}->${to.name} ${Date.now()} ` + "p".repeat(200);
    const started = Date.now();
    let sent;
    try { sent = await withTimeout(from.eval(([r, t]) => window.__app.send(r, "main", t), [ROOM, text], 40000), 35000, `${tag} send`); }
    catch (e) { return { sender: from.name, senderSaw: "exception/timeout in driver", error: e.message, ms: Date.now() - started }; }
    const senderSaw = sent.error ? `REJECTED: ${sent.error}` : sent.ok ? "resolved: delivered" : `resolved: 0 delivered`;
    let receiverGot = false, receiverBody = null;
    if (sent.merkleRootHex) {
      try {
        const got = await poll(to, ([r, root]) => { const m = window.__app.latestIncoming(r); return m && m.merkleRootHex === root ? m : null; }, [ROOM, sent.merkleRootHex], 8000, `${tag} receive`);
        receiverGot = !!got;
        if (got) receiverBody = (await to.eval((root) => window.__app.read(root), got.merkleRootHex, 10000)) === text ? "byte-exact" : "mismatch";
      } catch { receiverGot = false; }
    }
    return { sender: from.name, senderSaw, sendMs: sent.ms, outcomes: sent.outcomes, error: sent.error, merkleRoot: (sent.merkleRootHex ?? "").slice(0, 8), receiverStoredMessage: receiverGot, receiverBody, totalMs: Date.now() - started };
  };
  let lastSummary = "";
  let lastRefocus = Date.now();
  const obsEnd = tClear + OBSERVE_S * 1000;
  while (Date.now() < obsEnd) {
    const tick = Date.now();
    const [dA, dB, reg] = await Promise.all([A.dump(), B.dump(), registry()]);
    const inv = evalInvariants(dA, dB, reg, preFault);
    const sample = { t: rel(tick), sinceClear: sinceClear(tick), inv, A: dA, B: dB, registry: { clients: reg.clients.map((c) => ({ peerId: c.peerId, pub: c.publicKey.slice(0, 8), sock: c.sock, verified: c.verified, alive: c.isAlive })) } };
    results.samples.push(sample);
    // ---- big transfer: sample both sides, verify byte-exactness the moment it completes
    if (XF && XF.startedAt) {
      const s = await xfSample(`observe ${sample.sinceClear}s`);
      s.sinceClear = sample.sinceClear;
      sample.transfer = s;
      if (s.sender && s.sender.settled && !XF.senderSettled) {
        XF.senderSettled = { sinceClear: sample.sinceClear, outcome: s.sender.outcome, sendMs: s.sender.ms, error: s.sender.error, merkleRoot: String(s.sender.merkleRootHex ?? "").slice(0, 16), outcomes: s.sender.outcomes };
        results.transfer.senderSettled = XF.senderSettled;
        say(`  [${sample.sinceClear}s] TRANSFER sender handle.done SETTLED: ${JSON.stringify(XF.senderSettled)}`);
      }
      if (s.receiver && !s.receiver.err && !XF.firstSeen) {
        XF.firstSeen = sample.sinceClear;
        results.transfer.receiverFirstSeenSinceClear = sample.sinceClear;
        say(`  [${sample.sinceClear}s] TRANSFER receiver has a record: ${JSON.stringify(s.receiver)}`);
      }
      if (s.receiver && !s.receiver.err && s.receiver.complete && !XF.verified) {
        XF.completeAt = sample.sinceClear;
        const v = await XF.receiver.eval((root) => window.__app.verifyReceived(root), s.receiver.merkleRootHex, 180000).catch((e) => ({ error: e.message }));
        XF.verified = v;
        const hashMatch = v.sha256 === XF.sha256 && v.size === XF.bytes;
        XF.hashMatch = hashMatch;
        results.transfer.receiverCompleteSinceClear = sample.sinceClear;
        results.transfer.verify = { ...v, expectedSha256: XF.sha256, expectedBytes: XF.bytes, hashMatch };
        results.transfer.receiverTelemetry = { chunksReceivedReal: s.receiver.chunksReceivedReal, chunksReceivedTotal: s.receiver.chunksReceivedTotal, retransmits: s.receiver.retransmits, totalChunks: s.receiver.totalChunks, chunksCreated: s.receiver.chunksCreated, savedSize: s.receiver.savedSize, totalSize: s.receiver.totalSize };
        say(`  [${sample.sinceClear}s] TRANSFER receiver COMPLETE: ${v.size} B sha256=${String(v.sha256).slice(0, 16)}… expected=${XF.sha256.slice(0, 16)}… -> ${hashMatch ? "BYTE-EXACT" : "MISMATCH"} | telemetry real=${v.chunksReceivedReal}/${v.chunksReceivedTotal} retransmits=${v.retransmits}`);
        if (!hashMatch) results.transfer.problems.push(`receiver payload not byte-exact: got ${v.size}B/${String(v.sha256).slice(0, 16)} want ${XF.bytes}B/${XF.sha256.slice(0, 16)}${v.error ? " readMessage error: " + v.error : ""}`);
      }
      if (!xfDone && XF.verified && XF.senderSettled) { xfDone = true; say(`  [${sample.sinceClear}s] TRANSFER finished (receiver verified + sender settled); I4/probe sends released`); }
      if (!xfDone && sample.sinceClear >= TRANSFER_DEADLINE_S) {
        xfDone = true;
        results.transfer.deadlineExceeded = true;
        results.transfer.problems.push(`not finished within ${TRANSFER_DEADLINE_S}s of t=0 (receiverVerified=${!!XF.verified} senderSettled=${!!XF.senderSettled})`);
        say(`  [${sample.sinceClear}s] TRANSFER DEADLINE ${TRANSFER_DEADLINE_S}s EXCEEDED: receiverVerified=${!!XF.verified} senderSettled=${!!XF.senderSettled}; I4/probe sends released`);
      }
    }
    if (!inv.unknown) {
      for (const k of ["I1", "I2", "I3", "I5", "I6", "I7"]) { if (inv[k] && first[k] === null) first[k] = { sinceClear: sample.sinceClear, at: sample.t }; last[k] = inv[k]; }
      // I4: once both authenticated, try a round trip both ways (retry up to 3x, 15 s apart)
      if (xfDone && inv.bothAuthenticated && !i4ok && !sendInFlight && sendAttempts < 3 && tick - lastSendAt > 15000) {
        sendAttempts++; lastSendAt = tick;
        const attemptStart = tick;
        say(`  [${sample.sinceClear}s] I2 holds -> I4 attempt ${sendAttempts}: round trips A->B and B->A`);
        sendInFlight = (async () => {
          const ab = await roundTrip(A, B, `I4#${sendAttempts}`, 30000);
          const ba = await roundTrip(B, A, `I4#${sendAttempts}`, 30000);
          const ok = ab.ok && ba.ok;
          results.sends.push({ attempt: sendAttempts, startedAt: rel(attemptStart), sinceClear: sinceClear(attemptStart), ab, ba, ok });
          say(`  [${sinceClear()}s] I4 attempt ${sendAttempts}: A->B ${ab.ok ? "OK" : "FAIL"} (${ab.ms}ms ${ab.stage ?? ""} ${ab.error ?? ""} ${ab.sent && !ab.ok ? JSON.stringify(ab.sent).slice(0, 200) : ""}) | B->A ${ba.ok ? "OK" : "FAIL"} (${ba.ms}ms ${ba.stage ?? ""} ${ba.error ?? ""} ${ba.sent && !ba.ok ? JSON.stringify(ba.sent).slice(0, 200) : ""})`);
          if (ok && !i4ok) { i4ok = true; first.I4 = { sinceClear: sinceClear(), at: rel() }; }
          sendInFlight = null;
        })();
      }
      // Probe sends in the asymmetric window (A authenticated for B, B not for A): one from each side at ~10 s and ~60 s.
      const asym = inv.A.authenticated && !inv.B.authenticated;
      for (const at of PROBE_SEND_AT_S) {
        if (xfDone && asym && !probeInFlight && sample.sinceClear >= at && !probeDone.has(at)) {
          probeDone.add(at);
          say(`  [${sample.sinceClear}s] asymmetric window (A authenticated for B, B ${JSON.stringify(inv.B.hsOfRoster)}) -> PROBE SENDS (~${at}s): A->B then B->A on "main"`);
          probeInFlight = (async () => {
            const rec = { scheduledAt: at, startedSinceClear: sample.sinceClear, before: { A: uiOf(inv.A), B: uiOf(inv.B) } };
            rec.AtoB = await probeSend(A, B, `probe@${at}s`);
            say(`  [${sinceClear()}s] PROBE A->B: ${JSON.stringify(rec.AtoB)}`);
            rec.BtoA = await probeSend(B, A, `probe@${at}s`);
            say(`  [${sinceClear()}s] PROBE B->A: ${JSON.stringify(rec.BtoA)}`);
            const [pa, pb] = await Promise.all([A.dump(), B.dump()]);
            const pinv = evalInvariants(pa, pb, await registry(), preFault);
            rec.after = pinv.unknown ? pinv : { sinceClear: sinceClear(), A: uiOf(pinv.A), B: uiOf(pinv.B), I1: pinv.I1, I2: pinv.I2, I3: pinv.I3 };
            say(`  [${sinceClear()}s] after probes: A ${JSON.stringify(rec.after.A)} | B ${JSON.stringify(rec.after.B)}`);
            results.probeSends.push(rec);
            probeInFlight = null;
          })();
        }
      }
      const summary = `I1=${inv.I1} I2=${inv.I2} I3=${inv.I3} I5=${inv.I5} I6=${inv.I6} I7=${inv.I7}(A${inv.aHoldsPreFault ? "=pre" : "!=pre"},B${inv.bHoldsPreFault ? "=pre" : "!=pre"}) fp=${inv.fpAgree} | A[${inv.A.peerId} ws=${inv.A.ws} roster=${JSON.stringify(inv.A.roster)} hs=${JSON.stringify(inv.A.hsOfRoster)} pcs=${JSON.stringify(inv.A.livePcs)} all=${JSON.stringify(inv.A.allPcs)} staleHs=${JSON.stringify(inv.A.staleHs)}] B[${inv.B.peerId} ws=${inv.B.ws} roster=${JSON.stringify(inv.B.roster)} hs=${JSON.stringify(inv.B.hsOfRoster)} pcs=${JSON.stringify(inv.B.livePcs)} all=${JSON.stringify(inv.B.allPcs)} staleHs=${JSON.stringify(inv.B.staleHs)}] | UI A{connectedToPeers=${inv.A.connectedToPeers} reachable=${JSON.stringify(inv.A.reachablePeers)} mainCh=${JSON.stringify(inv.A.mainChannelPeerIds)} dcs=${JSON.stringify(inv.A.liveChannels)}} B{connectedToPeers=${inv.B.connectedToPeers} reachable=${JSON.stringify(inv.B.reachablePeers)} mainCh=${JSON.stringify(inv.B.mainChannelPeerIds)} dcs=${JSON.stringify(inv.B.liveChannels)}}`;
      if (summary !== lastSummary) { lastSummary = summary; say(`  [${sample.sinceClear}s] ${summary}`); }
    } else {
      say(`  [${sample.sinceClear}s] invariants unknown: A=${dA.unreachable ?? (dA.room ? "ok" : "no room")} B=${dB.unreachable ?? (dB.room ? "ok" : "no room")}`);
    }
    if (REFOCUS_S && procFreezeMatch && tick - lastRefocus >= REFOCUS_S * 1000) {
      lastRefocus = tick;
      const r = await focusReconnect(A, 5000).catch((e) => "error: " + e.message);
      results.fault.refocus ??= []; results.fault.refocus.push({ sinceClear: sinceClear(), result: r });
    }
    await sleep(Math.max(0, 1000 - (Date.now() - tick)));
  }
  if (sendInFlight) await withTimeout(sendInFlight, 65000, "final I4").catch(() => {});
  if (probeInFlight) await withTimeout(probeInFlight, 65000, "final probe").catch(() => {});
  if (!i4ok && first.I2 === null) results.problems.push("I4 never attempted: I2 (both authenticated) never held during observation");
  const fin = results.samples.at(-1)?.inv;
  results.invariants = { firstSatisfiedSinceClear: Object.fromEntries(Object.entries(first).map(([k, v]) => [k, v ? v.sinceClear : "never"])), heldAtEnd: { ...last, I4: i4ok }, finalSample: fin };
  say(`--- RESULT first-satisfied (s after t=0): ${JSON.stringify(results.invariants.firstSatisfiedSinceClear)}; held at end: ${JSON.stringify(results.invariants.heldAtEnd)}`);
  if (fin && !fin.unknown) {
    const aLive = fin.A.livePcIds, bLive = fin.B.livePcIds;
    say(`--- FINAL: A roster=${JSON.stringify(fin.A.roster)} hs=${JSON.stringify(fin.A.hsOfRoster)} livePC=${JSON.stringify(aLive)} (pre-fault #${preFault.A}${fin.aHoldsPreFault ? " STILL HELD" : ""}) | B roster=${JSON.stringify(fin.B.roster)} hs=${JSON.stringify(fin.B.hsOfRoster)} livePC=${JSON.stringify(bLive)} (pre-fault #${preFault.B}${fin.bHoldsPreFault ? " STILL HELD" : ""}) | fpAgree=${fin.fpAgree}`);
  }

  // ---- big transfer verdict + data-channel accounting
  if (XF) {
    const last = await xfSample("final").catch(() => null);
    const grabDc = async (P) => { try { return await P.eval(() => window.__app.dcStats(), null, 15000); } catch (e) { return { err: e.message }; } };
    results.transfer.dataChannels = { A: await grabDc(A), B: await grabDc(B) };
    results.transfer.senderMessageRow = XF.sender.frozen ? null : await XF.sender.eval(([r, mb]) => window.__app.outgoingBig(r, mb), [ROOM, XF.minBytes], 10000).catch((e) => ({ err: e.message }));
    if (!results.transfer.senderSettled && last?.sender?.settled)
      results.transfer.senderSettled = { sinceClear: sinceClear(), outcome: last.sender.outcome, sendMs: last.sender.ms, error: last.sender.error, outcomes: last.sender.outcomes };
    const st = results.transfer.senderSettled;
    const delivered = !!st && st.outcome === "resolved" && (st.outcomes ?? []).some((o) => o.status === "delivered");
    const inTime = results.transfer.receiverCompleteSinceClear !== undefined && results.transfer.receiverCompleteSinceClear <= TRANSFER_DEADLINE_S;
    results.transfer.pass = !!(XF.hashMatch && inTime && delivered);
    results.transfer.verdict = {
      receiverByteExact: !!XF.hashMatch,
      receiverCompleteSinceClear: results.transfer.receiverCompleteSinceClear ?? null,
      withinDeadline: inTime,
      senderResolvedDelivered: delivered,
      senderOutcome: st ? (st.outcome === "resolved" ? `resolved (${(st.outcomes ?? []).map((o) => o.status).join(",") || "no outcomes"})` : `rejected: ${st.error}`) : "NEVER SETTLED",
      senderSettledSinceClear: st?.sinceClear ?? null,
      chunks: results.transfer.receiverTelemetry ?? null,
    };
    say(`--- TRANSFER ${results.transfer.pass ? "PASS" : "FAIL"} ${TRANSFER.spec} (${XF.sender.name}=${XF.sender === A ? "A" : "B"} -> ${XF.receiver.name}): ${JSON.stringify(results.transfer.verdict)}`);
    say(`--- TRANSFER data channels: A=${JSON.stringify(results.transfer.dataChannels.A?.perPc ?? results.transfer.dataChannels.A)} | B=${JSON.stringify(results.transfer.dataChannels.B?.perPc ?? results.transfer.dataChannels.B)}`);
    if (!results.transfer.pass) { failed = true; results.problems.push("TRANSFER FAILED: " + JSON.stringify(results.transfer.verdict)); }
  }

} catch (e) {
  failed = true;
  results.problems.push("DRIVER FAILURE: " + e.message);
  say("DRIVER FAILURE: " + e.message);
  console.error(e);
} finally {
  // make sure nothing is left stopped, whatever happened
  for (const p of frozenPids) { try { process.kill(p, "SIGCONT"); } catch {} }
  frozenPids.clear();
  if (A) A.frozen = false;
  // evidence dumps (also on failure)
  const EA = A ?? P1, EB = B ?? P2;
  const grab = async (P, fn, label) => { try { return await withTimeout(P.page.evaluate(fn), 15000, label); } catch (e) { return String(e); } };
  try {
    if (EA) results.timelines = { A: await grab(EA, () => window.__app.timeline(), "A.timeline"), B: EB ? await grab(EB, () => window.__app.timeline(), "B.timeline") : null };
    if (EA) results.pcEvents = { A: await grab(EA, () => window.__app.pcEvents(), "A.pcEvents"), B: EB ? await grab(EB, () => window.__app.pcEvents(), "B.pcEvents") : null };
    if (EA) results.pageConsoles = { A: await grab(EA, () => ({ t0: window.__pageT0, lines: window.__consoleLines ? window.__consoleLines() : [] }), "A.console"), B: EB ? await grab(EB, () => ({ t0: window.__pageT0, lines: window.__consoleLines ? window.__consoleLines() : [] }), "B.console") : null };
    if (EA) results.finalDumps = { A: await grab(EA, () => window.__app.dump("de".repeat(32)), "A.dump"), B: EB ? await grab(EB, () => window.__app.dump("de".repeat(32)), "B.dump") : null };
    results.registryAtEnd = await registry().catch((e) => String(e));
    // Harness diagnostics: pending RTK mutations (a queryFn that never resolved), mutex registry, DB round trip.
    if (EA) results.diag = { A: await grab(EA, () => window.__app.diag("de".repeat(32)), "A.diag"), B: EB ? await grab(EB, () => window.__app.diag("de".repeat(32)), "B.diag") : null };
    if (results.diag) say(`--- DIAG A=${JSON.stringify(results.diag.A)} | B=${JSON.stringify(results.diag.B)}`);
  } catch (e) { results.problems.push("evidence dump failed: " + e.message); }
  results.relayLog = relayLog;
  results.consoles = { A: A ? pageConsoles.get(A.name) : pageConsoles.get("P1"), B: B ? pageConsoles.get(B.name) : pageConsoles.get("P2"), names: { A: A?.name, B: B?.name } };
  results.driverLog = logLines;
  writeFileSync(outBase + ".json", JSON.stringify(results, null, 1));
  // In-page console lines re-based onto the driver clock (page Date.now() is wall clock, same host).
  const inPage = (side) => { const c = results.pageConsoles?.[side]; if (!c || typeof c === "string" || !c.lines) return [`(unavailable: ${typeof c === "string" ? c : "no data"})`]; return c.lines.map((l) => `t=${rel(l.t)} [${l.kind}] ${l.text}`); };
  const text = [
    `# ${scenario} role=${role} peerIdMode=${PEERID_MODE}${procFreezeMatch ? ` socket=${SOCKET_MODE} freeze=${PROC_FREEZE_S}s` : ""} run=${n}`,
    `A=${A?.name} (${A?.role}) browserPid=${A?.pid} B=${B?.name} (${B?.role}) browserPid=${B?.pid}`,
    "", "## driver", ...logLines,
    "", "## relay", ...relayLog,
    "", `## console ${A?.name ?? "P1"} (A) -- driver-side receive timestamps (a frozen page's lines all arrive at thaw)`, ...(results.consoles.A ?? []),
    "", `## console ${B?.name ?? "P2"} (B) -- driver-side receive timestamps`, ...(results.consoles.B ?? []),
    "", `## in-page console ${A?.name ?? "P1"} (A) -- page's own Date.now(), re-based to driver clock`, ...inPage("A"),
    "", `## in-page console ${B?.name ?? "P2"} (B) -- page's own Date.now(), re-based to driver clock`, ...inPage("B"),
  ].join("\n");
  writeFileSync(outBase + ".log", text);
  say(`wrote ${outBase}.json / .log`);
  for (const P of [P1, P2]) if (P) await withTimeout(P.browser.close(), 10000, "browser.close").catch(() => { for (const d of descendants(P.pid)) { try { process.kill(d.pid, "SIGKILL"); } catch {} } try { process.kill(P.pid, "SIGKILL"); } catch {} });
  relay.kill("SIGKILL");
  server.close();
}
process.exit(failed ? 1 : 0);
