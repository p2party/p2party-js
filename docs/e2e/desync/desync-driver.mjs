// Desync probe driver: real p2party app stack (Redux + IndexedDB + WebRTC) in
// two headless-Chromium INSTANCES (one chromium.launch() per page, each its own
// process tree), a Bun signaling relay with fault-injection hooks. One command
// per scenario:
//
//   PLAYWRIGHT_BROWSERS_PATH=$HOME/Library/Caches/ms-playwright \
//   node desync-driver.mjs <scenario> <role> [--peerid=stable|fresh] [--n=1] [--observe=120] [--socket=evict|close2s] [--refocus=0]
//                                           [--mode=immediate|scheduled|pin] [--cadence=<ms>] [--cpuslow=<A|B>:<rate>]
//                                           [--pin=<hex>] [--pinb=<hex>] [--port=5810]
//
//   scenario: baseline | ws-drop | ws-drop-nofocus | pin-typo | cover-stall | freeze-ws-90 | offline-60 | freeze-20 | proc-freeze-<seconds>
//   role:     initiator | responder   (which identity role the FAULTED page A has;
//             Ed25519 role = lexically lower hex pubkey is the initiator)
//   FOCUS EMULATION: after the fault clears, every scenario except "baseline"
//             and "ws-drop-nofocus" runs window.__app.focusReconnect(), which is
//             the site's ChatLayout focus/visibilitychange/pageshow/online
//             handler. That poke is the reason the recorded ws-drop pass was
//             ever a pass: a FOREGROUND desktop tab whose socket dies gets none
//             of those events, so nothing calls connect. "ws-drop-nofocus" is
//             identical to "ws-drop" with the poke withheld, and is therefore
//             the arm that tests the SDK's own C4 reconnect ladder rather than
//             the driver's.
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
//             "stranded": keepalive AND blackhole A both ways until 40 s past the
//             thaw, so A stays registered while no signalling reaches it in either
//             direction. Both sides end with healthy sockets and empty rosters and
//             no inbound frame can start the recovery, which is what exercises the
//             client's roster reconciliation and its heartbeat watchdog.
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
//   --mode:   room policy both pages connect() with. "immediate" (default) is the
//             stock policy; "scheduled" turns on the scheduled cover scheduler --
//             the arm "cover-stall" needs; "pin" turns on PIN key confirmation.
//   --cadence=<ms>: the scheduled cover cadence (only meaningful with
//             --mode=scheduled, and REFUSED otherwise). The slot spacing is
//             cadence / (lanes x frames) = cadence/32, and the runtime's drift
//             tolerance is min(floor(spacing) - 1, 500) ms, so the cadence is how a
//             scenario chooses a tolerance it can deliberately overrun.
//   --cpuslow=<A|B>:<rate>: CDP Emulation.setCPUThrottlingRate on that page, applied
//             at the last instant before the fault and released 20 s after t=0. It
//             is what skews two otherwise-identical loopback machines so one side's
//             persist lands last (the C7 window).
//   --pin=<hex> / --pinb=<hex>: pin-typo only. The two PINs P1 and P2 join with;
//             they differ by default so key confirmation fails by construction.
//   --port=<n>: base TCP port (static server = n, relay = n+1). Default 5810.
//
//   scenario pin-typo:    both pages join the same PIN room with DIFFERENT PINs, so
//             both fail key confirmation. C2: a terminal handshake failure must stop
//             the re-dial loop -- exactly one transport per side and one join-time
//             peers request, with status=failed/reason=pin-mismatch left on the
//             roster for a UI to show. No fault is injected; the loop IS the bug.
//   scenario cover-stall: C5. A 1.5 s main-thread stall on A spanning a scheduled
//             cover boundary. The stalled boundary timer used to park the scheduler
//             in "suspended" with nothing armed to leave it, while both handshakes
//             still read "authenticated" -- the edge looks perfect while cover is
//             dead. Requires --mode=scheduled.
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
import { STATE_INVARIANTS, transportFingerprintAgreement, endInvariantState, invariantProblems, diagnosticProblems } from "./desync-verdict.mjs";

process.env.PLAYWRIGHT_BROWSERS_PATH ??= path.join(os.homedir(), "Library/Caches/ms-playwright");
const pw = await import("~/Desktop/@p2party/p2party.com/node_modules/playwright-core/index.js");
const { chromium } = pw.default ?? pw;

// ---------------------------------------------------------------- args
const argv = process.argv.slice(2);
const positional = argv.filter((a) => !a.startsWith("--"));
const flags = Object.fromEntries(argv.filter((a) => a.startsWith("--")).map((a) => { const [k, v] = a.slice(2).split("="); return [k, v ?? "1"]; }));
const die = (msg) => { console.error(msg); process.exit(2); };

// Every flag this driver understands. An argument that is not on this list is
// REFUSED rather than ignored. Three separate tasks independently discovered that
// --mode, --cadence and --cpuslow were dropped on the floor: each of their harness
// steps applied no configuration and no throttling at all and then reported a
// confident pass. A harness that silently discards an argument is worse than one
// that refuses it, so the allow-list is closed and typos exit 2.
const KNOWN_FLAGS = ["peerid", "n", "observe", "socket", "refocus", "udpflood", "transfer", "transferdeadline", "mode", "cadence", "cpuslow", "pin", "pinb", "port"];
const unknownFlags = Object.keys(flags).filter((k) => !KNOWN_FLAGS.includes(k));
if (unknownFlags.length) die(`unknown flag(s) ${unknownFlags.map((f) => "--" + f).join(" ")}; known: ${KNOWN_FLAGS.map((f) => "--" + f).join(" ")}`);
if (positional.length > 2) die(`unexpected positional argument(s): ${positional.slice(2).join(" ")} (usage: <scenario> <role> [--flags])`);

const scenario = positional[0] ?? "baseline";
const role = positional[1] ?? "initiator";
const SCENARIOS = ["baseline", "two-tabs", "ws-drop", "ws-drop-nofocus", "pin-typo", "cover-stall", "freeze-ws-90", "offline-60", "freeze-20"];
const procFreezeMatch = scenario.match(/^proc-freeze-(\d+)$/);
const PROC_FREEZE_S = procFreezeMatch ? Number(procFreezeMatch[1]) : 0;
if (!SCENARIOS.includes(scenario) && !procFreezeMatch) die(`unknown scenario ${scenario}; one of ${SCENARIOS.join("|")}|proc-freeze-<seconds>`);
if (!["initiator", "responder"].includes(role)) die("role must be initiator|responder");

// A numeric flag whose value did not parse used to become NaN and then silently
// disable the very thing it configures: `--observe=x` made `Date.now() < obsEnd`
// false on the first iteration, so the observation window never ran and the run
// still exited 0. Refuse the value instead of quietly reinterpreting it.
const num = (name, dflt) => {
  if (flags[name] === undefined) return dflt;
  const v = Number(flags[name]);
  if (!Number.isFinite(v)) die(`--${name} must be a number, got "${flags[name]}"`);
  return v;
};
const oneOf = (name, allowed, dflt) => {
  if (flags[name] === undefined) return dflt;
  if (!allowed.includes(flags[name])) die(`--${name} must be one of ${allowed.join("|")}, got "${flags[name]}"`);
  return flags[name];
};
const bool = (name, dflt) => {
  if (flags[name] === undefined) return dflt;
  if (["1", "true", "yes"].includes(flags[name])) return true;
  if (["0", "false", "no"].includes(flags[name])) return false;
  return die(`--${name} must be 1|0|true|false, got "${flags[name]}"`);
};
// A flag whose scenario cannot act on it is a lie about what the run did.
const onlyFor = (name, ok, why) => { if (flags[name] !== undefined && !ok) die(`--${name} has no effect for scenario "${scenario}": ${why}`); };

const PEERID_MODE = oneOf("peerid", ["stable", "fresh"], "stable");
const OBSERVE_S = num("observe", 120);
if (OBSERVE_S <= 0) die(`--observe must be > 0 seconds, got "${flags.observe}"`);
onlyFor("socket", !!procFreezeMatch, "the socket policy is applied inside the proc-freeze arm only");
onlyFor("refocus", !!procFreezeMatch, "the periodic focus-handler re-run is armed inside the proc-freeze arm only");
onlyFor("udpflood", !!procFreezeMatch, "the UDP receive-buffer flood is fired right after the SIGSTOP, which only proc-freeze does");
const SOCKET_MODE = oneOf("socket", ["evict", "close2s", "keep", "stranded"], "evict");
const REFOCUS_S = num("refocus", 0);
if (REFOCUS_S < 0) die(`--refocus must be >= 0 seconds (0 = off), got "${flags.refocus}"`);
const UDP_FLOOD = bool("udpflood", false);
const TRANSFER = (() => {
  if (!flags.transfer) return null;
  const m = String(flags.transfer).match(/^(A2B|B2A):([0-9]+(?:\.[0-9]+)?)$/i);
  if (!m) die(`--transfer must be <A2B|B2A>:<MiB>, got "${flags.transfer}"`);
  return { spec: String(flags.transfer), dir: m[1].toUpperCase(), mib: Number(m[2]) };
})();
// Verification budget for the big transfer, measured from t=0 (thaw / fault cleared).
const TRANSFER_DEADLINE_S = num("transferdeadline", 90);
onlyFor("transferdeadline", !!TRANSFER, "there is no transfer to time without --transfer");
// Room policy both pages connect() with. "scheduled" is the arm the cover
// scenarios need: the cadence sets the slot spacing (cadence / (lanes*frames)),
// and the runtime's drift tolerance is min(floor(spacing) - 1, 500) ms.
const CONNECT_MODE = oneOf("mode", ["immediate", "scheduled", "pin"], "immediate");
if (scenario === "pin-typo" && flags.mode !== undefined) die(`--mode is fixed to "pin" by the pin-typo scenario; drop it (use --pin/--pinb to choose the two PINs)`);
if (scenario === "cover-stall" && CONNECT_MODE !== "scheduled") die(`cover-stall needs --mode=scheduled: with the immediate cover preset there is no boundary timer to overrun, so the run would pass vacuously`);
const CONNECT_CADENCE_MS = num("cadence", undefined);
if (CONNECT_CADENCE_MS !== undefined && CONNECT_MODE !== "scheduled") die(`--cadence only configures the scheduled cover preset; got --mode=${CONNECT_MODE}`);
if (CONNECT_CADENCE_MS !== undefined && CONNECT_CADENCE_MS <= 0) die(`--cadence must be > 0 ms, got "${flags.cadence}"`);
const CONNECT_OPTS = { mode: CONNECT_MODE, ...(CONNECT_CADENCE_MS === undefined ? {} : { coverCadenceMs: CONNECT_CADENCE_MS }) };
// pin-typo: the two pages join the same PIN room with DIFFERENT PINs, so both
// sides fail key confirmation by construction. Overridable so a run can also
// pin-typo with matching PINs as a control.
const pinHex = (name, dflt) => {
  if (flags[name] === undefined) return dflt;
  if (!/^([0-9a-fA-F]{2})+$/.test(flags[name])) die(`--${name} must be an even-length hex string, got "${flags[name]}"`);
  return String(flags[name]).toLowerCase();
};
onlyFor("pin", scenario === "pin-typo", "only pin-typo connects with a PIN");
onlyFor("pinb", scenario === "pin-typo", "only pin-typo connects with a PIN");
const PIN_A = pinHex("pin", "01020304");
const PIN_B = pinHex("pinb", "01020305");
// CDP CPU throttling on one page: the only way to skew two identical loopback
// machines so one side's persist reliably lands last.
const CPU_SLOW = (() => {
  if (flags.cpuslow === undefined) return null;
  const m = String(flags.cpuslow).match(/^(A|B):([0-9]+(?:\.[0-9]+)?)$/i);
  if (!m) return die(`--cpuslow must be <A|B>:<rate>, got "${flags.cpuslow}"`);
  const rate = Number(m[2]);
  if (!(rate >= 1)) die(`--cpuslow rate must be >= 1 (1 = no throttling), got "${m[2]}"`);
  return { page: m[1].toUpperCase(), rate };
})();
// Released this many seconds after t=0, so the recovery is measured unthrottled.
const CPU_SLOW_RELEASE_S = 20;

const dir = path.dirname(fileURLToPath(import.meta.url));
const runsDir = path.join(dir, "..", "runs");
mkdirSync(runsDir, { recursive: true });
let n = num("n", 0);
if (!Number.isInteger(n) || n < 0) die(`--n must be a non-negative integer run number, got "${flags.n}"`);
if (!n) { n = 1; while (existsSync(path.join(runsDir, `${scenario}-${role}-${n}.json`))) n++; }
const outBase = path.join(runsDir, `${scenario}-${role}-${n}`);

// Several agents share this laptop, so the port pair is selectable. Nothing below
// 5000 may ever be bound here (5432 is a live PostgreSQL).
const PORT_BASE = num("port", 5810);
if (!Number.isInteger(PORT_BASE) || PORT_BASE < 5001 || PORT_BASE > 65534) die(`--port must be an integer in 5001..65534 (never below 5000 on this host), got "${flags.port}"`);
const HTTP_PORT = PORT_BASE;
const RELAY_PORT = PORT_BASE + 1;
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
let ownedRelay = null;
const emergencyCleanup = () => {
  ownedRelay?.kill("SIGKILL");
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
const relay = ownedRelay = spawn("bun", [path.join(dir, "relay.ts")], {
  env: { ...process.env, RELAY_PORT: String(RELAY_PORT), RELAY_PEERID_MODE: PEERID_MODE },
  stdio: ["ignore", "pipe", "pipe"],
});
const onRelayData = (d) => { for (const l of String(d).split("\n")) if (l.trim()) { relayLog.push(`t=${rel()} ${l}`); process.stdout.write("  " + l + "\n"); } };
relay.stdout.on("data", onRelayData);
relay.stderr.on("data", (d) => onRelayData("[relay-err] " + String(d)));
try {
  // Never query a listener left by a different run if our relay failed to bind.
  // Waiting alone previously made EADDRINUSE look like a valid fixture.
  await Promise.race([
    sleep(900),
    new Promise((_, reject) => {
      relay.once("error", reject);
      relay.once("exit", (code, signal) => reject(new Error(`owned relay exited during startup: code=${code} signal=${signal}`)));
    }),
  ]);
} catch (error) {
  emergencyCleanup();
  server.close();
  throw error;
}
const ctl = async (p) => { const r = await fetch(`${ctlUrl}/${p}`, { method: p.startsWith("registry") || p.startsWith("log") ? "GET" : "POST" }); return r.json(); };
const registry = () => ctl("registry");
/**
 * How many `peers` requests each identity has sent to the relay. The relay logs
 * one line per request as `peers <short(peerId)>->srv room=… members=[…]`
 * (relay.ts:392). Before C2 a mismatched-PIN pair produced tens of these — one
 * per re-dial — because every failed handshake tore the edge down and asked for
 * the roster again.
 */
const peersFrameCounts = async (peerIds) => {
  const lines = await ctl("log").catch(() => []);
  const out = {};
  for (const id of peerIds) {
    const short = String(id).slice(0, 8);
    out[short] = lines.filter((l) => typeof l === "string" && l.includes(`peers ${short}`) && l.includes("->srv")).length;
  }
  return out;
};

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

const bootPage = async (name, sharedContext = null) => {
  const { browser, pid } = sharedContext ?? await launchBrowser(name);
  const ctx = sharedContext?.ctx ?? await browser.newContext();
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
  const fpAgree = transportFingerprintAgreement(liveA, liveB);
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

// ---------------------------------------------------------------- invariant expectations
// WHICH invariants must actually hold for a scenario to pass. Until this table
// existed NOTHING in the observation loop could fail a run: `failed` was set only
// by a driver exception or the big-transfer verdict, so every one of I1..I7 was
// decorative. The archived pre-fix ws-drop-nofocus-initiator-1.json is the proof --
// it recorded I6 "never" and heldAtEnd false, carried problems: [] and exited 0 --
// and proc-freeze-20-responder-1.json did the same for I7.
//
//   I1 exactly one roster entry for the other identity, on both sides
//   I2 both authenticated, or both absent (no half-open view)
//   I3 exactly one live RTCPeerConnection per side
//   I4 a byte-exact round trip in BOTH directions after the fault clears
//   I5 no handshake/cover entry for a peerId that is not on the roster
//   I6 every roster entry is a client the relay registry still knows
//   I7 the pre-fault transport is kept or replaced SYMMETRICALLY
const ALL_INVARIANTS = ["I1", "I2", "I3", "I4", "I5", "I6", "I7"];
const INVARIANT_EXEMPTIONS = {
  // A mismatched-PIN pair must NEVER authenticate, so the invariants that describe
  // a healthy authenticated edge cannot apply. What pin-typo asserts instead is
  // results.pinTypo.end.verdict (one transport per side, both sides reporting
  // pin-mismatch, the roster not emptied).
  "pin-typo": ["I2", "I3", "I4", "I7"],
};
const REQUIRED_INVARIANTS = ALL_INVARIANTS.filter((k) => !(INVARIANT_EXEMPTIONS[scenario] ?? []).includes(k));

// A terminal PIN mismatch is not a transport fault. The initial transport is
// the only attempt; neither a hot reconnect loop nor the room roster ladder may
// silently start another handshake after that failure.
const PIN_TYPO_TRANSPORT_BUDGET = 1;

// ---------------------------------------------------------------- run
const results = { scenario, role, n, peerIdMode: PEERID_MODE, socketMode: SOCKET_MODE, procFreezeS: PROC_FREEZE_S, udpFlood: UDP_FLOOD, transferSpec: TRANSFER?.spec ?? null, connectMode: CONNECT_MODE, coverCadenceMs: CONNECT_CADENCE_MS ?? null, cpuSlow: CPU_SLOW, pins: scenario === "pin-typo" ? { P1: PIN_A, P2: PIN_B } : null, ports: { http: HTTP_PORT, relay: RELAY_PORT }, observeS: OBSERVE_S, requiredInvariants: REQUIRED_INVARIANTS, startedAt: new Date(T0).toISOString(), driverPid: process.pid, browsers: {}, baseline: {}, fault: {}, invariants: {}, samples: [], sends: [], probeSends: [], transfer: null, problems: [] };
let failed = false;
let P1, P2, A, B, replacedTab;

try {
  say(`=== desync probe: scenario=${scenario} role=${role} peerIdMode=${PEERID_MODE}${procFreezeMatch ? ` socket=${SOCKET_MODE} freeze=${PROC_FREEZE_S}s refocus=${REFOCUS_S} udpflood=${UDP_FLOOD}` : ""} run=${n} (two Chromium instances) ===`);
  P1 = await bootPage("P1");
  P2 = await bootPage("P2");
  results.browsers = { P1: { pid: P1.pid, tree: descendants(P1.pid).map((t) => t.pid) }, P2: { pid: P2.pid, tree: descendants(P2.pid).map((t) => t.pid) } };
  for (const P of [P1, P2]) await P.eval((r) => window.__app.watch(r), ROOM);

  // ---- 6. baseline
  const PIN_TYPO = scenario === "pin-typo";
  const connectOpts = PIN_TYPO
    ? [{ mode: "pin", pinHex: PIN_A }, { mode: "pin", pinHex: PIN_B }]
    : [CONNECT_OPTS, CONNECT_OPTS];
  say(PIN_TYPO
    ? "--- baseline: both connect() with MISMATCHED PINs; no authenticated edge is expected"
    : "--- baseline: both connect(), wait mutual authenticated, round trip both ways");
  await P1.eval(([r, w, o]) => window.__app.connect(r, w, o), [ROOM, wsUrl, connectOpts[0]], 20000);
  await P2.eval(([r, w, o]) => window.__app.connect(r, w, o), [ROOM, wsUrl, connectOpts[1]], 20000);
  say(`  connect opts: P1=${JSON.stringify(connectOpts[0])} P2=${JSON.stringify(connectOpts[1])}`);
  await poll(P1, () => window.__app.isVerified(), null, 15000, "P1 verified");
  await poll(P2, () => window.__app.isVerified(), null, 15000, "P2 verified");
  say(`  verified: P1=${(await P1.eval(() => window.__app.myPeerId())).slice(0, 8)} P2=${(await P2.eval(() => window.__app.myPeerId())).slice(0, 8)}`);
  // Hoisted above the branch: pin-typo has no round trip to dump after. The
  // non-pin branch re-dumps after its round trips, so the state the role control
  // and preFault PC ids are read from is unchanged from before this split.
  let d1 = await P1.dump(), d2 = await P2.dump();
  if (PIN_TYPO) {
    // There is no authenticated edge to wait for and no round trip to make.
    // Record the identities and the relay's peers-request count at t0 so the
    // observation window below can measure the DELTA.
    results.baseline = {
      skipped: "pin-typo: mismatched PINs cannot authenticate",
      passed: true,
      P1: { peerId: d1.keyPair.peerId, publicKey: d1.keyPair.publicKey },
      P2: { peerId: d2.keyPair.peerId, publicKey: d2.keyPair.publicKey },
    };
    results.pinTypo = {
      pins: { P1: PIN_A, P2: PIN_B },
      t0: {
        pcCountP1: (d1.pcs ?? []).length,
        pcCountP2: (d2.pcs ?? []).length,
        peersFrames: await peersFrameCounts([d1.keyPair.peerId, d2.keyPair.peerId]),
      },
    };
    say(`  pin-typo t0: PCs P1=${results.pinTypo.t0.pcCountP1} P2=${results.pinTypo.t0.pcCountP2}; peers frames ${JSON.stringify(results.pinTypo.t0.peersFrames)}`);
  } else {
    await poll(P1, (r) => window.__app.authenticatedCount(r) >= 1, ROOM, 60000, "P1 sees P2 authenticated");
    await poll(P2, (r) => window.__app.authenticatedCount(r) >= 1, ROOM, 60000, "P2 sees P1 authenticated");
    say("  both sides authenticated");
    const rt12 = await roundTrip(P1, P2, "baseline");
    say(`  round trip P1->P2: ${JSON.stringify(rt12)}`);
    const rt21 = await roundTrip(P2, P1, "baseline");
    say(`  round trip P2->P1: ${JSON.stringify(rt21)}`);
    d1 = await P1.dump(); d2 = await P2.dump();
    results.baseline = { rt12, rt21, passed: rt12.ok && rt21.ok, P1: { peerId: d1.keyPair.peerId, publicKey: d1.keyPair.publicKey }, P2: { peerId: d2.keyPair.peerId, publicKey: d2.keyPair.publicKey }, invariants: evalInvariants(d1, d2, await registry(), null) };
    if (!results.baseline.passed) throw new Error("baseline round trip failed");
    say(`  BASELINE PASSED (I1=${results.baseline.invariants.I1} I2=${results.baseline.invariants.I2} I3=${results.baseline.invariants.I3} I5=${results.baseline.invariants.I5} I6=${results.baseline.invariants.I6} fpAgree=${results.baseline.invariants.fpAgree})`);
  }

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
    XF = { id, sender, receiver, bytes: prep.bytes, sha256: prep.sha256, filename: prep.filename, minBytes: Math.floor(prep.bytes * 0.5), verified: null, firstSeen: null, completeAt: null, senderSettled: null, progress: [], chunkSeries: [] };
    results.transfer = {
      spec: TRANSFER.spec, dir: TRANSFER.dir, mib: TRANSFER.mib, id,
      sender: sender.name, senderRole: sender.role, senderIsFaulted: sender === A,
      receiver: receiver.name, receiverRole: receiver.role,
      bytes: prep.bytes, sha256: prep.sha256, filename: prep.filename,
      prepMs: Date.now() - t0prep,
      deadlineS: TRANSFER_DEADLINE_S,
      progress: XF.progress, chunkCountSeries: XF.chunkSeries, problems: [],
    };
    say(`--- transfer: prepared ${prep.bytes} B (${TRANSFER.mib} MiB) on ${sender.name}=${sender === A ? "A(faulted)" : "B(untouched)"} ${sender.role} -> ${receiver.name} ${receiver.role}; sha256=${String(prep.sha256).slice(0, 16)}… file=${prep.filename} (prep ${Date.now() - t0prep}ms)`);
  }
  // One transfer sample from whichever side is not frozen.
  const xfSample = async (label) => {
    if (!XF) return null;
    const s = { t: rel(), label };
    if (!XF.sender.frozen) { try { s.sender = await XF.sender.eval((i) => window.__app.transferState(i), XF.id, 8000); } catch (e) { s.sender = { err: e.message }; } }
    if (!XF.receiver.frozen) { try { s.receiver = await XF.receiver.eval(([r, mb]) => window.__app.incomingBig(r, mb), [ROOM, XF.minBytes], 8000); } catch (e) { s.receiver = { err: e.message }; } }
    // The receiver's real (non-retransmit) chunk count must never go BACKWARDS.
    // A drop to 0 is cancelReceiveTransfer deleting the partial mid-flight, which
    // is exactly what C7 did when a side read its own pre-auth close as a peer
    // cancel. Only samples up to and including the first complete one count: what
    // the store does with the row after materialization is not this assertion's
    // business.
    if (!XF.completeAt && s.receiver && !s.receiver.err && typeof s.receiver.chunksReceivedReal === "number")
      XF.chunkSeries.push({ t: s.t, label, real: s.receiver.chunksReceivedReal, total: s.receiver.chunksReceivedTotal, savedSize: s.receiver.savedSize, complete: !!s.receiver.complete });
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
  // --cpuslow: CDP CPU throttling on one page. Applied at the last instant before
  // the fault and released CPU_SLOW_RELEASE_S after t=0, so the recovery itself is
  // measured unthrottled. rate 1 = no throttling, rate 6 = six times slower.
  const setCpuThrottle = async (P, rate) => {
    P.cdp ??= await P.ctx.newCDPSession(P.page);
    await P.cdp.send("Emulation.setCPUThrottlingRate", { rate });
    say(`  ${P.name}: CPU throttling rate ${rate}`);
  };
  const cpuSlowPage = () => (CPU_SLOW ? (CPU_SLOW.page === "A" ? A : B) : null);
  let cpuSlowApplied = false, cpuSlowReleased = false;

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
      // C5: handshake "authenticated" and a connected transport say nothing
      // about whether the cover scheduler is still running. Record it.
      sample.cover = { A: A.frozen ? null : await A.eval((r) => window.__app.coverStatus(r), ROOM, 8000).catch(() => null), B: await B.eval((r) => window.__app.coverStatus(r), ROOM, 8000).catch(() => null) };
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

  if (CPU_SLOW) {
    await setCpuThrottle(cpuSlowPage(), CPU_SLOW.rate);
    cpuSlowApplied = true;
    results.fault.cpuSlow = { page: CPU_SLOW.page, pageName: cpuSlowPage().name, rate: CPU_SLOW.rate, appliedAt: rel(), releaseAtSinceClear: CPU_SLOW_RELEASE_S };
  }

  say(`--- fault: ${scenario} on ${A.name}`);
  let thawAt = null;
  let replacementConnectAt = null;
  if (scenario === "baseline") {
    say("  (no fault) observing for stability");
  } else if (scenario === "pin-typo") {
    // Both sides fail key-confirmation by construction. Before C2 the catch's
    // channel close fired main.onclose, which re-dialled unconditionally: the
    // pair rebuilt PC + ICE + DTLS + main every 3-5 s and walked the PIN
    // backoff to its 300 s cap. Nothing to inject; just watch.
    say("  (no fault) mismatched PINs; counting transports and re-dials");
  } else if (scenario === "cover-stall") {
    // C5: a main-thread stall that spans a cycle boundary. At cadence 10 s with
    // 2 lanes x 16 frames the slot spacing is 10000/32 = 312.5 ms, so the
    // runtime's drift tolerance is min(floor(312.5) - 1, 500) = 311 ms: any
    // stall longer than that which overlaps a due boundary overran it. Before
    // the fix that called setStatus("suspended","timer-drift") and armed
    // nothing, and only visibilitychange->visible or online could ever leave
    // that state -- neither of which a visible, online tab fires. Both
    // handshakes stay "authenticated" throughout in BOTH runs; the flip is
    // cover status and the round trips.
    // The stall must span a CYCLE BOUNDARY, not merely a slot: handleLateTimer
    // only parks on kind === "boundary" (a late slot always degraded). A fixed
    // 1.5 s stall at cadence 10 s overlaps a boundary about one run in seven --
    // measured: a run with the C5 park deliberately restored still passed,
    // because no boundary timer was late. Making the stall one cadence longer
    // than a full cycle puts a boundary inside it by construction, so the
    // scenario reproduces every time instead of one time in seven.
    const cadenceMs = CONNECT_CADENCE_MS ?? 2000;
    const stallMs = cadenceMs + 1500;
    results.fault.note = `cover-stall: ${stallMs} ms main-thread stall on A (cadence ${cadenceMs} ms + 1.5 s), which spans a scheduled cover cycle boundary by construction`;
    results.fault.stallMs = stallMs;
    const spins = await A.eval((ms) => window.__app.stallMainThread(ms), stallMs, stallMs + 20000);
    say(`  ${A.name}.stallMainThread(${stallMs}) -> ${spins} spins`);
    await probeDuring("post-stall", 30);
    // "A late timer must not park the cover scheduler forever." Parking under
    // the label "suspended" is only ONE way to park, and -- measured, twice --
    // the one a main-thread stall cannot reach: a late SLOT timer fires first,
    // and degrade() disarms the pending boundary timer, so handleLateTimer's
    // boundary branch (everything C5 changed) never runs from this fault. With
    // that branch's pre-C5 `setStatus("suspended","timer-drift")` deliberately
    // restored, this scenario still passed at cadence 3 s and 10 s.
    //
    // What the stall DOES reach is degrade(), and degrade()'s re-arm is the
    // thing that must hold. So the assertion is LIVENESS, not a label: the
    // stalled side must be back to "active" within a few cycles. A scheduler
    // that stops re-arming fails this whatever status it wears.
    const coverAllActive = (s) => { const v = Object.values(s ?? {}); return v.length > 0 && v.every((x) => x === "active"); };
    const coverDeadlineMs = Math.max(4 * cadenceMs, 20_000);
    const coverDeadline = Date.now() + coverDeadlineMs;
    let coverA = await A.eval((r) => window.__app.coverStatus(r), ROOM, 8000);
    const coverTrail = [{ sinceFault: +((Date.now() - faultStart) / 1000).toFixed(1), status: coverA }];
    while (Date.now() < coverDeadline && !coverAllActive(coverA)) {
      await sleep(1000);
      coverA = await A.eval((r) => window.__app.coverStatus(r), ROOM, 8000).catch(() => coverA);
      const lastTrail = coverTrail.at(-1);
      if (JSON.stringify(lastTrail.status) !== JSON.stringify(coverA)) coverTrail.push({ sinceFault: +((Date.now() - faultStart) / 1000).toFixed(1), status: coverA });
    }
    say(`  A.coverStatus after stall: ${JSON.stringify(coverA)} (trail ${JSON.stringify(coverTrail)})`);
    results.fault.coverAfterStall = coverA;
    results.fault.coverTrail = coverTrail;
    results.fault.coverRecoveryDeadlineMs = coverDeadlineMs;
    if (Object.values(coverA).some((s) => s === "suspended" || s === "stopped"))
      results.problems.push("cover parked after a stall: " + JSON.stringify(coverA));
    else if (!coverAllActive(coverA))
      results.problems.push(`cover never returned to "active" within ${coverDeadlineMs} ms of the stall: ${JSON.stringify(coverA)} (trail ${JSON.stringify(coverTrail)})`);
  } else if (scenario === "ws-drop") {
    await closeSocket(A, dA0.keyPair.peerId);
    await probeDuring("ws-drop wait 5s", 5);
  } else if (scenario === "ws-drop-nofocus") {
    // Identical to ws-drop, but the driver never emulates the site's focus
    // handler. A focused desktop tab gets no focus/visibilitychange/pageshow/
    // online event when its socket dies, so this is what a real foreground
    // client experiences. Before the C4 reconnect landed, A stayed
    // disconnected indefinitely and the server dropped every introduction
    // routed toward it.
    await closeSocket(A, dA0.keyPair.peerId);
    await probeDuring("ws-drop-nofocus wait 5s", 5);
  } else if (scenario === "two-tabs") {
    replacedTab = A;
    const beforeRegistry = await registry();
    const predecessor = beforeRegistry.clients.find((client) => client.peerId === dA0.keyPair.peerId);
    const replacement = await bootPage(`${A.name}-tab2`, A);
    replacement.role = A.role;
    await replacement.eval((r) => window.__app.watch(r), ROOM);
    replacementConnectAt = Date.now();
    await replacement.eval(([r, w, o]) => window.__app.connect(r, w, o), [ROOM, wsUrl, CONNECT_OPTS], 20000);
    await poll(replacement, () => window.__app.isVerified(), null, 15000, "replacement tab verified");
    const identity = await replacement.dump();
    const successor = (await registry()).clients.find((client) => client.peerId === identity.keyPair?.peerId);
    results.twoTabs = {
      originalPage: A.name, replacementPage: replacement.name,
      connectAt: rel(replacementConnectAt), sharedBrowserContext: replacement.ctx === A.ctx,
      originalIdentity: dA0.keyPair, replacementIdentity: identity.keyPair,
      predecessor, successor,
    };
    if (identity.keyPair?.publicKey !== dA0.keyPair.publicKey || identity.keyPair?.peerId !== dA0.keyPair.peerId)
      throw new Error("second tab did not adopt the original IndexedDB identity and stable peerId");
    if (!predecessor || !successor || predecessor.sock === successor.sock || !successor.socketGeneration || predecessor.socketGeneration === successor.socketGeneration)
      throw new Error("second tab did not replace the registered socket with a fresh generation");
    A = replacement;
    results.A.replacementPage = A.name;
    say(`  same identity second tab ${replacedTab.name} -> ${A.name}: socket ${predecessor.sock} -> ${successor.sock}; generation ${predecessor.socketGeneration} -> ${successor.socketGeneration}`);
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
    if (SOCKET_MODE === "keep" || SOCKET_MODE === "stranded") {
      const ka = await ctl(`keepalive?peerId=${dA0.keyPair.peerId}&ms=${PROC_FREEZE_S * 1000 + 15000}`);
      results.fault.keepalive = { at: rel(), ...ka };
      say(`  relay ctl keepalive for A (${PROC_FREEZE_S + 15}s: pong-timeout eviction suppressed): ${JSON.stringify(ka)}`);
    }
    if (SOCKET_MODE === "stranded") {
      // Keep A registered but cut its signalling both ways, past the thaw. The
      // room then has two healthy sockets and two empty rosters: introductions
      // to A were dropped and A's own requests never left. Nothing in an
      // inbound frame can start the recovery, so this is what exercises the
      // client's own roster reconciliation (and, now that the relay's ping
      // shares the drop gate, its heartbeat watchdog).
      const strandMs = PROC_FREEZE_S * 1000 + 40000;
      const bh = await ctl(`blackhole?peerId=${dA0.keyPair.peerId}&ms=${strandMs}`);
      results.fault.blackhole = { at: rel(), ms: strandMs, ...bh };
      say(`  relay ctl blackhole A both ways for ${Math.round(strandMs / 1000)}s (stranded: registered but unreachable): ${JSON.stringify(bh)}`);
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
  const tClear = replacementConnectAt ?? thawAt ?? Date.now();
  results.fault.clearedAt = rel(tClear);
  const sinceClear = (t = Date.now()) => (t - tClear) / 1000;

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
    // ws-drop-nofocus withholds the poke on purpose: the SDK's own bounded
    // reconnect ladder (C4) has to be what brings A's socket back.
    // baseline / pin-typo / cover-stall never drop the socket, so there is nothing
    // for a focus handler to reconnect.
    if (!["baseline", "two-tabs", "ws-drop-nofocus", "pin-typo", "cover-stall"].includes(scenario))
      results.fault.focusReconnect = await focusReconnect(A);
    else results.fault.focusReconnect = "skipped: " + scenario;
  }

  // ---- 7. observe, evaluate invariants every 1 s
  say(`--- observing ${OBSERVE_S}s from t=0=${procFreezeMatch ? "thaw" : "fault cleared"} (invariants every 1s; I4 send attempted once I2 holds${REFOCUS_S ? `; focus handler re-run every ${REFOCUS_S}s` : ""})`);
  const first = { I1: null, I2: null, I3: null, I4: null, I5: null, I6: null, I7: null };
  // A new tab has a new JS realm; its local PC #1 is not the old tab's PC #1.
  const observedPreFault = replacedTab ? { ...preFault, A: -1 } : preFault;
  let firstAuthenticatedSinceClear = null;
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
    const inv = evalInvariants(dA, dB, reg, observedPreFault);
    const sampledAt = Date.now();
    const sample = { t: rel(sampledAt), sinceClear: sinceClear(sampledAt), inv, A: dA, B: dB, registry: { clients: reg.clients.map((c) => ({ peerId: c.peerId, pub: c.publicKey.slice(0, 8), sock: c.sock, verified: c.verified, alive: c.isAlive })) } };
    results.samples.push(sample);
    if (results.pinTypo && !results.pinTypo.firstTerminalFailure) {
      const failedPin = (d) => Object.values(d.room?.handshakeStatusByPeer ?? {}).some((row) => row.status === "failed" && row.reason === "pin-mismatch");
      if (failedPin(dA) && failedPin(dB)) {
        results.pinTypo.firstTerminalFailure = {
          sinceClear: sample.sinceClear,
          peersFrames: await peersFrameCounts([dA.keyPair.peerId, dB.keyPair.peerId]),
          transportsPerSide: { A: dA.pcs.length, B: dB.pcs.length },
        };
        say(`  PIN mismatch stable-state anchor: ${JSON.stringify(results.pinTypo.firstTerminalFailure)}`);
      }
    }
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
      for (const k of STATE_INVARIANTS) { if (inv[k] && first[k] === null) first[k] = { sinceClear: sample.sinceClear, at: sample.t }; }
      if (inv.bothAuthenticated && firstAuthenticatedSinceClear === null) firstAuthenticatedSinceClear = sample.sinceClear;
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
            const pinv = evalInvariants(pa, pb, await registry(), observedPreFault);
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
    if (cpuSlowApplied && !cpuSlowReleased && sinceClear(tick) >= CPU_SLOW_RELEASE_S) {
      cpuSlowReleased = true;
      await setCpuThrottle(cpuSlowPage(), 1).catch((e) => say(`  cpu throttle release failed: ${e.message}`));
      results.fault.cpuSlow.releasedAtSinceClear = sinceClear();
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
  // Only a problem where I4 is actually required: pin-typo must never authenticate.
  if (REQUIRED_INVARIANTS.includes("I4") && !i4ok && first.I2 === null) results.problems.push("I4 never attempted: I2 (both authenticated) never held during observation");
  const fin = results.samples.at(-1)?.inv;
  results.invariants = {
    firstSatisfiedSinceClear: Object.fromEntries(Object.entries(first).map(([k, v]) => [k, v ? v.sinceClear : "never"])),
    firstAuthenticatedSinceClear: firstAuthenticatedSinceClear ?? "never",
    heldAtEnd: endInvariantState(fin, i4ok), finalSample: fin,
    required: REQUIRED_INVARIANTS, exempt: INVARIANT_EXEMPTIONS[scenario] ?? [],
  };
  say(`--- RESULT first-satisfied (s after t=0): ${JSON.stringify(results.invariants.firstSatisfiedSinceClear)}; held at end: ${JSON.stringify(results.invariants.heldAtEnd)}`);
  results.problems.push(...invariantProblems({ ...results.invariants, scenario, role, observeS: OBSERVE_S }));
  if (replacedTab) {
    results.twoTabs.originalAtEnd = await replacedTab.dump();
    results.twoTabs.originalTimeline = await replacedTab.eval(() => window.__app.timeline());
    results.twoTabs.originalPcEvents = await replacedTab.eval(() => window.__app.pcEvents());
    const current = (await registry()).clients.find((client) => client.peerId === results.twoTabs.replacementIdentity.peerId);
    results.twoTabs.registryAtEnd = current;
    if (results.twoTabs.originalAtEnd.unreachable || results.twoTabs.originalAtEnd.signalingServer?.isConnected !== false)
      results.problems.push("replaced tab was unreachable or still connected at the end");
    if (current?.sock !== results.twoTabs.successor.sock)
      results.problems.push("replacement tab lost registry ownership after the second-tab takeover");
  }
  say(`--- INVARIANT VERDICT required=${JSON.stringify(REQUIRED_INVARIANTS)}${(INVARIANT_EXEMPTIONS[scenario] ?? []).length ? ` exempt-for-${scenario}=${JSON.stringify(INVARIANT_EXEMPTIONS[scenario])}` : ""} fpAgree=${fin && !fin.unknown ? fin.fpAgree : "n/a"} -> ${results.problems.length ? "PROBLEMS" : "all held"}`);
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
    // Monotonicity of the receiver's real chunk count (see xfSample). A drop is a
    // partial that was deleted under the receiver mid-flight.
    const series = XF.chunkSeries;
    let regression = null;
    for (let i = 1; i < series.length && !regression; i++)
      if (series[i].real < series[i - 1].real) regression = { from: series[i - 1], to: series[i] };
    results.transfer.chunkCountMonotonic = !regression;
    if (regression) results.transfer.problems.push(`receiver chunk count went BACKWARDS: real ${regression.from.real} at ${regression.from.t} -> ${regression.to.real} at ${regression.to.t} (${regression.to.label})`);
    results.transfer.pass = !!(XF.hashMatch && inTime && delivered && !regression);
    results.transfer.verdict = {
      receiverByteExact: !!XF.hashMatch,
      receiverCompleteSinceClear: results.transfer.receiverCompleteSinceClear ?? null,
      withinDeadline: inTime,
      senderResolvedDelivered: delivered,
      senderOutcome: st ? (st.outcome === "resolved" ? `resolved (${(st.outcomes ?? []).map((o) => o.status).join(",") || "no outcomes"})` : `rejected: ${st.error}`) : "NEVER SETTLED",
      senderSettledSinceClear: st?.sinceClear ?? null,
      chunkCountMonotonic: !regression,
      chunkSeriesSamples: series.length,
      chunks: results.transfer.receiverTelemetry ?? null,
    };
    say(`--- TRANSFER ${results.transfer.pass ? "PASS" : "FAIL"} ${TRANSFER.spec} (${XF.sender.name}=${XF.sender === A ? "A" : "B"} -> ${XF.receiver.name}): ${JSON.stringify(results.transfer.verdict)}`);
    say(`--- TRANSFER data channels: A=${JSON.stringify(results.transfer.dataChannels.A?.perPc ?? results.transfer.dataChannels.A)} | B=${JSON.stringify(results.transfer.dataChannels.B?.perPc ?? results.transfer.dataChannels.B)}`);
    if (!results.transfer.pass) { failed = true; results.problems.push("TRANSFER FAILED: " + JSON.stringify(results.transfer.verdict)); }
  }

  // ---- pin-typo verdict (measured at the end of the observation window, with
  // both pages still alive; the report's anchor put it in the finally block, but a
  // driver failure must not be masked by a second round of page evaluation).
  if (results.pinTypo) {
    const [dEndA, dEndB] = await Promise.all([P1.dump(), P2.dump()]);
    const hsOf = (d) => Object.values(d.room?.handshakeStatusByPeer ?? {});
    results.pinTypo.end = {
      pcCountP1: (dEndA.pcs ?? []).length,
      pcCountP2: (dEndB.pcs ?? []).length,
      peersFrames: await peersFrameCounts([dEndA.keyPair.peerId, dEndB.keyPair.peerId]),
      handshakeP1: hsOf(dEndA),
      handshakeP2: hsOf(dEndB),
      rosterP1: (dEndA.room?.peers ?? []).length,
      rosterP2: (dEndB.room?.peers ?? []).length,
    };
    // The assertion that flips. Pre-fix: > 10 PCs per side over 120 s (a rebuild
    // every 3-5 s) and tens of peers requests per identity. Post-fix: exactly one
    // PC per side and one join-time peers request, with the failure still on the
    // roster so a UI can show it.
    const e = results.pinTypo.end;
    const failedWith = (rows) => rows.filter((r) => r.status === "failed" && r.reason === "pin-mismatch").length;
    e.transportBudget = PIN_TYPO_TRANSPORT_BUDGET;
    e.verdict = {
      transportsWithinBudget: e.pcCountP1 === PIN_TYPO_TRANSPORT_BUDGET && e.pcCountP2 === PIN_TYPO_TRANSPORT_BUDGET,
      transportBudget: PIN_TYPO_TRANSPORT_BUDGET,
      transportsPerSide: { P1: e.pcCountP1, P2: e.pcCountP2 },
      bothReportPinMismatch: failedWith(e.handshakeP1) >= 1 && failedWith(e.handshakeP2) >= 1,
      rosterNotEmptied: e.rosterP1 >= 1 && e.rosterP2 >= 1,
      peersFrames: e.peersFrames,
      noPeersRequestsAfterTerminalFailure: !!results.pinTypo.firstTerminalFailure &&
        Object.entries(results.pinTypo.firstTerminalFailure.peersFrames).every(([peer, count]) => e.peersFrames[peer] === count),
    };
    if (!e.verdict.transportsWithinBudget) results.problems.push(`pin-typo must use exactly one transport per side: P1=${e.pcCountP1} P2=${e.pcCountP2} transports in ${OBSERVE_S}s, budget ${PIN_TYPO_TRANSPORT_BUDGET}`);
    if (!e.verdict.noPeersRequestsAfterTerminalFailure) results.problems.push("pin-typo: peers discovery retried after terminal PIN mismatch (or the terminal failure was never observed)");
    if (!e.verdict.bothReportPinMismatch) results.problems.push("pin-typo: a side never reported status=failed reason=pin-mismatch");
    if (!e.verdict.rosterNotEmptied) results.problems.push("pin-typo: the roster was emptied, so the failure has nobody to attach to");
    say(`  pin-typo verdict: ${JSON.stringify(e.verdict)}`);
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
    results.problems.push(...diagnosticProblems(results.diag));
  } catch (e) { results.problems.push("evidence dump failed: " + e.message); }
  // A RECORDED PROBLEM IS A FAILURE. Until this line `failed` came only from a
  // driver exception or the big-transfer verdict, so a run could archive a
  // non-empty results.problems -- a violated invariant, an unstarted transfer, a
  // SIGSTOP that did not take -- and still exit 0. Every problem push above is a
  // real assertion now.
  if (results.problems.length > 0) failed = true;
  results.failed = failed;
  if (results.problems.length) { say(`--- FAILED with ${results.problems.length} problem(s):`); for (const p of results.problems) say(`    * ${p}`); }
  else say("--- PASSED: no problems recorded");
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
