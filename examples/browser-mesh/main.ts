/**
 * The whole library in one file: join a room, wait for a peer, send, receive.
 *
 * Serve this directory with any static server that can compile TypeScript
 * (`bunx vite examples/browser-mesh`), open it twice, and paste the invite from
 * the first tab into the second tab's URL fragment.
 */
import p2party from "p2party";

const $ = (id: string) => document.getElementById(id)!;
const log = (text: string, className = "") => {
  const line = document.createElement("p");
  line.className = className;
  line.textContent = text;
  $("log").prepend(line);
};

// A fragment invite in the URL means "join that room"; otherwise make one.
// The capability lives after `#`, so it never reaches an HTTP server or log.
const invite = location.hash.slice(1) || p2party.generateRoomInvite();
($("invite") as HTMLInputElement).value = invite;

// One call. `connect()` alone would return before the room has an id.
const room = await p2party.joinRoom(invite, undefined, undefined, {
  timeoutMs: 30_000,
});
$("status").textContent = `joined ${room.id} — waiting for a peer…`;

// One subscription, owned by the library: fires once per fully-arrived
// message, already decoded.
p2party.onMessage(room.id, (incoming) => {
  if (typeof incoming.message === "string") log(`← ${incoming.message}`);
  else log(`← ${incoming.filename} (${String(incoming.size)} bytes)`);
});

// A room having an id does not mean anyone can receive yet.
void p2party
  .waitForPeers(room.id, { timeoutMs: 120_000 })
  .then((peers) => {
    $("status").textContent =
      `joined ${room.id} — ${String(peers.length)} peer(s) authenticated`;
  })
  .catch(() => {
    $("status").textContent =
      `joined ${room.id} — no peer yet; open a second tab`;
  });

$("send").addEventListener("submit", (event) => {
  event.preventDefault();
  const field = $("text") as HTMLInputElement;
  const text = field.value.trim();
  if (!text) return;
  field.value = "";
  log(`→ ${text}`, "sent");

  const handle = p2party.sendMessage(text, "chat", room.id);
  void handle.done.catch((error: unknown) => {
    // `done` REJECTS when nobody took delivery — an empty room, or a cancel.
    // With one tab open that is the expected outcome, not a failure to debug.
    if (error instanceof p2party.MessageDeliveryError)
      log(
        `   (not delivered: ${String(error.result.outcomes.length)} peer outcome(s))`,
        "sent",
      );
  });
});
