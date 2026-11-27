import { randomInt, sign, verify } from "node:crypto";
import { providerId } from "./payment-protocol.mjs";

const uint = (n) => Number.isSafeInteger(n) && n >= 0;
const maxProviders = 24;
function offerBytes(o) {
  if (
    !o ||
    typeof o.scope !== "string" ||
    !/^[a-z0-9-]{1,64}$/.test(o.scope) ||
    !/^[0-9a-f]{128}$/.test(o.provider) ||
    !uint(o.price) ||
    !uint(o.availableBytes) ||
    !uint(o.expires) ||
    !uint(o.sequence)
  )
    throw Error("Invalid relay advertisement");
  return Buffer.from(
    JSON.stringify([
      "p2party/relay-offer/v1",
      o.scope,
      o.provider,
      o.price,
      o.availableBytes,
      o.expires,
      o.sequence,
    ]),
  );
}
export function signOffer(offer, key) {
  return {
    offer,
    signature: sign(null, offerBytes(offer), key).toString("hex"),
  };
}
// The local observer supplies identity pins, directed link costs and counters.
// No endpoint is contacted, no identity is admitted and no money is committed here.
export function discoverRoute(
  { pins, advertisements, scope, links, uses = new Map() },
  request,
) {
  const {
    hops,
    cap,
    bytes,
    now,
    alreadyCommitted = 0,
    latencySlackMs = 0,
  } = request;
  if (
    ![2, 3].includes(hops) ||
    !uint(cap) ||
    !uint(bytes) ||
    !bytes ||
    !uint(now) ||
    !uint(alreadyCommitted) ||
    alreadyCommitted > cap ||
    !uint(latencySlackMs) ||
    pins.size > maxProviders ||
    advertisements.length > maxProviders * 4
  )
    throw Error("Invalid discovery request");
  const latest = new Map(),
    conflicts = new Set();
  for (const ad of advertisements) {
    try {
      const o = ad.offer,
        key = pins.get(o.provider);
      if (
        !key ||
        providerId(key) !== o.provider ||
        o.scope !== scope ||
        !/^[0-9a-f]{6618}$/.test(ad.signature) ||
        !verify(null, offerBytes(o), key, Buffer.from(ad.signature, "hex"))
      )
        continue;
      const previous = latest.get(o.provider);
      if (previous && previous.sequence > o.sequence) continue;
      if (previous && previous.sequence === o.sequence) {
        if (!offerBytes(previous).equals(offerBytes(o)))
          conflicts.add(o.provider);
        continue;
      }
      conflicts.delete(o.provider);
      latest.set(o.provider, o);
    } catch {
      /* Ignore invalid and unpinned announcements. */
    }
  }
  const providers = [...latest.values()].filter(
    (o) =>
      !conflicts.has(o.provider) &&
      o.expires > now &&
      o.availableBytes >= bytes,
  );
  const remaining = cap - alreadyCommitted,
    paths = [];
  function walk(path, price, latency) {
    const from = path.at(-1) ?? "sender";
    if (path.length === hops) {
      const last = links.get(from)?.get("recipient");
      if (uint(last) && Number.isSafeInteger(latency + last))
        paths.push({ providers: path, price, latencyMs: latency + last });
      return;
    }
    for (const o of providers) {
      const ms = links.get(from)?.get(o.provider);
      if (
        !uint(ms) ||
        !Number.isSafeInteger(latency + ms) ||
        path.includes(o.provider) ||
        o.price > remaining - price
      )
        continue;
      walk([...path, o.provider], price + o.price, latency + ms);
    }
  }
  walk([], 0, 0);
  if (!paths.length) return null;
  const cheapest = paths.reduce((m, p) => Math.min(m, p.price), Infinity);
  const fastest = paths.reduce(
    (m, p) => (p.price === cheapest ? Math.min(m, p.latencyMs) : m),
    Infinity,
  );
  // Minimize the largest existing assignment counts on the selected relays.
  // Uniform reservoir sampling breaks exact path ties without directory-order bias.
  let winner = null,
    best = null,
    ties = 0;
  for (const p of paths) {
    if (p.price !== cheapest || p.latencyMs - fastest > latencySlackMs)
      continue;
    const counts = p.providers.map((id) => uses.get(id) ?? 0);
    if (!counts.every(uint)) throw Error("Invalid assignment count");
    counts.sort((a, b) => b - a);
    let comparison = 0;
    if (best)
      for (let i = 0; i < counts.length && !comparison; i++)
        comparison = counts[i] - best[i];
    if (!best || comparison < 0) {
      best = counts;
      winner = p;
      ties = 1;
    } else if (!comparison && randomInt(++ties) === 0) winner = p;
  }
  return winner;
}
