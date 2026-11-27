import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { discoverRoute, signOffer } from "./discovery.mjs";
import { providerId } from "./payment-protocol.mjs";

const scope = "test-scope",
  pairs = Array.from({ length: 4 }, () => generateKeyPairSync("ml-dsa-65"));
const ids = pairs.map((p) => providerId(p.publicKey));
const pins = new Map(pairs.map((p, i) => [ids[i], p.publicKey]));
const quote = (i, fields = {}) =>
  signOffer(
    {
      provider: ids[i],
      scope,
      price: 1,
      availableBytes: 100,
      expires: 10,
      sequence: 1,
      ...fields,
    },
    pairs[i].privateKey,
  );
const offers = ids.map((_, i) => quote(i));
const links = new Map(
  ["sender", ...ids].map((from) => [
    from,
    new Map(
      [...ids, "recipient"].filter((id) => id !== from).map((id) => [id, 1]),
    ),
  ]),
);
const request = { hops: 2, cap: 2, bytes: 100, now: 4 };
const find = (extra = {}, opts = {}) =>
  discoverRoute(
    { pins, advertisements: offers, scope, links, ...extra },
    { ...request, ...opts },
  );

test("the cumulative cap includes outstanding authorizations, and the cheapest reachable path wins", () => {
  assert.equal(find({}, { cap: 1 }), null);
  assert.equal(find({}, { alreadyCommitted: 1 }), null);
  assert.equal(find({}, { cap: 4, alreadyCommitted: 2 }).price, 2);
  const expensive = offers.map((_, i) => quote(i, { price: i > 1 ? 2 : 1 }));
  const p = find({ advertisements: expensive }, { cap: 12 });
  assert.deepEqual(new Set(p.providers), new Set(ids.slice(0, 2)));
  assert.equal(p.price, 2);
  assert.equal(find({ links: new Map() }), null);
  assert.equal(find({}, { bytes: 101 }), null);
});
test("discard expired, equivocal, unpinned, stale and altered advertisements", () => {
  const none = [
    quote(0, { scope: "wrong" }),
    quote(1, { expires: 4 }),
    quote(2, { availableBytes: 0 }),
    quote(3, { expires: 4 }),
  ];
  assert.equal(find({ advertisements: none }), null);
  const ads = [
    offers[0],
    quote(0, { expires: 4, sequence: 2 }),
    offers[1],
    { ...offers[2], offer: { ...offers[2].offer, price: 0 } },
    quote(3, { price: 2 }),
    quote(3, { price: 1 }),
  ];
  assert.equal(find({ advertisements: ads }), null);
  assert.equal(find({ pins: new Map(), advertisements: offers }), null);
  assert.equal(
    find({ advertisements: [...ads, quote(0, { sequence: 3 })] }).price,
    2,
  );
});
test("choose observed latency within the user's price cap and spread comparable paid assignments", () => {
  const uses = new Map();
  for (let i = 0; i < 60; i++) {
    const p = find({ uses });
    assert.equal(p.latencyMs, 3);
    assert.equal(new Set(p.providers).size, 2);
    for (const id of p.providers) uses.set(id, (uses.get(id) ?? 0) + 1);
  }
  assert.deepEqual(
    ids.map((id) => uses.get(id)),
    [30, 30, 30, 30],
  );
  const sparse = new Map([
    [
      "sender",
      new Map([
        [ids[0], 1],
        [ids[2], 2],
      ]),
    ],
    [ids[0], new Map([[ids[1], 1]])],
    [ids[1], new Map([["recipient", 1]])],
    [ids[2], new Map([[ids[3], 1]])],
    [ids[3], new Map([["recipient", 1]])],
  ]);
  const busy = new Map([
    [ids[0], 8],
    [ids[1], 8],
  ]);
  assert.deepEqual(
    find({ links: sparse, uses: busy }).providers,
    ids.slice(0, 2),
  );
  assert.deepEqual(
    find({ links: sparse, uses: busy }, { latencySlackMs: 1 }).providers,
    ids.slice(2),
  );
});
