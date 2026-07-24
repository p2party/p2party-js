#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import pkg from "../package.json" with { type: "json" };

const expectedBytes = await readFile("lib/libcrypto.wasm");
const provenance = JSON.parse(
  await readFile("lib/libcrypto.provenance.json", "utf8"),
);
const expectedSha256 = createHash("sha256").update(expectedBytes).digest("hex");
const expectedSri = `sha384-${createHash("sha384")
  .update(expectedBytes)
  .digest("base64")}`;
if (provenance.artifact?.sha256 !== expectedSha256)
  throw new Error("packaged WASM does not match its provenance SHA-256");
if (provenance.artifact?.sri !== expectedSri)
  throw new Error("packaged WASM does not match its provenance SRI");

const baseUrl =
  process.env.P2PARTY_CDN_BASE_URL?.trim() ?? "https://cdn.p2party.com/";
const assetUrl = new URL(`@${pkg.version}/libcrypto.wasm`, baseUrl);
const attempts = 8;
let lastError;
for (let attempt = 1; attempt <= attempts; attempt += 1) {
  try {
    const response = await fetch(assetUrl, {
      cache: "no-store",
      headers: { "cache-control": "no-cache" },
    });
    if (!response.ok)
      throw new Error(`CDN returned HTTP ${String(response.status)}`);
    const receivedBytes = Buffer.from(await response.arrayBuffer());
    if (!receivedBytes.equals(expectedBytes))
      throw new Error("CDN returned bytes that differ from the release WASM");
    const receivedSha256 = createHash("sha256")
      .update(receivedBytes)
      .digest("hex");
    const receivedSri = `sha384-${createHash("sha384")
      .update(receivedBytes)
      .digest("base64")}`;
    if (receivedSha256 !== expectedSha256 || receivedSri !== expectedSri)
      throw new Error("CDN WASM digest verification failed");
    console.log(
      `Verified ${assetUrl.href}: ${receivedBytes.byteLength} bytes, SHA-256 ${receivedSha256}, ${receivedSri}`,
    );
    process.exit(0);
  } catch (error) {
    lastError = error;
    if (attempt === attempts) break;
    const delayMs = Math.min(1_000 * 2 ** (attempt - 1), 8_000);
    console.warn(
      `CDN verification attempt ${String(attempt)}/${String(attempts)} failed: ${error.message}; retrying in ${String(delayMs)}ms`,
    );
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

throw new Error(
  `CDN verification failed for ${assetUrl.href}: ${lastError?.message ?? "unknown error"}`,
);
