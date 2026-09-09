#!/usr/bin/env node
// ============================================================================
// Update the SRI integrity hash in wasmLoader.ts after emscripten rebuilds
// the WASM binary. Runs automatically as part of prebuild / predist.
// ============================================================================
import { readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPath = resolve(
  __dirname,
  "..",
  "src",
  "cryptography",
  "libcrypto.wasm",
);
const loaderPath = resolve(
  __dirname,
  "..",
  "src",
  "cryptography",
  "wasmLoader.ts",
);

const wasmBytes = readFileSync(wasmPath);
const sha384 = createHash("sha384").update(wasmBytes).digest("base64");
const newIntegrity = `sha384-${sha384}`;

const source = readFileSync(loaderPath, "utf-8");

// Replace only the quoted digest, never the whitespace around it.
//
// This used to rewrite `integrity:` plus a hardcoded six-space indent, which
// matched Prettier only for the exact nesting the literal happened to sit in.
// Move the constant and the two tools start overwriting each other: the build
// writes six spaces, format:check demands four, and CI runs release:pack
// immediately before check. Touching just the literal has no opinion about
// layout, so Prettier stays the sole authority on formatting.
const literal = /"sha384-[A-Za-z0-9+/=]+"/g;
const matches = source.match(literal) ?? [];
if (matches.length !== 1) {
  console.error(
    `Expected exactly one SRI literal in wasmLoader.ts, found ${matches.length}`,
  );
  process.exit(1);
}

writeFileSync(
  loaderPath,
  source.replace(literal, `"${newIntegrity}"`),
  "utf-8",
);
console.log(`Updated wasmLoader.ts integrity → ${newIntegrity}`);
