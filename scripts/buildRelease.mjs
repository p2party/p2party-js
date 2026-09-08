#!/usr/bin/env node

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, "..");
const packageJsonPath = path.join(projectRoot, "package.json");
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const bun = process.platform === "win32" ? "bun.exe" : "bun";
const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH ?? "0";
const expectedNodeMajor = 24;
const expectedEmscriptenVersion = "6.0.9";
const expectedLibsodiumCommit = "2ce4d906a68eae82b27b4867f3d4172ec508cb27";
const expectedLibsodiumTree = "2dabe17c708edd7334e3316b5094b753859395d9";
const expectedMlkemNativeCommit = "0ba906cb14b1c241476134d7403a811b382ca498";
const expectedMlkemNativeSourceTreeSha256 =
  "a2e15382a8dc0207752b3f5cdfc907886505fe304948183b4b61e99e7cb92ac6";
const expectedMlkemWrapperSha256 =
  "ec8250c5fefebf1b7958c5ad20ed92bf7ef0a3c5e7b0783c2079d2be678f090d";
const expectedRoomWordlistSha256 =
  "531238ede7be78f5fd444b3a4452b023f408f0146aa82bd9fe03aad902b3ff8e";
const releaseRoot = mkdtempSync(
  path.join(realpathSync(tmpdir()), "p2party-release-"),
);
const stageRoot = path.join(releaseRoot, "package");
const stageLib = path.join(stageRoot, "lib");
const packedRoot = path.join(releaseRoot, "packed");
const npmCache = path.join(releaseRoot, "npm-cache");
const emscriptenCache = path.join(releaseRoot, "emscripten-cache");
const releaseBuildEnvironment = {
  P2PARTY_ANALYZE: "false",
  P2PARTY_OUTPUT_DIR: stageLib,
};

const run = (command, args, options = {}) =>
  execFileSync(command, args, {
    cwd: options.cwd ?? projectRoot,
    env: {
      ...process.env,
      SOURCE_DATE_EPOCH: sourceDateEpoch,
      ...options.env,
    },
    maxBuffer: 64 * 1024 * 1024,
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
    encoding: options.capture ? "utf8" : undefined,
  });

const sha = (algorithm, bytes) =>
  createHash(algorithm).update(bytes).digest("hex");

const sri = (bytes) =>
  `sha384-${createHash("sha384").update(bytes).digest("base64")}`;

const listFiles = (root, current = root) =>
  readdirSync(current, { withFileTypes: true })
    .flatMap((entry) => {
      const absolutePath = path.join(current, entry.name);
      return entry.isDirectory()
        ? listFiles(root, absolutePath)
        : [path.relative(root, absolutePath).split(path.sep).join("/")];
    })
    .sort();

const digestFiles = (root, relativePaths) => {
  const hash = createHash("sha256");
  for (const relativePath of relativePaths) {
    const bytes = readFileSync(path.join(root, relativePath));
    const byteLength = Buffer.alloc(8);
    byteLength.writeBigUInt64BE(BigInt(bytes.byteLength));
    hash.update(relativePath);
    hash.update(Buffer.from([0]));
    hash.update(byteLength);
    hash.update(bytes);
  }
  return hash.digest("hex");
};

const fail = (message) => {
  throw new Error(`release validation failed: ${message}`);
};

const requireFile = (relativePath) => {
  const absolutePath = path.join(stageRoot, relativePath);
  if (!existsSync(absolutePath)) fail(`missing ${relativePath}`);
  return absolutePath;
};

const exportedTargets = (exportsField) => {
  const targets = [];
  const visit = (value) => {
    if (typeof value === "string") {
      targets.push(value);
      return;
    }
    if (value && typeof value === "object")
      for (const nested of Object.values(value)) visit(nested);
  };
  visit(exportsField);
  return targets;
};

const validateWasmGlue = async (wasmBytes) => {
  const require = createRequire(import.meta.url);
  const gluePath = path.join(
    projectRoot,
    "src",
    "cryptography",
    "libcrypto.js",
  );
  delete require.cache[require.resolve(gluePath)];
  const factory = require(gluePath);
  const cryptoModule = await factory({
    wasmBinary: wasmBytes,
    wasmMemory: new WebAssembly.Memory({
      initial: 32,
      maximum: 16_384,
    }),
  });
  const requiredCryptoExports = [
    "_crypto_init",
    "_cpace_ristretto255_from_hash",
    "_cpace_ristretto255_scalarmult",
    "_cpace_ristretto255_scalar_random",
    "_x25519_keypair",
    "_x25519_dh",
    "_hkdf_sha512_extract",
    "_hkdf_sha512_expand",
    "_encrypt_chachapoly_symmetric",
    "_decrypt_chachapoly_symmetric",
    "_receive_message_with_key",
    "_mlkem512_keypair",
    "_mlkem512_encaps",
    "_mlkem512_decaps",
    "_mlkem768_keypair",
    "_mlkem768_encaps",
    "_mlkem768_decaps",
    "_mlkem1024_keypair",
    "_mlkem1024_encaps",
    "_mlkem1024_decaps",
    "_fips202_shake256",
    "_fips202_sha3_256",
  ];
  for (const name of requiredCryptoExports)
    if (typeof cryptoModule[name] !== "function")
      fail(`generated glue/WASM pair is missing ${name}`);
  if (cryptoModule._crypto_init() !== 0)
    fail("configured libsodium runtime did not initialize");
};

const validateCryptoProvenance = (provenance, wasmBytes) => {
  if (provenance.schemaVersion !== 1)
    fail("crypto provenance has an unsupported schema version");
  if (provenance.sources?.libsodium?.commit !== expectedLibsodiumCommit)
    fail("crypto provenance has an unexpected libsodium commit");
  if (provenance.sources?.libsodium?.tree !== expectedLibsodiumTree)
    fail("crypto provenance has an unexpected libsodium tree");
  if (provenance.sources?.libsodium?.configuredBuild !== true)
    fail("crypto provenance does not attest a configured libsodium build");
  if (provenance.sources?.mlkemNative?.commit !== expectedMlkemNativeCommit)
    fail("crypto provenance has an unexpected mlkem-native commit");
  if (
    provenance.sources?.mlkemNative?.sourceTreeSha256 !==
    expectedMlkemNativeSourceTreeSha256
  )
    fail("crypto provenance has an unexpected mlkem-native source-tree digest");
  if (
    provenance.sources?.mlkemNative?.wrapperSha256 !==
    expectedMlkemWrapperSha256
  )
    fail("crypto provenance has an unexpected ML-KEM wrapper digest");
  if (
    JSON.stringify(provenance.sources?.mlkemNative?.parameterSets) !==
    JSON.stringify([512, 768, 1024])
  )
    fail("crypto provenance does not attest all ML-KEM parameter sets");
  if (provenance.sources?.mlkemNative?.multilevel?.shared !== 768)
    fail("crypto provenance has an unexpected shared ML-KEM build");
  if (
    JSON.stringify(provenance.sources?.mlkemNative?.multilevel?.noShared) !==
    JSON.stringify([512, 1024])
  )
    fail("crypto provenance has unexpected no-shared ML-KEM builds");
  if (provenance.build?.mode !== "production")
    fail("crypto provenance is not for a production build");
  if (provenance.build?.linkTimeOptimization !== false)
    fail("crypto provenance does not attest that LTO is disabled");
  if (provenance.build?.publicSodiumApi !== true)
    fail("crypto provenance does not attest public libsodium API use");
  // Exact equality, not a loose match. The old pattern also accepted
  // "6.0.9-git" and anything else containing the version, so a provenance file
  // generated by a differently-installed compiler passed here and only failed
  // later, in CI, at the byte comparison.
  if (provenance.toolchain?.emscripten !== expectedEmscriptenVersion)
    fail(
      `crypto provenance names Emscripten ${String(provenance.toolchain?.emscripten)}, expected exactly ${expectedEmscriptenVersion}`,
    );
  if (provenance.artifact?.bytes !== wasmBytes.byteLength)
    fail("crypto provenance has an incorrect WASM byte length");
  if (provenance.artifact?.sha256 !== sha("sha256", wasmBytes))
    fail("crypto provenance has an incorrect WASM SHA-256");
  if (provenance.artifact?.sri !== sri(wasmBytes))
    fail("crypto provenance has an incorrect WASM SRI");
};

/**
 * Documentation must never name a version other than this release's.
 *
 * Every doc that prints an install command, a CDN path or a vendored directory
 * hardcodes the version, and each release they silently keep pointing at the
 * previous one — a reader then installs, or self-hosts, the wrong artifact. The
 * version in package.json is the single source of truth; this makes shipping a
 * doc that disagrees with it a release failure rather than a later bug report.
 */
const validateDocumentedVersions = () => {
  const current = packageJson.version;

  // Scanning for a bare \d+\.\d+\.\d+ is unusable here: the docs also pin Node
  // 24.11.1, Bun 1.3.14, Emscripten 6.0.9 and a dozen dependency versions.
  // Instead, take the set of versions this project has ever released — the
  // CHANGELOG headings — and treat any of them except the current one as a
  // stale reference. That cannot fire on a toolchain pin, and it needs no
  // maintenance: a version becomes checkable the moment it is released.
  const released = new Set(
    [
      ...readFileSync(path.join(projectRoot, "CHANGELOG.md"), "utf8").matchAll(
        /^## \[(\d+\.\d+\.\d+)\]/gm,
      ),
    ].map(([, version]) => version),
  );
  released.delete(current);
  if (released.size === 0) return;

  const stale = new RegExp(
    `(?<![\\d.])(${[...released].map((v) => v.replaceAll(".", "\\.")).join("|")})(?![\\d.])`,
    "g",
  );

  // Scan every tracked Markdown file rather than an allowlist: a doc added
  // next release is then covered without anyone remembering to register it,
  // which is exactly how ROADMAP.md drifted to a stale version unnoticed.
  //
  // The exemptions are the files whose purpose is to record history, where
  // naming an old version is correct and rewriting it would be a lie:
  // CHANGELOG.md, the two decision logs, and the browser results and original
  // desync investigation. Their historical version labels must stay intact.
  // The dated prior-art report also pins third-party package versions that
  // happen to overlap our own release numbers.
  // Vendored and submodule trees carry upstream's versions, not ours.
  const documentation = execFileSync(
    "git",
    [
      "ls-files",
      "*.md",
      ":!:CHANGELOG.md",
      ":!:docs/design-decisions-and-security-findings.md",
      ":!:docs/protocol-evolution-decision-log.md",
      ":!:docs/e2e/README.md",
      ":!:docs/e2e/desync-hunt-2026-09-07.md",
      ":!:docs/rendezvous-prior-art-delta-2026-09.md",
      ":!:libsodium/**",
      ":!:src/cryptography/vendor/**",
    ],
    { cwd: projectRoot, encoding: "utf8" },
  )
    .split("\n")
    .filter(Boolean);

  // The one line this scan must not judge is the line the build owns.
  // syncDocumentedIntegrity rewrites the README's pasteable bundle `src` —
  // version included, deliberately, so the pinned hash and the URL that names
  // its build stay a matched pair. That rewrite happens after validation, so
  // scanning it here fails every release on a reference the build is about to
  // correct, and the only way through is to hand-edit the line the script
  // exists to own. That is the manual step the sync was written to remove.
  const autoSynced =
    /src="https:\/\/cdn\.p2party\.com\/@[^"/]+\/p2party\.min\.js"/u;

  for (const relativePath of documentation) {
    const absolute = path.join(projectRoot, relativePath);
    if (!existsSync(absolute)) continue;
    readFileSync(absolute, "utf8")
      .split("\n")
      .forEach((line, index) => {
        if (autoSynced.test(line)) return;
        for (const [version] of line.matchAll(stale))
          fail(
            `${relativePath}:${index + 1} names released version ${version}, but this release is ${current} — ${line.trim()}`,
          );
      });
  }
};

/**
 * The README hands readers a `<script integrity="...">` tag to paste. A stale
 * hash there is worse than none: the browser blocks the script outright, so
 * every copy of that snippet breaks the moment a release changes the bundle.
 *
 * Both digests are over the decoded bytes, which is what SRI compares — the
 * CDN stores these objects gzipped and serves them with Content-Encoding.
 */
const syncDocumentedIntegrity = () => {
  const readmePath = path.join(projectRoot, "README.md");
  let readme = readFileSync(readmePath, "utf8");
  const before = readme;

  const bundleSri = sri(readFileSync(requireFile("lib/index.min.js")));
  const workerSri = sri(readFileSync(requireFile("lib/db.worker.js")));

  // The README hands readers a <script integrity="..."> tag to paste, and a
  // stale hash there is worse than none: the browser blocks the script, so
  // every copy of that snippet breaks the moment a release changes the bundle.
  //
  // Rewritten rather than merely checked, the same way updateWasmIntegrity
  // rewrites the pinned WASM SRI. Failing the build instead just meant a
  // manual copy-paste on every bundle change, which is the kind of step that
  // eventually gets skipped.
  readme = readme.replace(
    /integrity="sha384-[A-Za-z0-9+/=]+"/u,
    `integrity="${bundleSri}"`,
  );
  // The src and the integrity are only correct as a pair: a pinned hash names
  // one build, so the version in that URL is rewritten here too rather than by
  // hand. Every other CDN reference in the README is version-free on purpose.
  readme = readme.replace(
    /src="https:\/\/cdn\.p2party\.com\/@[^"/]+\/p2party\.min\.js"/u,
    `src="https://cdn.p2party.com/@${packageJson.version}/p2party.min.js"`,
  );
  // Anchored on the integrity= prefix rather than "first backticked sha384
  // followed by a period", which silently rewrote whichever such line came
  // first in the document.
  readme = readme.replace(
    /`integrity=sha384-[A-Za-z0-9+/=]+`/u,
    `\`integrity=${workerSri}\``,
  );

  if (!readme.includes(bundleSri))
    fail("README has no <script integrity> tag to keep in sync");
  if (!readme.includes(workerSri))
    fail("README has no worker integrity value to keep in sync");
  if (!readme.includes(`@${packageJson.version}/p2party.min.js`))
    fail("README has no versioned bundle src to keep in sync");

  if (readme !== before) {
    writeFileSync(readmePath, readme);
    console.log(`Updated README SRI -> ${bundleSri}`);
  }
};

const validateBundle = (
  relativePath,
  expectedIntegrity,
  expectedPublicNames = [],
) => {
  const source = readFileSync(requireFile(relativePath), "utf8");
  if (!source.includes(packageJson.version))
    fail(
      `${relativePath} does not embed package version ${packageJson.version}`,
    );
  if (!source.includes(expectedIntegrity))
    fail(`${relativePath} does not embed the current WASM SRI`);
  // The bundle builds its CDN URL by interpolating the version constant, so a
  // hardcoded version should never appear. Reject any CDN reference that names
  // a literal version other than this release's — a denylist of known-old
  // versions cannot do this job, since it stops protecting the moment a
  // release forgets to extend it.
  for (const [, cdnVersion] of source.matchAll(
    /cdn\.p2party\.com\/@([^/"'`\s]+)\/libcrypto\.wasm/g,
  )) {
    if (cdnVersion.includes("${")) continue; // interpolated; covered above
    if (cdnVersion !== packageJson.version)
      fail(
        `${relativePath} hardcodes CDN version ${cdnVersion}, expected ${packageJson.version}`,
      );
  }
  for (const name of [
    "_mlkem512_keypair",
    "_mlkem512_encaps",
    "_mlkem512_decaps",
    "_mlkem768_keypair",
    "_mlkem768_encaps",
    "_mlkem768_decaps",
    "_mlkem1024_keypair",
    "_mlkem1024_encaps",
    "_mlkem1024_decaps",
    "_fips202_shake256",
    "_fips202_sha3_256",
  ])
    if (!source.includes(name)) fail(`${relativePath} is missing ${name}`);
  for (const name of expectedPublicNames)
    if (!source.includes(name))
      fail(`${relativePath} is missing public API ${name}`);
};

const validateSessionSurface = async () => {
  const wasmBinary = readFileSync(requireFile("lib/libcrypto.wasm"));
  const esm = await import(
    `${pathToFileURL(requireFile("lib/session.mjs")).href}?release=${Date.now()}`
  );
  const require = createRequire(import.meta.url);
  const cjs = require(requireFile("lib/session.js"));
  for (const [format, module] of [
    ["ESM", esm],
    ["CommonJS", cjs],
  ])
    for (const name of [
      "createSession",
      "restoreSession",
      "generateSessionIdentity",
    ])
      if (typeof module[name] !== "function")
        fail(`${format} session export is missing ${name}`);

  for (const [format, module] of [
    ["ESM", esm],
    ["CommonJS", cjs],
  ]) {
    const identity = await module.generateSessionIdentity({ wasmBinary });
    if (
      identity.ed25519PublicKey?.byteLength !== 32 ||
      identity.ed25519SecretKey?.byteLength !== 64 ||
      identity.x25519PublicKey?.byteLength !== 32 ||
      identity.x25519SecretKey?.byteLength !== 32 ||
      identity.x25519CrossSignature?.byteLength !== 64
    )
      fail(`${format} session identity smoke returned malformed key material`);
    identity.ed25519SecretKey.fill(0);
    identity.x25519SecretKey.fill(0);
  }

  // The zero-config path the README promises: no wasmBinary, no network. It
  // must resolve the packaged WASM next to the bundle and verify it against
  // the pinned SHA-384. Tested separately from the explicit-bytes calls above,
  // because those would mask a broken local resolver by never exercising it.
  //
  // fetch is stubbed to throw so a silent CDN fallback fails the release
  // instead of passing here and then breaking in an offline install.
  const realFetch = globalThis.fetch;
  globalThis.fetch = () => {
    throw new Error("zero-config session load must not reach the network");
  };
  try {
    for (const [format, module] of [
      ["ESM", esm],
      ["CommonJS", cjs],
    ]) {
      const identity = await module.generateSessionIdentity();
      if (identity.ed25519PublicKey?.byteLength !== 32)
        fail(`${format} zero-config session identity is malformed`);
      identity.ed25519SecretKey.fill(0);
      identity.x25519SecretKey.fill(0);
    }
  } catch (error) {
    fail(`zero-config session load failed: ${String(error)}`);
  } finally {
    globalThis.fetch = realFetch;
  }
};

const validatePackList = (packResult) => {
  const paths = new Set(packResult.files.map(({ path: filePath }) => filePath));
  const required = [
    "package.json",
    "README.md",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
    "docs/getting-started.md",
    "docs/session-api.md",
    "docs/protocol-v4-security.md",
    "docs/references.md",
    "docs/wire-format.md",
    "docs/assets/p2party-cat.svg",
    "examples/standalone-e2ee.ts",
    "lib/index.js",
    "lib/index.mjs",
    "lib/index.min.js",
    "lib/index.d.ts",
    "lib/session.js",
    "lib/session.mjs",
    "lib/session.d.ts",
    "lib/db.worker.js",
    "lib/libcrypto.wasm",
    "lib/libcrypto.provenance.json",
  ];
  for (const requiredPath of required)
    if (!paths.has(requiredPath)) fail(`tarball is missing ${requiredPath}`);

  const exactFiles = new Set(required);
  for (const filePath of paths) {
    if (exactFiles.has(filePath)) continue;
    if (/^lib\/.+\.d\.ts$/u.test(filePath)) continue;
    fail(`tarball unexpectedly contains ${filePath}`);
  }
};

const runtimeArtifacts = [
  "db.worker.js",
  "index.js",
  "index.mjs",
  "index.min.js",
  "session.js",
  "session.mjs",
  "libcrypto.wasm",
  "libcrypto.provenance.json",
];

try {
  mkdirSync(stageLib, { recursive: true });
  mkdirSync(packedRoot, { recursive: true });
  mkdirSync(path.join(stageRoot, "docs"), { recursive: true });
  mkdirSync(path.join(stageRoot, "docs", "assets"), { recursive: true });
  mkdirSync(path.join(stageRoot, "examples"), { recursive: true });

  const mlkemSourceRoot = path.join(
    projectRoot,
    "src",
    "cryptography",
    "vendor",
    "mlkem-native",
    "mlkem",
  );
  if (
    digestFiles(mlkemSourceRoot, listFiles(mlkemSourceRoot)) !==
    expectedMlkemNativeSourceTreeSha256
  )
    fail("the vendored mlkem-native source tree does not match its pin");
  const mlkemBuildRoot = path.join(projectRoot, "src", "cryptography");
  const mlkemWrapperFiles = [512, 768, 1024]
    .flatMap((parameterSet) => [
      `mlkem${parameterSet}.c`,
      `mlkem${parameterSet}.h`,
    ])
    .sort();
  if (
    digestFiles(mlkemBuildRoot, mlkemWrapperFiles) !==
    expectedMlkemWrapperSha256
  )
    fail("the p2party ML-KEM wrappers do not match their pin");
  if (
    sha(
      "sha256",
      readFileSync(path.join(projectRoot, "src", "utils", "wordlist.json")),
    ) !== expectedRoomWordlistSha256
  )
    fail("the BIP39 English room wordlist does not match its pin");

  const nodeMajor = Number.parseInt(process.versions.node, 10);
  if (nodeMajor !== expectedNodeMajor)
    fail(
      `Node ${expectedNodeMajor}.x is required; found ${process.versions.node}`,
    );
  const emscriptenBanner = run("emcc", ["--version"], { capture: true });
  if (
    !new RegExp(
      `\\b${expectedEmscriptenVersion.replaceAll(".", "\\.")}(?:-git)?\\b`,
    ).test(emscriptenBanner)
  )
    fail(
      `Emscripten ${expectedEmscriptenVersion} is required; found ${emscriptenBanner.split("\n", 1)[0]}`,
    );

  validateDocumentedVersions();

  console.log("[1/7] Compile production WASM and update its pinned SRI");
  run(npm, ["run", "--silent", "predist"], {
    env: { EM_CACHE: emscriptenCache },
  });

  console.log("[2/7] Build the IndexedDB worker into a fresh staging tree");
  run(npm, ["run", "--silent", "dist:worker"], {
    env: releaseBuildEnvironment,
  });

  console.log("[3/7] Build root and store-free session packages");
  run(npm, ["run", "--silent", "dist:package"], {
    env: releaseBuildEnvironment,
  });

  console.log("[4/7] Copy and validate the exact WASM artifact");
  const sourceWasmPath = path.join(
    projectRoot,
    "src",
    "cryptography",
    "libcrypto.wasm",
  );
  const packagedWasmPath = path.join(stageLib, "libcrypto.wasm");
  const sourceProvenancePath = path.join(
    projectRoot,
    "src",
    "cryptography",
    "libcrypto.provenance.json",
  );
  const packagedProvenancePath = path.join(
    stageLib,
    "libcrypto.provenance.json",
  );
  const sourceWasm = readFileSync(sourceWasmPath);
  const sourceProvenanceBytes = readFileSync(sourceProvenancePath);
  const sourceProvenance = JSON.parse(sourceProvenanceBytes.toString("utf8"));
  validateCryptoProvenance(sourceProvenance, sourceWasm);
  copyFileSync(sourceWasmPath, packagedWasmPath);
  copyFileSync(sourceProvenancePath, packagedProvenancePath);
  const packagedWasm = readFileSync(packagedWasmPath);
  if (!sourceWasm.equals(packagedWasm))
    fail("packaged WASM differs from the just-compiled source artifact");

  const expectedIntegrity = sri(sourceWasm);
  const loaderSource = readFileSync(
    path.join(projectRoot, "src", "cryptography", "wasmLoader.ts"),
    "utf8",
  );
  if (!loaderSource.includes(expectedIntegrity))
    fail("wasmLoader.ts SRI does not match the just-compiled WASM");
  if (
    !loaderSource.includes(
      `process.env.P2PARTY_VERSION ?? "${packageJson.version}"`,
    )
  )
    fail("wasmLoader.ts fallback version does not match package.json");

  await validateWasmGlue(sourceWasm);
  // The README embeds digests of the freshly built staging bundles. Update the
  // source before copying it into the package so the archived documentation
  // and the project documentation describe the same exact artifacts.
  syncDocumentedIntegrity();

  for (const fileName of [
    "package.json",
    "README.md",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
  ])
    copyFileSync(
      path.join(projectRoot, fileName),
      path.join(stageRoot, fileName),
    );

  // Derived from package.json `files` rather than restated: a hand-kept second
  // list desynced once already, when a doc rename left protocol-v3-security.md
  // here and every release died at this copy.
  const packagedDocs = packageJson.files
    .filter((entry) => entry.startsWith("docs/") && entry.endsWith(".md"))
    .map((entry) => entry.slice("docs/".length));

  for (const fileName of packagedDocs)
    copyFileSync(
      path.join(projectRoot, "docs", fileName),
      path.join(stageRoot, "docs", fileName),
    );

  copyFileSync(
    path.join(projectRoot, "docs", "assets", "p2party-cat.svg"),
    path.join(stageRoot, "docs", "assets", "p2party-cat.svg"),
  );

  copyFileSync(
    path.join(projectRoot, "examples", "standalone-e2ee.ts"),
    path.join(stageRoot, "examples", "standalone-e2ee.ts"),
  );

  for (const target of exportedTargets(packageJson.exports)) {
    if (!target.startsWith("./"))
      fail(`package export is not relative: ${target}`);
    requireFile(target.slice(2));
  }

  for (const bundle of ["lib/index.js", "lib/index.mjs", "lib/index.min.js"])
    validateBundle(bundle, expectedIntegrity, ["setWasmSourceUrl"]);
  for (const bundle of ["lib/session.js", "lib/session.mjs"])
    validateBundle(bundle, expectedIntegrity);
  await validateSessionSurface();

  console.log("[5/7] Run the packaged standalone session example");
  const exampleOutput = run(bun, ["run", "examples/standalone-e2ee.ts"], {
    cwd: stageRoot,
    capture: true,
  });
  if (!/^OK\b/mu.test(exampleOutput))
    fail("packaged standalone session example did not print OK");

  console.log("[6/7] Pack the validated staging tree");
  const packJson = run(
    npm,
    ["pack", "--json", "--ignore-scripts", "--pack-destination", packedRoot],
    {
      cwd: stageRoot,
      env: { npm_config_cache: npmCache },
      capture: true,
    },
  );
  const [packResult] = JSON.parse(packJson);
  if (!packResult || packResult.version !== packageJson.version)
    fail("npm pack reported an unexpected package version");
  validatePackList(packResult);

  console.log(
    "[7/7] Verify archived bytes and publish the validated artifacts",
  );
  const stagedTarball = path.join(packedRoot, packResult.filename);
  const archivedWasm = execFileSync(
    "tar",
    ["-xOf", stagedTarball, "package/lib/libcrypto.wasm"],
    { maxBuffer: 8 * 1024 * 1024 },
  );
  if (!sourceWasm.equals(archivedWasm))
    fail("WASM bytes changed while packing the tarball");
  const archivedProvenance = execFileSync(
    "tar",
    ["-xOf", stagedTarball, "package/lib/libcrypto.provenance.json"],
    { maxBuffer: 1024 * 1024 },
  );
  if (!sourceProvenanceBytes.equals(archivedProvenance))
    fail("crypto provenance changed while packing the tarball");
  const archivedReadme = execFileSync(
    "tar",
    ["-xOf", stagedTarball, "package/README.md"],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  const bundleSri = sri(readFileSync(path.join(stageLib, "index.min.js")));
  const workerSri = sri(readFileSync(path.join(stageLib, "db.worker.js")));
  if (
    !archivedReadme.includes(
      `src="https://cdn.p2party.com/@${packageJson.version}/p2party.min.js"`,
    ) ||
    !archivedReadme.includes(`integrity="${bundleSri}"`) ||
    !archivedReadme.includes(`integrity=${workerSri}`)
  )
    fail("archived README does not describe the packed release artifacts");

  const projectLib = path.join(projectRoot, "lib");
  mkdirSync(projectLib, { recursive: true });
  for (const fileName of runtimeArtifacts)
    copyFileSync(
      path.join(stageLib, fileName),
      path.join(projectLib, fileName),
    );

  const finalTarball = path.join(projectRoot, packResult.filename);
  copyFileSync(stagedTarball, finalTarball);
  const tarballBytes = readFileSync(finalTarball);

  console.log("");
  console.log(`Release package: ${finalTarball}`);
  console.log(`Package files: ${packResult.entryCount}`);
  console.log(`WASM bytes: ${sourceWasm.byteLength}`);
  console.log(`WASM SHA-256: ${sha("sha256", sourceWasm)}`);
  console.log(`WASM SRI: ${expectedIntegrity}`);
  console.log(`libsodium commit: ${expectedLibsodiumCommit}`);
  console.log(`libsodium tree: ${expectedLibsodiumTree}`);
  console.log(`Tarball SHA-256: ${sha("sha256", tarballBytes)}`);
  console.log(`Tarball SHA-512: ${sha("sha512", tarballBytes)}`);
} finally {
  rmSync(releaseRoot, { recursive: true, force: true });
}
