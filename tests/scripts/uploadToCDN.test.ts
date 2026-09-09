import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const uploaderUrl = new URL("../../scripts/uploadToCDN.mjs", import.meta.url)
  .href;

interface UploadResult {
  error?: string;
  puts: {
    key: string;
    contentType: string;
    contentEncoding?: string;
    decodedMatches: boolean;
    storedHashMatches: boolean;
    ifNoneMatch: string;
  }[];
  wasmGets: number;
  raced: boolean;
}

/**
 * Run the real CLI with an isolated S3 mock and temporary synthetic assets.
 * A child keeps the mock out of other SDK tests; it never creates a real client
 * or reads deployment credentials or built release assets.
 */
const runUploader = (existing: "absent" | "raw" | "different" | "race") => {
  const result = spawnSync(
    process.execPath,
    [
      "--no-env-file",
      "--eval",
      `
      import { mock } from "bun:test";
      import { createHash } from "node:crypto";
      import { gzipSync, gunzipSync } from "node:zlib";
      import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
      import { tmpdir } from "node:os";
      import { join } from "node:path";

      const existing = ${JSON.stringify(existing)};
      const raw = {
        "p2party.min.js": Buffer.from("globalThis.p2party = {};"),
        "db.worker.js": Buffer.from("self.onmessage = () => {};"),
        "libcrypto.wasm": Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]),
      };
      const hash = (body) => createHash("sha256").update(body).digest("hex");
      const puts = [];
      let wasmGets = 0;
      let raced = false;
      const remote = existing === "different"
        ? Buffer.concat([raw["libcrypto.wasm"], Buffer.from([1])])
        : raw["libcrypto.wasm"];
      const notFound = () => Object.assign(new Error("fixture missing"), { name: "NotFound" });

      class Command { constructor(input) { this.input = input; } }
      class HeadObjectCommand extends Command {}
      class GetObjectCommand extends Command {}
      class PutObjectCommand extends Command {}
      class S3Client {
        async send(command) {
          const input = command.input;
          const name = input.Key.split("/").at(-1);
          const wasm = name === "libcrypto.wasm";
          if (command instanceof HeadObjectCommand) {
            if (!wasm || existing === "absent" || (existing === "race" && !raced)) throw notFound();
            return { Metadata: { sha256: hash(remote) }, ContentType: "application/wasm" };
          }
          if (command instanceof GetObjectCommand) {
            if (!wasm) throw new Error("unexpected fixture GET");
            wasmGets++;
            return { Body: { transformToByteArray: async () => remote } };
          }
          if (!(command instanceof PutObjectCommand)) throw new Error("unexpected command");
          puts.push({
            key: input.Key,
            contentType: input.ContentType,
            contentEncoding: input.ContentEncoding,
            decodedMatches: gunzipSync(input.Body).equals(raw[name]),
            storedHashMatches: input.Metadata.sha256 === hash(input.Body),
            ifNoneMatch: input.IfNoneMatch,
          });
          if (wasm && existing === "race") {
            raced = true;
            throw Object.assign(new Error("fixture raced"), { $metadata: { httpStatusCode: 412 } });
          }
          return {};
        }
      }
      mock.module("@aws-sdk/client-s3", () => ({ S3Client, HeadObjectCommand, GetObjectCommand, PutObjectCommand }));
      const previousDirectory = process.cwd();
      const fixture = mkdtempSync(join(tmpdir(), "p2party-cdn-test-"));
      mkdirSync(join(fixture, "lib"));
      for (const [name, bytes] of Object.entries(raw))
        writeFileSync(join(fixture, "lib", name + ".gz"), gzipSync(bytes));
      process.chdir(fixture);
      let error;
      try { await import(${JSON.stringify(uploaderUrl)}); }
      catch (cause) { error = cause.message; }
      finally { process.chdir(previousDirectory); rmSync(fixture, { recursive: true, force: true }); }
      console.log("CDN_TEST_RESULT=" + JSON.stringify({ error, puts, wasmGets, raced }));
      `,
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        AWS_S3_BUCKET: "offline-test-bucket",
        AWS_S3_REGION: "offline-test-region",
        AWS_S3_ENDPOINT: "",
        AWS_S3_ACCESS_KEY: "",
        AWS_S3_SECRET_KEY: "",
        AWS_S3_FORCE_PATH_STYLE: "",
      },
    },
  );
  if (result.status !== 0)
    throw new Error(`Offline uploader fixture failed: ${result.stderr}`);
  const line = result.stdout
    .split("\n")
    .find((value) => value.startsWith("CDN_TEST_RESULT="));
  if (!line) throw new Error("Offline uploader fixture produced no result");
  return JSON.parse(line.slice("CDN_TEST_RESULT=".length)) as UploadResult;
};

describe("immutable CDN gzip delivery", () => {
  test("prepares WASM gzip before uploading and preserves decoded content and metadata", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    );
    expect(pkg.scripts["prepare:uploadcdn"]).toContain("npm run gzip:wasm");
    // Upload preparation must preserve the validated artifact already in lib/.
    // Copying a local development WASM here could silently replace that release.
    expect(pkg.scripts["prepare:uploadcdn"]).not.toContain("copy:wasm");
    const result = runUploader("absent");
    expect(result.error).toBeUndefined();
    expect(result.puts).toHaveLength(3);
    for (const asset of result.puts) {
      expect(asset.contentEncoding).toBe("gzip");
      expect(asset.decodedMatches).toBe(true);
      expect(asset.storedHashMatches).toBe(true);
      expect(asset.ifNoneMatch).toBe("*");
    }
    expect(
      result.puts.find((asset) => asset.key.endsWith("/libcrypto.wasm"))
        ?.contentType,
    ).toBe("application/wasm");
  });

  test("keeps an already published raw WASM object without replacing its representation", () => {
    const result = runUploader("raw");
    expect(result.error).toBeUndefined();
    expect(result.wasmGets).toBe(1);
    expect(
      result.puts.some((asset) => asset.key.endsWith("/libcrypto.wasm")),
    ).toBe(false);
  });

  test("refuses different decoded WASM under the same versioned key", () => {
    const result = runUploader("different");
    expect(result.error).toContain("refusing to replace immutable CDN object");
    expect(
      result.puts.some((asset) => asset.key.endsWith("/libcrypto.wasm")),
    ).toBe(false);
  });

  test("a concurrent raw upload wins without a compressed overwrite", () => {
    const result = runUploader("race");
    expect(result.error).toBeUndefined();
    expect(result.raced).toBe(true);
    expect(result.wasmGets).toBe(1);
    expect(
      result.puts.filter((asset) => asset.key.endsWith("/libcrypto.wasm")),
    ).toHaveLength(1);
  });
});
