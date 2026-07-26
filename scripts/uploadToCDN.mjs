import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { gunzipSync } from "node:zlib";

import {
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import pkg from "../package.json" with { type: "json" };

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

const requiredEnvironment = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const bucket = requiredEnvironment("AWS_S3_BUCKET");
const region = requiredEnvironment("AWS_S3_REGION");
const endpoint = process.env.AWS_S3_ENDPOINT?.trim();
const accessKeyId = process.env.AWS_S3_ACCESS_KEY?.trim();
const secretAccessKey = process.env.AWS_S3_SECRET_KEY?.trim();
if (Boolean(accessKeyId) !== Boolean(secretAccessKey))
  throw new Error(
    "AWS_S3_ACCESS_KEY and AWS_S3_SECRET_KEY must either both be set or both be omitted",
  );

// An unset GitHub Actions secret renders as an empty string, not as an absent
// variable, so `env: FOO: ${{ secrets.FOO }}` sets FOO="" when FOO is not
// configured. Treating "" as a bad value made an *optional* setting fail the
// release with "must be true or false", which reads like a typo rather than a
// missing secret. Empty means unset here, the same as omitted.
const forcePathStyleValue =
  process.env.AWS_S3_FORCE_PATH_STYLE?.trim() || undefined;
if (
  forcePathStyleValue !== undefined &&
  forcePathStyleValue !== "true" &&
  forcePathStyleValue !== "false"
)
  throw new Error(
    `AWS_S3_FORCE_PATH_STYLE must be "true" or "false"; got "${forcePathStyleValue}"`,
  );

const client = new S3Client({
  region,
  ...(endpoint ? { endpoint } : {}),
  forcePathStyle: forcePathStyleValue === "true",
  ...(accessKeyId && secretAccessKey
    ? { credentials: { accessKeyId, secretAccessKey } }
    : {}),
});

const assets = [
  {
    source: path.join("lib", "p2party.min.js.gz"),
    keyName: "p2party.min.js",
    contentType: "application/javascript",
    contentEncoding: "gzip",
  },
  {
    source: path.join("lib", "db.worker.js.gz"),
    keyName: "db.worker.js",
    contentType: "application/javascript",
    contentEncoding: "gzip",
  },
  {
    source: path.join("lib", "libcrypto.wasm"),
    keyName: "libcrypto.wasm",
    contentType: "application/wasm",
  },
];

const isNotFound = (error) =>
  error?.name === "NotFound" ||
  error?.name === "NoSuchKey" ||
  error?.$metadata?.httpStatusCode === 404;

const headObject = async (key) => {
  try {
    return await client.send(
      new HeadObjectCommand({
        Bucket: bucket,
        Key: key,
      }),
    );
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
};

/**
 * Confirm a republish carries the same artifact, comparing what the browser
 * would actually execute rather than the bytes we happen to have stored.
 *
 * The stored form is gzip, and a gzip stream embeds an MTIME in its header, so
 * two runs over byte-identical input produce different gzip bytes. Comparing
 * the compressed hash therefore reported a mismatch on every re-run of an
 * already-published tag -- an immutability violation that had not happened.
 *
 * Fetching and decoding the object costs one GET per asset and answers the
 * question that matters: is the published artifact the one this build made?
 */
const assertSameObject = async (key, head, compressedSha256, asset) => {
  if (head?.Metadata?.sha256 === compressedSha256) return "identical bytes";

  const published = await client.send(
    new GetObjectCommand({ Bucket: bucket, Key: key }),
  );
  // The SDK transparently decodes Content-Encoding, so this is the artifact.
  const publishedBytes = Buffer.from(
    await published.Body.transformToByteArray(),
  );
  const localBytes =
    asset.contentEncoding === "gzip"
      ? gunzipSync(await readFile(asset.source))
      : await readFile(asset.source);

  if (!publishedBytes.equals(localBytes))
    throw new Error(
      `refusing to replace immutable CDN object ${key}: published content is ` +
        `${sha256Hex(publishedBytes)}, this release builds ${sha256Hex(localBytes)}`,
    );
  return "identical content, different compression";
};

for (const asset of assets) {
  const body = await readFile(asset.source);
  const sha256 = createHash("sha256").update(body).digest("hex");
  const key = path.posix.join(`@${pkg.version}`, asset.keyName);
  const existing = await headObject(key);
  if (existing) {
    const how = await assertSameObject(key, existing, sha256, asset);
    console.log(`Already published ${key} (${how})`);
    continue;
  }

  try {
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        CacheControl: "public, max-age=31536000, immutable",
        ContentType: asset.contentType,
        ...(asset.contentEncoding
          ? { ContentEncoding: asset.contentEncoding }
          : {}),
        Metadata: { sha256 },
        IfNoneMatch: "*",
      }),
    );
    console.log(`Published ${asset.source} -> ${key} (${sha256})`);
  } catch (error) {
    if (error?.$metadata?.httpStatusCode !== 412) throw error;
    const racedObject = await headObject(key);
    if (!racedObject) throw error;
    const how = await assertSameObject(key, racedObject, sha256, asset);
    console.log(`Already published concurrently ${key} (${how})`);
  }
}

console.log(`Published immutable CDN assets for p2party ${pkg.version}`);
