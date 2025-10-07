import { promises as fs, readFileSync } from "fs";
import * as path from "path";
import {
  S3Client,
  ListObjectsV2Command,
  DeleteObjectsCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import pkg from "../package.json" with { type: "json" };

const client = new S3Client({
  region: process.env.AWS_S3_REGION,
  credentials: {
    accessKeyId: process.env.AWS_S3_ACCESS_KEY,
    secretAccessKey: process.env.AWS_S3_SECRET_KEY,
  },
});

console.log("Updating " + process.env.AWS_S3_BUCKET);

// Recursive getFiles
async function getDirFiles(dir) {
  const dirents = await fs.readdir(dir, { withFileTypes: true });
  const files = await Promise.all(
    dirents.map((d) => {
      const res = path.resolve(dir, d.name);
      return d.isDirectory() ? getDirFiles(res) : res;
    }),
  );
  return Array.prototype.concat(...files);
}

async function getAllObjectsFromS3Bucket() {
  const listcommand = new ListObjectsV2Command({
    Bucket: process.env.AWS_S3_BUCKET,
  });

  const files = [];
  try {
    let isTruncated = true;
    while (isTruncated) {
      const { Contents, IsTruncated, NextContinuationToken } =
        await client.send(listcommand);
      if (!Contents) return [];

      for (const obj of Contents) {
        if (obj.Key?.includes("@" + pkg.version)) files.push({ Key: obj.Key });
      }
      isTruncated = IsTruncated;
      listcommand.input.ContinuationToken = NextContinuationToken;
    }
    return files;
  } catch (err) {
    console.error(err);
  }
}

const existingFiles = await getAllObjectsFromS3Bucket();

if (existingFiles && existingFiles.length > 0) {
  const command = new DeleteObjectsCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Delete: { Objects: existingFiles },
  });
  try {
    const { Deleted } = await client.send(command);
    console.log(
      `Successfully deleted ${Deleted.length} objects from S3 bucket.`,
    );
  } catch (err) {
    console.error(err);
  }
}

const buildDir = "lib";
const files = await getDirFiles(buildDir);

for (const filePath of files) {
  const base = path.basename(filePath);

  // Upload only .min.js.gz and .wasm (and optionally .wasm.gz)
  const isJsGz = base.endsWith(".min.js.gz") || base.endsWith(".js.gz");
  const isWasm = base.endsWith(".wasm");
  const isWasmGz = base.endsWith(".wasm.gz");

  if (!(isJsGz || isWasm || isWasmGz)) continue;

  // Key: strip the .gz extension for gzipped assets
  const keyFileName = isJsGz || isWasmGz ? base.replace(/\.gz$/, "") : base;

  // Content-Type
  const contentType =
    isWasm || isWasmGz ? "application/wasm" : "application/javascript";

  // Only set Content-Encoding when the local file is actually gzipped
  const maybeContentEncoding =
    isJsGz || isWasmGz ? { ContentEncoding: "gzip" } : {};

  const putcommand = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: path.posix.join("@" + pkg.version, keyFileName), // posix for S3 keys
    Body: readFileSync(filePath),
    CacheControl: "no-cache",
    ContentType: contentType,
    ...maybeContentEncoding,

    // (Note: CORS should be configured at bucket level; Metadata below is harmless but not used as headers)
    Metadata: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET",
    },
  });

  try {
    console.log("Uploading " + filePath + " -> " + keyFileName);
    await client.send(putcommand);
  } catch (err) {
    console.error(err);
  }
}

console.log("Successfully uploaded assets");
