import { promises as fs, readFileSync } from "fs";
import * as path from "path";
import dotenv from "dotenv";
import {
  S3Client,
  // This command supersedes the ListObjectsCommand and is the recommended way to list objects.
  ListObjectsV2Command,
  // DeleteObjectCommand,
  DeleteObjectsCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import pkg from "../package.json" with { type: "json" };

dotenv.config({ path: "./.env" });

const client = new S3Client({
  region: process.env.AWS_S3_REGION,
  credentials: {
    accessKeyId: process.env.AWS_S3_ACCESS_KEY,
    secretAccessKey: process.env.AWS_S3_SECRET_KEY,
  },
});

console.log("Updating " + process.env.AWS_S3_BUCKET);

// Recursive getFiles from
// https://stackoverflow.com/a/45130990/831465
async function getDirFiles(dir) {
  const dirents = await fs.readdir(dir, { withFileTypes: true });
  const files = await Promise.all(
    dirents.map((dirent) => {
      const res = path.resolve(dir, dirent.name);
      return dirent.isDirectory() ? getDirFiles(res) : res;
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

      const contentsLen = Contents.length;
      for (let i = 0; i < contentsLen; i++) {
        if (!Contents[i].Key?.includes("@" + pkg.version)) continue;

        files.push({ Key: Contents[i].Key });
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
    Delete: {
      Objects: existingFiles,
    },
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
const filesLen = files.length;

for (let i = 0; i < filesLen; i++) {
  if (!files[i].includes(".js.gz")) continue;

  // if (files[i].includes(".DS_Store")) continue;
  //
  // if (process.env.NODE_ENV === "development" && files[i].includes("robots.txt"))
  //   continue;
  //
  const putcommand = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: path.join(
      "@" + pkg.version,
      path.basename(files[i]).replace(".js.gz", ".js"),
    ),
    Body: readFileSync(files[i]),
    Metadata: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET",
    },
    CacheControl: "no-cache",
    ContentType: files[i].includes(".d.ts")
      ? "text/plain"
      : "application/javascript",
    ...(!files[i].includes(".d.ts") && { ContentEncoding: "gzip" }),
  });

  try {
    console.log("Uploading " + files[i]);
    await client.send(putcommand);
  } catch (err) {
    console.error(err);
  }
}

console.log("Successfully uploaded website");
