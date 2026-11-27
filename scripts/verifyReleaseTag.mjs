import { readFileSync } from "node:fs";

const { version } = JSON.parse(readFileSync("package.json", "utf8"));
const tag = process.env.GITHUB_REF_NAME;

// This workflow publishes immutable CDN assets and npm's public latest tag.
// Candidate versions can still use the same pack and CI checks locally.
if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(version))
  throw new Error(
    `The public release workflow requires a stable package version, received ${version}`,
  );
if (tag !== `v${version}`)
  throw new Error(
    `Tag ${String(tag)} does not match package version ${version}`,
  );
