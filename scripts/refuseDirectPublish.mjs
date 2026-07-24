#!/usr/bin/env node

console.error(
  "Direct source-tree publishing is disabled. Run `npm run release:pack`, then publish the validated p2party-<version>.tgz with `--ignore-scripts`.",
);
process.exit(1);
