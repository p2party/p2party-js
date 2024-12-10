import typescript from "@rollup/plugin-typescript";
import { nodeResolve } from "@rollup/plugin-node-resolve";

export default {
  input: "src/db/db.worker.ts",
  output: {
    file: "lib/db.worker.js",
    format: "es",
  },
  plugins: [
    nodeResolve({
      browser: true, // Ensures browser-compatible imports
    }),
    typescript(),
  ],
  external: [],
};
