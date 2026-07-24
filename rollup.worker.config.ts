import path from "path";
import typescript from "@rollup/plugin-typescript";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import terser from "@rollup/plugin-terser";

const isDist = process.env.NODE_ENV === "production";
const dir = process.env.P2PARTY_OUTPUT_DIR ?? "lib";

export default {
  input: "src/db/db.worker.ts",
  output: {
    file: path.join(dir, "db.worker.js"),
    format: "es",
    sourcemap: !isDist,
  },
  plugins: [
    nodeResolve({
      browser: true, // Ensures browser-compatible imports
    }),

    typescript({
      sourceMap: !isDist,
      inlineSources: false,
      declaration: true,
      declarationMap: !isDist,
      outDir: `${dir}`,
    }),

    isDist &&
      terser({
        ecma: 2020,
        toplevel: true,
      }),
  ],
  external: [],
};
