import typescript from "@rollup/plugin-typescript";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import terser from "@rollup/plugin-terser";

const isDist = process.env.NODE_ENV === "production";
const dir = "lib";

export default {
  input: "src/db/db.worker.ts",
  output: {
    file: "lib/db.worker.js",
    format: "es",
    sourcemap: true,
  },
  plugins: [
    nodeResolve({
      browser: true, // Ensures browser-compatible imports
    }),

    typescript({
      sourceMap: true,
      inlineSources: false,
      declaration: true,
      declarationMap: true,
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
