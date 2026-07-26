import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: [
      "lib/*",
      "node_modules/*",
      "wasm/*",
      "coverage/*",
      // Preserved browser E2E harnesses (docs/e2e/): run manually per
      // docs/e2e/README.md, not part of the shipped library surface.
      "docs/*",
      // Local session-history scratch space, not project source.
      ".remember/*",
      "eslint.config.mjs",
      "rollup.config.ts",
      "rollup.worker.config.ts",
      // Emscripten SDK checkouts. The release workflow caches the SDK into
      // ./emsdk-cache inside the workspace, and emsdk ships its own
      // eslint.config.mjs — `eslint .` then loads that config instead of this
      // one and dies on its unresolvable @eslint/eslintrc import. A bare
      // "emsdk" only matched a file of that exact name, so it never applied.
      "emsdk/**",
      "emsdk-cache/**",
      "src/cryptography/libcrypto.js",
    ],
  },
  { languageOptions: { globals: globals.browser } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["scripts/**/*.{js,mjs}"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: { globals: globals.node },
    rules: {
      "@typescript-eslint/no-require-imports": "off",
    },
  },
  {
    rules: {
      "@typescript-eslint/no-empty-function": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
    },
  },
];
