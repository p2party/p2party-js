import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  { languageOptions: { globals: globals.browser } },
  {
    ignores: [
      "lib/*",
      "node_modules/*",
      "wasm/*",
      "scripts/*",
      "coverage/*",
      "eslint.config.mjs",
      "rollup.config.ts",
      "emsdk",
      "src/cryptography/libcrypto.js",
    ],
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: true,
      },
    },
  },
  // eslintPluginPrettierRecommended,
  {
    files: ["**/*.js"],
    ...tseslint.configs.disableTypeChecked,
  },
];
