// @ts-check
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "build/**", "src/wasm-gen/**", "node_modules/**", "test-results/**"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked.map((config) => ({ ...config, files: ["**/*.ts"] })),
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
      globals: { ...globals.browser, ...globals.webextensions },
    },
    rules: {
      // Secrets must never reach the console (ADR 0017): no console at all.
      "no-console": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // innerHTML would let a title or a page inject markup into our UI.
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Build DOM nodes; never parse strings as HTML." },
        { property: "outerHTML", message: "Build DOM nodes; never parse strings as HTML." },
        { property: "insertAdjacentHTML", message: "Build DOM nodes; never parse strings as HTML." },
      ],
    },
  },
  {
    files: ["scripts/**/*.mjs", "eslint.config.js"],
    languageOptions: { globals: { ...globals.node } },
  },
);
