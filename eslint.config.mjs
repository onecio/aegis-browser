import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["dist/**", "node_modules/**"]
  },
  js.configs.recommended,
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
        chrome: "readonly",
        BarcodeDetector: "readonly"
      }
    },
    rules: {
      "no-debugger": "error",
      "no-eval": "error",
      "no-new-func": "error"
    }
  },
  {
    files: ["src/**/*.js", "gateway/**/*.js", "extension/**/*.js"],
    rules: {
      "no-console": "error"
    }
  }
];
