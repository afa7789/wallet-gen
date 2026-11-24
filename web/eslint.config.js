const shared = ["console", "crypto", "fetch", "URL", "Blob", "TextEncoder", "TextDecoder", "globalThis", "process"];
const browser = ["window", "document"];
const node = ["Buffer", "Bun"];
const globals = Object.fromEntries([...shared, ...browser, ...node].map((g) => [g, "readonly"]));

export default [
  { ignores: ["dist/", "node_modules/"] },
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module", globals },
    rules: {
      complexity: ["error", 10],
      "no-undef": "error",
      "no-unused-vars": "error",
      "no-var": "error",
      "prefer-const": "error",
      eqeqeq: "error",
    },
  },
];
